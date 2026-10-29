import { App } from 'aws-cdk-lib';
import { Match, Template } from 'aws-cdk-lib/assertions';
import { buildApp } from '../lib/app';
import { config } from '../lib/config';

// Synthesizes the whole app against a dummy environment (no AWS calls; context lookups
// such as AMIs resolve to CDK's placeholder values).
const env = { account: '123456789012', region: 'us-east-1' };
const stacks = buildApp(new App(), env);
const t = (s: keyof typeof stacks) => Template.fromStack(stacks[s]);

describe('SFTP endpoint', () => {
  const sftp = t('sftp');

  test('is SFTP only, VPC-only, with the Directory Service identity provider', () => {
    sftp.hasResourceProperties('AWS::Transfer::Server', {
      Protocols: ['SFTP'],
      EndpointType: 'VPC',
      IdentityProviderType: 'AWS_DIRECTORY_SERVICE',
      SecurityPolicyName: Match.stringLikeRegexp('^TransferSecurityPolicy-20(2[4-9]|[3-9]\\d)'),
      LoggingRole: Match.absent(),
    });
  });

  test('only the SFTP client SG may reach port 22', () => {
    t('network').hasResourceProperties('AWS::EC2::SecurityGroupIngress', {
      IpProtocol: 'tcp', FromPort: 22, ToPort: 22,
      SourceSecurityGroupId: Match.anyValue(),
      CidrIp: Match.absent(),
    });
  });

  test('Transfer data roles trust only this server', () => {
    const roles = sftp.findResources('AWS::IAM::Role', {
      Properties: { RoleName: Match.stringLikeRegexp(`^${config.prefix}-transfer-`) },
    });
    expect(Object.keys(roles)).toHaveLength(2);
    for (const r of Object.values(roles)) {
      const cond = (r as any).Properties.AssumeRolePolicyDocument.Statement[0].Condition;
      expect(cond.StringEquals['aws:SourceAccount']).toBe(env.account);
      expect(JSON.stringify(cond.ArnLike['aws:SourceArn'])).toContain('SftpServer');
    }
  });
});

describe('S3 access point on the ONTAP volume', () => {
  const ap = () => Object.values(t('sftp').findResources('AWS::FSx::S3AccessPointAttachment'))[0] as any;

  test('has Internet origin (no VpcConfiguration), as Transfer Family requires', () => {
    expect(ap().Properties.S3AccessPoint.VpcConfiguration).toBeUndefined();
  });

  test('policy explicitly denies every principal except the Transfer roles and the provisioner', () => {
    const stmts = ap().Properties.S3AccessPoint.Policy.Statement;
    const deny = stmts.find((s: any) => s.Sid === 'DenyEveryoneElse');
    expect(deny.Effect).toBe('Deny');
    expect(deny.Condition.StringNotEquals['aws:PrincipalArn']).toHaveLength(3);
    const roDeny = stmts.find((s: any) => s.Sid === 'DenyWritesForReadOnlyRole');
    expect(roDeny.Action).toEqual(expect.arrayContaining(['s3:PutObject', 's3:DeleteObject']));
  });

  test('policy never contains s3:GetBucketLocation (rejected in access-point policies)', () => {
    expect(JSON.stringify(ap().Properties.S3AccessPoint.Policy)).not.toContain('GetBucketLocation');
  });
});

describe('audit trail', () => {
  const sftp = t('sftp');

  test('audit bucket writes server access logs to a separate, retained bucket', () => {
    sftp.resourceCountIs('AWS::S3::Bucket', 2);
    sftp.hasResourceProperties('AWS::S3::Bucket', {
      LoggingConfiguration: { DestinationBucketName: Match.anyValue(), LogFilePrefix: 'audit-trail-bucket/' },
      VersioningConfiguration: { Status: 'Enabled' },
    });
    for (const b of Object.values(sftp.findResources('AWS::S3::Bucket')) as any[]) {
      expect(b.DeletionPolicy).toBe('Retain');
    }
  });
});

describe('hosts', () => {
  const client = t('client');

  test('all root volumes are encrypted and IMDSv2 is required', () => {
    const instances = Object.values(client.findResources('AWS::EC2::Instance')) as any[];
    expect(instances).toHaveLength(3);
    for (const i of instances) {
      expect(i.Properties.BlockDeviceMappings[0].Ebs.Encrypted).toBe(true);
    }
    client.resourceCountIs('AWS::EC2::LaunchTemplate', 3);
    client.allResourcesProperties('AWS::EC2::LaunchTemplate', {
      LaunchTemplateData: { MetadataOptions: { HttpTokens: 'required' } },
    });
  });

  test('no host can read the cluster-wide fsxadmin secret', () => {
    expect(JSON.stringify(client.findResources('AWS::IAM::Policy'))).not.toContain('fsxadmin');
  });

  test('host IDs are handed over through SSM parameters, not exports', () => {
    client.resourceCountIs('AWS::SSM::Parameter', 3);
    expect(Object.keys(client.toJSON().Outputs ?? {}).every((k) => !(client.toJSON().Outputs[k].Export))).toBe(true);
  });
});

test('VPC flow logs are enabled', () => {
  t('network').hasResourceProperties('AWS::EC2::FlowLog', { TrafficType: 'ALL' });
});

test('the self-test stack imports nothing from the other stacks', () => {
  expect(JSON.stringify(t('demo').toJSON())).not.toContain('Fn::ImportValue');
});

test('no hard-coded account IDs in any template', () => {
  for (const s of Object.values(stacks)) {
    const json = JSON.stringify(Template.fromStack(s).toJSON());
    for (const id of json.match(/\b\d{12}\b/g) ?? []) expect(id).toBe(env.account);
  }
});
