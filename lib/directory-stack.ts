import { Stack, StackProps, CfnOutput, Fn } from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as directory from 'aws-cdk-lib/aws-directoryservice';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import { config, adUsers, userSecretName } from './config';

interface DirectoryStackProps extends StackProps {
  vpc: ec2.Vpc;
}

/** Generated password secret (alphanumeric; contains upper, lower and digits for AD complexity). */
export function generatedSecret(scope: Construct, id: string, name: string, username: string, description: string) {
  return new secretsmanager.Secret(scope, id, {
    secretName: name,
    description,
    generateSecretString: {
      passwordLength: 24,
      excludePunctuation: true,
      includeSpace: false,
      requireEachIncludedType: true,
      generateStringKey: 'password',
      secretStringTemplate: JSON.stringify({ username }),
    },
  });
}

/**
 * AWS Managed Microsoft AD.
 *
 * One directory serves two roles:
 *   1. The native identity provider (AWS_DIRECTORY_SERVICE) for the Transfer Family SFTP
 *      server: clients authenticate with their AD username/password.
 *   2. The identity source the FSx ONTAP SVM is joined to, so NTFS ownership by the fixed
 *      access-point identity (ANYBANK\svc-fsx) resolves.
 *
 * All passwords are generated into Secrets Manager; no credential appears in source.
 * The users and groups are created inside AD by the identity stack (bootstrap script run
 * via SSM on the admin host): CloudFormation has no resource type for AD users or groups,
 * and the Directory Service Data API is not available in every region.
 */
export class DirectoryStack extends Stack {
  public readonly adminSecret: secretsmanager.Secret;
  /** Password secret per AD user, keyed by sAMAccountName. */
  public readonly userSecrets: Record<string, secretsmanager.Secret>;
  public readonly directoryId: string;
  public readonly dnsIps: string[];

  constructor(scope: Construct, id: string, props: DirectoryStackProps) {
    super(scope, id, props);

    this.adminSecret = new secretsmanager.Secret(this, 'AdAdminSecret', {
      secretName: `${config.prefix}/ad-admin`,
      description: 'AWS Managed Microsoft AD admin password',
      generateSecretString: {
        passwordLength: 24,
        excludePunctuation: true,
        includeSpace: false,
        generateStringKey: 'password',
        secretStringTemplate: JSON.stringify({ username: 'Admin' }),
      },
    });

    // Demo AD users: access-point identity, service accounts, SMB reader, one user per SFTP group.
    this.userSecrets = Object.fromEntries(adUsers.map((u) => [u,
      generatedSecret(this, `User-${u}`, userSecretName(u), u, `AD password for ${u}`)]));

    const privateSubnetIds = props.vpc.selectSubnets({
      subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
    }).subnetIds;

    const mad = new directory.CfnMicrosoftAD(this, 'ManagedAd', {
      name: config.directory.domainName,
      shortName: config.directory.netbios,
      password: this.adminSecret.secretValueFromJson('password').unsafeUnwrap(),
      edition: config.directory.edition,
      vpcSettings: {
        vpcId: props.vpc.vpcId,
        // Managed AD requires exactly two subnets in different AZs.
        subnetIds: [privateSubnetIds[0], privateSubnetIds[1]],
      },
    });

    this.directoryId = mad.ref;
    this.dnsIps = mad.attrDnsIpAddresses;

    new CfnOutput(this, 'DirectoryId', { value: this.directoryId });
    new CfnOutput(this, 'DirectoryDnsIps', { value: Fn.join(',', this.dnsIps) });
    new CfnOutput(this, 'DomainName', { value: config.directory.domainName });
    new CfnOutput(this, 'AdAdminSecretArn', { value: this.adminSecret.secretArn });
  }
}
