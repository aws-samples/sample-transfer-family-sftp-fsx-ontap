import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { RemovalPolicy, Stack, StackProps, CfnOutput, Duration, CustomResource, custom_resources as cr } from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as logs from 'aws-cdk-lib/aws-logs';
import { config, hostParam } from './config';

/** No cross-stack inputs: the self-test discovers the environment at run time. */
type DemoStackProps = StackProps;

const TEST_DIR = path.join(__dirname, '..', 'lambda', 'demo');

/**
 * End-to-end self-test (see lambda/demo/index.py for the full list of checks).
 *
 * The test is a standalone function: invoke it whenever you want a verification. It runs
 * at deploy time ONLY when the test code itself changes, so ordinary infrastructure
 * deploys neither write data nor depend on the test. Test files are written to
 * <partner>/_selftest/ and removed afterwards.
 */
export class DemoStack extends Stack {
  constructor(scope: Construct, id: string, props: DemoStackProps) {
    super(scope, id, props);

    const logGroup = new logs.LogGroup(this, 'DemoLogs', {
      retention: logs.RetentionDays.ONE_MONTH,
      removalPolicy: RemovalPolicy.DESTROY,
    });
    const rw = config.sftpGroups.find((g) => g.access === 'readwrite')!;
    const ro = config.sftpGroups.find((g) => g.access === 'readonly')!;
    const testConfig = {
      Prefix: config.prefix,
      ServerTag: `${config.prefix}-sftp`,
      AccessPointName: config.accessPoint.name,
      FileSystemTag: `${config.prefix}-ontap`,
      SvmName: config.fsx.svmName,
      RwUser: rw.user,
      RoUser: ro.user,
      NoGroupUser: config.directory.noGroupUser,
      Reader: config.directory.readerUser,
      Netbios: config.directory.netbios,
      Share: config.fsx.shareName,
      PartnerDir: config.accessPoint.partnerDir,
      FileName: config.demo.fileName,
      SelfTestDir: config.demo.selfTestDir,
      Canary: config.demo.canaryFile,
    };
    const fn = new lambda.Function(this, 'SelfTest', {
      functionName: `${config.prefix}-selftest`,
      runtime: lambda.Runtime.PYTHON_3_14,
      code: lambda.Code.fromAsset(TEST_DIR),
      handler: 'index.run_test',
      timeout: Duration.minutes(15),
      logGroup,
      environment: { TEST_CONFIG: Stack.of(this).toJsonString(testConfig) },
    });

    const instances = `arn:aws:ec2:${this.region}:${this.account}:instance/*`;
    fn.addToRolePolicy(new iam.PolicyStatement({
      actions: ['ssm:SendCommand'],
      resources: [instances],
      conditions: { StringEquals: { 'ssm:resourceTag/Name': [`${config.prefix}-sftp-client`, `${config.prefix}-smb-reader`] } },
    }));
    fn.addToRolePolicy(new iam.PolicyStatement({
      actions: ['ssm:SendCommand'],
      resources: [
        `arn:aws:ssm:${this.region}::document/AWS-RunShellScript`,
        `arn:aws:ssm:${this.region}::document/AWS-RunPowerShellScript`,
      ],
    }));
    fn.addToRolePolicy(new iam.PolicyStatement({
      actions: ['ssm:GetParameter'],
      resources: (['sftp-client', 'reader'] as const).map((h) => `arn:aws:ssm:${this.region}:${this.account}:parameter${hostParam(h)}`),
    }));
    fn.addToRolePolicy(new iam.PolicyStatement({
      actions: ['ssm:GetCommandInvocation', 'ec2:DescribeVpcEndpoints', 'ec2:DescribeNetworkInterfaces'],
      resources: ['*'],
    }));
    // Run-time discovery (read-only).
    fn.addToRolePolicy(new iam.PolicyStatement({
      actions: ['transfer:ListServers', 'transfer:ListTagsForResource', 'transfer:DescribeServer',
        'fsx:DescribeFileSystems', 'fsx:DescribeStorageVirtualMachines', 'fsx:DescribeS3AccessPointAttachments'],
      resources: ['*'],
    }));
    // Deliberately ALLOWED by IAM: the test proves the access-point policy still denies it.
    fn.addToRolePolicy(new iam.PolicyStatement({
      sid: 'ProbeAccessPointDenial',
      actions: ['s3:GetObject'],
      resources: [`arn:aws:s3:${this.region}:${this.account}:accesspoint/${config.accessPoint.name}/object/*`],
    }));

    // Run at deploy time only when the test code changes.
    const testCodeSha256 = crypto.createHash('sha256');
    for (const f of fs.readdirSync(TEST_DIR).filter((n) => !n.startsWith('__')).sort()) {
      testCodeSha256.update(f).update(fs.readFileSync(path.join(TEST_DIR, f)));
    }
    const onEvent = new lambda.Function(this, 'SelfTestOnDeploy', {
      runtime: lambda.Runtime.PYTHON_3_14,
      code: lambda.Code.fromAsset(TEST_DIR),
      handler: 'index.on_event',
      timeout: Duration.minutes(15),
      logGroup,
      environment: { TEST_CONFIG: Stack.of(this).toJsonString(testConfig) },
      role: fn.role,
    });
    new CfnOutput(this, 'SelfTestFunction', { value: fn.functionName });
    new CfnOutput(this, 'EvidenceLogGroup', { value: logGroup.logGroupName });
    // `-c skipSelfTest=true` deploys the function without the deploy-time run (recovery /
    // bootstrap ordering); invoke it afterwards.
    if (this.node.tryGetContext('skipSelfTest') === 'true') return;
    const run = new CustomResource(this, 'SelfTestRun', {
      serviceToken: new cr.Provider(this, 'SelfTestProvider', { onEventHandler: onEvent }).serviceToken,
      properties: { TestCodeSha256: testCodeSha256.digest('hex') },
    });

    new CfnOutput(this, 'Result', { value: run.getAttString('Result') });
    new CfnOutput(this, 'Denials', { value: run.getAttString('Denials') });
    new CfnOutput(this, 'Sha256', { value: run.getAttString('Sha256') });
    new CfnOutput(this, 'SmbOwner', { value: run.getAttString('SmbOwner') });
  }
}
