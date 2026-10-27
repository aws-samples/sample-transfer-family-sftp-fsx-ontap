import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { Duration, CustomResource, RemovalPolicy, Stack, custom_resources as cr } from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as logs from 'aws-cdk-lib/aws-logs';

const BOOTSTRAP_DIR = path.join(__dirname, '..', 'lambda', 'bootstrap');

export interface SsmBootstrapProps {
  /** SSM parameter holding the admin host's instance ID (resolved at run time). */
  hostParam: string;
  /** Name tag of the admin host; scopes the start/stop/send-command permissions. */
  hostNameTag: string;
  /** Script file name in lambda/bootstrap. */
  script: string;
  /** Values for the script's __NAME__ placeholders. */
  vars: Record<string, string>;
  /** Optional: resolve __MGMT_IP__ / __SMB_IP__ from this file system + SVM. */
  fileSystemId?: string;
  svmId?: string;
}

/**
 * Runs a PowerShell script on the admin host through SSM Run Command as a custom
 * resource, with a real lifecycle: Create/Update apply the desired state (the previous
 * properties are passed so removed objects get cleaned up), Delete removes what the
 * script created. The admin host is started for the run and stopped afterwards.
 * The script's SHA-256 is part of the resource properties, so editing the script
 * re-runs it on the next deploy. Every "OUT_<KEY>=value" line the script prints is
 * available through getAtt(KEY).
 */
export class SsmBootstrap extends Construct {
  public readonly resource: CustomResource;

  constructor(scope: Construct, id: string, props: SsmBootstrapProps) {
    super(scope, id);
    const stack = Stack.of(this);

    const fnProps = {
      runtime: lambda.Runtime.PYTHON_3_14,
      code: lambda.Code.fromAsset(BOOTSTRAP_DIR),
      timeout: Duration.minutes(14),
      logGroup: new logs.LogGroup(this, 'Logs', {
        retention: logs.RetentionDays.ONE_MONTH, removalPolicy: RemovalPolicy.DESTROY,
      }),
    };
    const onEvent = new lambda.Function(this, 'OnEvent', { ...fnProps, handler: 'index.on_event' });
    const isComplete = new lambda.Function(this, 'IsComplete', { ...fnProps, handler: 'index.is_complete' });
    const hostTag = { StringEquals: { 'aws:ResourceTag/Name': props.hostNameTag } };
    for (const f of [onEvent, isComplete]) {
      f.addToRolePolicy(new iam.PolicyStatement({
        actions: ['ssm:DescribeInstanceInformation', 'ssm:GetCommandInvocation', 'ec2:DescribeInstances',
          'fsx:DescribeStorageVirtualMachines'],
        resources: ['*'],
      }));
      f.addToRolePolicy(new iam.PolicyStatement({
        actions: ['ssm:GetParameter'],
        resources: [`arn:aws:ssm:${stack.region}:${stack.account}:parameter${props.hostParam}`],
      }));
      // Start/stop only the admin host (matched by its Name tag).
      f.addToRolePolicy(new iam.PolicyStatement({
        actions: ['ec2:StartInstances', 'ec2:StopInstances'],
        resources: [`arn:aws:ec2:${stack.region}:${stack.account}:instance/*`],
        conditions: hostTag,
      }));
    }
    onEvent.addToRolePolicy(new iam.PolicyStatement({
      actions: ['ssm:SendCommand'],
      resources: [`arn:aws:ec2:${stack.region}:${stack.account}:instance/*`],
      conditions: { StringEquals: { 'ssm:resourceTag/Name': props.hostNameTag } },
    }));
    onEvent.addToRolePolicy(new iam.PolicyStatement({
      actions: ['ssm:SendCommand'],
      resources: [`arn:aws:ssm:${stack.region}::document/AWS-RunPowerShellScript`],
    }));
    const provider = new cr.Provider(this, 'Provider', {
      onEventHandler: onEvent,
      isCompleteHandler: isComplete,
      queryInterval: Duration.seconds(30),
      totalTimeout: Duration.hours(1),
    });

    const scriptSha256 = crypto.createHash('sha256')
      .update(fs.readFileSync(path.join(BOOTSTRAP_DIR, props.script)))
      .update(fs.readFileSync(path.join(BOOTSTRAP_DIR, 'index.py')))
      .digest('hex');
    this.resource = new CustomResource(this, 'Run', {
      serviceToken: provider.serviceToken,
      properties: {
        HostParam: props.hostParam,
        Script: props.script,
        ScriptSha256: scriptSha256,
        Vars: props.vars,
        ...(props.fileSystemId ? { FileSystemId: props.fileSystemId, SvmId: props.svmId } : {}),
      },
    });
  }

  getAtt(key: string): string {
    return this.resource.getAttString(key);
  }
}
