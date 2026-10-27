import * as path from 'path';
import { Stack, StackProps, CfnOutput, Duration, CustomResource, RemovalPolicy, custom_resources as cr } from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as fsx from 'aws-cdk-lib/aws-fsx';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as transfer from 'aws-cdk-lib/aws-transfer';
import * as cloudtrail from 'aws-cdk-lib/aws-cloudtrail';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as s3 from 'aws-cdk-lib/aws-s3';
import { config, SftpAccessLevel, hostParam, svmCertPinParam } from './config';
import { SsmBootstrap } from './ssm-bootstrap';

interface SftpStackProps extends StackProps {
  vpc: ec2.Vpc;
  transferSg: ec2.SecurityGroup;
  directoryId: string;
  fileSystemId: string;
  svmId: string;
  volumeId: string;
  groupSids: Record<string, string>;
  fsUserSid: string;
  readerSid: string;
}

const READ_ACTIONS = ['s3:GetObject', 's3:GetObjectTagging'];
const WRITE_ACTIONS = ['s3:PutObject', 's3:DeleteObject', 's3:PutObjectTagging'];

/**
 * The SFTP data path: share bootstrap -> S3 access point on the ONTAP volume -> Transfer.
 *
 *  1. Share bootstrap (SSM on the admin host): SMB share via the SVM's REST endpoint as
 *     vsadmin (pinned certificate), NTFS DACL as svc-fsxadm.
 *  2. S3 access point attachment, Windows identity ANYBANK\svc-fsx.
 *  3. Home directory created through the S3 API (zero-byte "partner01/" object) by a
 *     dedicated function whose role can do nothing else.
 *  4. Transfer Family server (VPC endpoint, AWS_DIRECTORY_SERVICE) and one "access" per
 *     AD group: SftpPartners read-write, SftpAuditors read-only, both on partner01/.
 *
 * Permissions are enforced in three independent places:
 *  - the access level's IAM role (what actions are possible at all),
 *  - a session policy per access (which folder; defence in depth behind the logical
 *    home-directory mapping that already confines the user),
 *  - the access-point policy (who may use the access point and with which actions).
 *
 * Security:
 *  - Access point network origin is Internet (no VpcConfiguration) because Transfer
 *    Family calls it from service infrastructure; traffic stays on the AWS backbone. The
 *    gate is IAM: every principal other than the two Transfer roles and the home-dir
 *    provisioner is explicitly denied, and each of those is denied what it does not need.
 *  - The Transfer endpoint is VPC-only; its SG allows port 22 only from the SFTP client SG.
 *  - Both Transfer role trust policies carry confused-deputy conditions pinned to this server.
 *  - Attribution: on the volume every file is owned by svc-fsx, so "who did what" lives on
 *    the AWS side: structured Transfer logs and CloudTrail data events on the access point.
 */
export class SftpStack extends Stack {
  public readonly serverId: string;
  public readonly smbIp: string;
  public readonly accessPointAlias: string;

  constructor(scope: Construct, id: string, props: SftpStackProps) {
    super(scope, id, props);

    const apName = config.accessPoint.name;
    const apArn = `arn:aws:s3:${this.region}:${this.account}:accesspoint/${apName}`;
    const partner = config.accessPoint.partnerDir;
    const d = config.directory;

    // ---------- 1. SMB share + NTFS DACL on the admin host ----------
    const share = new SsmBootstrap(this, 'ShareBootstrap', {
      hostParam: hostParam('admin'),
      hostNameTag: `${config.prefix}-admin-host`,
      script: 'share.ps1',
      fileSystemId: props.fileSystemId,
      svmId: props.svmId,
      vars: {
        PREFIX: config.prefix,
        NETBIOS: d.netbios,
        SVM_NAME: config.fsx.svmName,
        SHARE: config.fsx.shareName,
        JUNCTION: config.fsx.junctionPath,
        FSX_ADMIN_USER: d.fsxAdminUser,
        SID_FS: props.fsUserSid,
        SID_READER: props.readerSid,
        CANARY: config.demo.canaryFile,
        CERT_PIN_PARAM: svmCertPinParam,
      },
    });

    // ---------- Transfer roles: one per access level ----------
    // Trust: confused-deputy conditions pinned to THIS server (set below, once the
    // server exists; the server does not depend on these roles).
    const transferPrincipal = new iam.ServicePrincipal('transfer.amazonaws.com');
    const roles: Record<SftpAccessLevel, iam.Role> = {
      readwrite: new iam.Role(this, 'TransferRole', {
        roleName: `${config.prefix}-transfer-role`,
        assumedBy: transferPrincipal,
        description: 'Transfer Family read-write access to the FSx ONTAP S3 access point',
      }),
      readonly: new iam.Role(this, 'TransferReadOnlyRole', {
        roleName: `${config.prefix}-transfer-readonly-role`,
        assumedBy: transferPrincipal,
        description: 'Transfer Family read-only access to the FSx ONTAP S3 access point',
      }),
    };
    roles.readwrite.addToPolicy(new iam.PolicyStatement({
      sid: 'ReadWriteObjects', actions: [...READ_ACTIONS, ...WRITE_ACTIONS], resources: [`${apArn}/object/*`],
    }));
    roles.readonly.addToPolicy(new iam.PolicyStatement({
      sid: 'ReadObjects', actions: READ_ACTIONS, resources: [`${apArn}/object/*`],
    }));
    for (const r of Object.values(roles)) {
      r.addToPolicy(new iam.PolicyStatement({
        sid: 'ListAccessPoint', actions: ['s3:ListBucket', 's3:GetBucketLocation'], resources: [apArn],
      }));
    }

    // ---------- 2. S3 access point on the ONTAP volume (policy attached below) ----------
    const attachment = new fsx.CfnS3AccessPointAttachment(this, 'AccessPoint', {
      name: apName,
      type: 'ONTAP',
      ontapConfiguration: {
        volumeId: props.volumeId,
        fileSystemIdentity: {
          type: 'WINDOWS',
          windowsUser: { name: `${d.netbios}\\${d.fileSystemUser}` },
        },
      },
    });
    attachment.node.addDependency(share);
    const alias = attachment.attrS3AccessPointAlias;

    // ---------- 3. Home directory via the S3 API (own function, own role) ----------
    const homeDirFn = new lambda.Function(this, 'HomeDirFn', {
      runtime: lambda.Runtime.PYTHON_3_14,
      code: lambda.Code.fromAsset(path.join(__dirname, '..', 'lambda', 'homedirs')),
      handler: 'index.on_event',
      timeout: Duration.minutes(2),
      logGroup: new logs.LogGroup(this, 'HomeDirFnLogs', {
        retention: logs.RetentionDays.ONE_MONTH, removalPolicy: RemovalPolicy.DESTROY,
      }),
    });
    homeDirFn.addToRolePolicy(new iam.PolicyStatement({
      actions: ['s3:PutObject'], resources: [`${apArn}/object/${partner}/`],
    }));
    const homeDirs = new CustomResource(this, 'HomeDirs', {
      serviceToken: new cr.Provider(this, 'HomeDirProvider', { onEventHandler: homeDirFn }).serviceToken,
      properties: { Bucket: alias, Dirs: [partner] },
    });
    homeDirs.node.addDependency(attachment);
    // The access-point policy is a create-only property: any change replaces the access
    // point (new alias). Reference roles by static ARNs built from their fixed names, NOT
    // GetAtt, so updating a role (e.g. its trust policy) never replaces the access point.
    const roleArn = (name: string) => `arn:aws:iam::${this.account}:role/${name}`;
    // The provisioner role is never updated in place (its permissions live in a separate
    // policy resource), so its GetAtt is stable.
    const provisionerArn = homeDirFn.role!.roleArn;
    const rwRoleArn = roleArn(`${config.prefix}-transfer-role`);
    const roRoleArn = roleArn(`${config.prefix}-transfer-readonly-role`);
    attachment.node.addDependency(roles.readwrite, roles.readonly);

    // ---------- Access-point policy ----------
    const dataActions = [...READ_ACTIONS, ...WRITE_ACTIONS, 's3:ListBucket'];
    const apResources = [apArn, `${apArn}/object/*`];
    const asPrincipal = (arn: string) => ({ StringEquals: { 'aws:PrincipalArn': arn } });
    // s3:GetBucketLocation is valid in the roles' IAM policies but rejected in an
    // access-point resource policy (Access Analyzer: UNSUPPORTED_ACTION_IN_POLICY).
    attachment.s3AccessPoint = {
      // No vpcConfiguration => Internet network origin (required for Transfer Family).
      policy: {
        Version: '2012-10-17',
        Statement: [
          { Sid: 'AllowReadWriteRole', Effect: 'Allow', Principal: { AWS: '*' }, Action: dataActions,
            Resource: apResources, Condition: asPrincipal(rwRoleArn) },
          { Sid: 'AllowReadOnlyRole', Effect: 'Allow', Principal: { AWS: '*' },
            Action: [...READ_ACTIONS, 's3:ListBucket'], Resource: apResources,
            Condition: asPrincipal(roRoleArn) },
          { Sid: 'AllowHomeDirProvisioner', Effect: 'Allow', Principal: { AWS: '*' }, Action: ['s3:PutObject'],
            Resource: [`${apArn}/object/${partner}/`], Condition: asPrincipal(provisionerArn) },
          { Sid: 'DenyEveryoneElse', Effect: 'Deny', Principal: { AWS: '*' }, Action: dataActions,
            Resource: apResources,
            Condition: { StringNotEquals: { 'aws:PrincipalArn': [rwRoleArn, roRoleArn, provisionerArn] } } },
          { Sid: 'DenyWritesForReadOnlyRole', Effect: 'Deny', Principal: { AWS: '*' }, Action: WRITE_ACTIONS,
            Resource: apResources, Condition: asPrincipal(roRoleArn) },
          { Sid: 'DenyProvisionerAllButPut', Effect: 'Deny', Principal: { AWS: '*' },
            Action: dataActions.filter((a) => a !== 's3:PutObject'), Resource: apResources,
            Condition: asPrincipal(provisionerArn) },
        ],
      },
    };

    // ---------- 4. Transfer Family SFTP server ----------
    // Generated name: the group is retained on delete (audit history), so a fixed
    // name would collide with the retained copy on the next fresh deploy.
    const transferLogs = new logs.LogGroup(this, 'TransferStructuredLogs', {
      retention: config.logging.retentionDays as logs.RetentionDays,
      removalPolicy: RemovalPolicy.RETAIN,
    });
    const privateSubnets = props.vpc.selectSubnets({ subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS });
    const server = new transfer.CfnServer(this, 'SftpServer', {
      protocols: ['SFTP'],
      domain: 'S3',
      endpointType: 'VPC',
      endpointDetails: {
        vpcId: props.vpc.vpcId,
        subnetIds: privateSubnets.subnetIds,
        securityGroupIds: [props.transferSg.securityGroupId],
      },
      identityProviderType: 'AWS_DIRECTORY_SERVICE',
      identityProviderDetails: { directoryId: props.directoryId },
      // Structured JSON logs only (user, session, file, action) with a defined retention.
      // No logging role: structured logging is delivered by CloudWatch Logs itself, so
      // the legacy /aws/transfer/<server-id> log group and its IAM role are not needed.
      structuredLogDestinations: [transferLogs.logGroupArn],
      securityPolicyName: 'TransferSecurityPolicy-2024-01',
      tags: [{ key: 'Name', value: `${config.prefix}-sftp` }],
    });

    // Pin both roles' trust to this server. Transfer's AssumeRole for an AD-group access
    // carries a SourceArn for the server (session name "<user>.<id>@<server-id>"); both the
    // server ARN and its user ARN space are accepted, nothing outside this server is.
    for (const r of Object.values(roles)) {
      (r.node.defaultChild as iam.CfnRole).assumeRolePolicyDocument = {
        Version: '2012-10-17',
        Statement: [{
          Effect: 'Allow',
          Principal: { Service: 'transfer.amazonaws.com' },
          Action: 'sts:AssumeRole',
          Condition: {
            StringEquals: { 'aws:SourceAccount': this.account },
            ArnLike: { 'aws:SourceArn': [
              `arn:aws:transfer:${this.region}:${this.account}:server/${server.attrServerId}`,
              `arn:aws:transfer:${this.region}:${this.account}:user/${server.attrServerId}/*`,
            ] },
          },
        }],
      };
    }

    // One Transfer "access" per AD group (no CloudFormation resource exists for it).
    const folderPrefixes = [partner, `${partner}/`, `${partner}/*`];
    for (const g of config.sftpGroups) {
      const sessionPolicy = {
        Version: '2012-10-17',
        Statement: [
          { Sid: 'ListOwnFolder', Effect: 'Allow', Action: ['s3:ListBucket'], Resource: [apArn],
            Condition: { StringLike: { 's3:prefix': folderPrefixes } } },
          { Sid: 'LocateAccessPoint', Effect: 'Allow', Action: ['s3:GetBucketLocation'], Resource: [apArn] },
          { Sid: 'OwnFolderObjects', Effect: 'Allow',
            Action: g.access === 'readwrite' ? [...READ_ACTIONS, ...WRITE_ACTIONS] : READ_ACTIONS,
            // "partner01/*" also matches the zero-byte "partner01/" directory object.
            Resource: [`${apArn}/object/${partner}/*`] },
        ],
      };
      const params = {
        ServerId: server.attrServerId,
        ExternalId: props.groupSids[g.name],
        Role: roles[g.access].roleArn,
        Policy: JSON.stringify(sessionPolicy),
        HomeDirectoryType: 'LOGICAL',
        HomeDirectoryMappings: [{ Entry: '/', Target: `/${alias}/${partner}` }],
      };
      const physicalResourceId = cr.PhysicalResourceId.of(`${g.name}-access`);
      const access = new cr.AwsCustomResource(this, `${g.name}Access`, {
        onCreate: { service: 'Transfer', action: 'createAccess', parameters: params, physicalResourceId },
        onUpdate: { service: 'Transfer', action: 'updateAccess', parameters: params, physicalResourceId },
        onDelete: {
          service: 'Transfer', action: 'deleteAccess',
          parameters: { ServerId: server.attrServerId, ExternalId: props.groupSids[g.name] },
          ignoreErrorCodesMatching: 'ResourceNotFoundException',
        },
        policy: cr.AwsCustomResourcePolicy.fromStatements([
          new iam.PolicyStatement({
            actions: ['transfer:CreateAccess', 'transfer:UpdateAccess', 'transfer:DeleteAccess'],
            resources: [server.attrArn],
          }),
          new iam.PolicyStatement({ actions: ['iam:PassRole'], resources: [roles[g.access].roleArn] }),
          // Transfer validates the group against the directory when creating access.
          new iam.PolicyStatement({ actions: ['ds:DescribeDirectories'], resources: ['*'] }),
        ]),
        timeout: Duration.minutes(2),
        installLatestAwsSdk: false,
      });
      access.node.addDependency(homeDirs);
    }

    // ---------- 5. Audit and alarms ----------
    const metric = (name: string, pattern: string) => {
      new logs.MetricFilter(this, `${name}Filter`, {
        logGroup: transferLogs,
        metricNamespace: config.prefix,
        metricName: name,
        filterPattern: logs.FilterPattern.literal(pattern),
        metricValue: '1',
        defaultValue: 0,
      });
      return new cloudwatch.Metric({ namespace: config.prefix, metricName: name, statistic: 'Sum', period: Duration.minutes(5) });
    };
    new cloudwatch.Alarm(this, 'SftpAuthFailuresAlarm', {
      alarmName: `${config.prefix}-sftp-auth-failures`,
      alarmDescription: 'SFTP authentication failures (possible password guessing).',
      metric: metric('SftpAuthFailures', '"AUTH_FAILURE"'),
      threshold: config.logging.authFailureThreshold,
      evaluationPeriods: 1,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    // Refused operations ("Access denied", e.g. an auditor trying to write, or the
    // self-test's deliberate checks) are counted separately and do not page.
    metric('SftpAccessDenied', '"ERROR" "Access denied"');
    new cloudwatch.Alarm(this, 'SftpErrorsAlarm', {
      alarmName: `${config.prefix}-sftp-errors`,
      alarmDescription: 'SFTP session or transfer errors other than refused operations.',
      metric: metric('SftpErrors', '"ERROR" -"Access denied"'),
      threshold: 1,
      evaluationPeriods: 1,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });

    // Data events on the access point: every object read/write with the Transfer session
    // (which carries the SFTP user name) as the caller. This is the system of record for
    // "who uploaded this file": on the volume every file is owned by svc-fsx.
    // Server access logs for the audit bucket: who read or changed the audit logs themselves.
    // This bucket is the end of the chain and does not log itself (that would loop).
    const auditAccessLogBucket = new s3.Bucket(this, 'AuditAccessLogBucket', {
      encryption: s3.BucketEncryption.S3_MANAGED,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      objectOwnership: s3.ObjectOwnership.BUCKET_OWNER_ENFORCED,
      versioned: true,
      lifecycleRules: [{
        expiration: Duration.days(config.logging.retentionDays),
        noncurrentVersionExpiration: Duration.days(config.logging.retentionDays),
      }],
      removalPolicy: RemovalPolicy.RETAIN,
    });
    const auditBucket = new s3.Bucket(this, 'AuditTrailBucket', {
      serverAccessLogsBucket: auditAccessLogBucket,
      serverAccessLogsPrefix: 'audit-trail-bucket/',
      encryption: s3.BucketEncryption.S3_MANAGED,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      objectOwnership: s3.ObjectOwnership.BUCKET_OWNER_ENFORCED,
      // Versioning keeps an overwritten or deleted audit log recoverable.
      versioned: true,
      lifecycleRules: [{
        expiration: Duration.days(config.logging.retentionDays),
        noncurrentVersionExpiration: Duration.days(config.logging.retentionDays),
      }],
      removalPolicy: RemovalPolicy.RETAIN,
    });
    const trail = new cloudtrail.Trail(this, 'AccessPointDataTrail', {
      trailName: `${config.prefix}-accesspoint-data`,
      bucket: auditBucket,
      isMultiRegionTrail: false,
      includeGlobalServiceEvents: false,
      sendToCloudWatchLogs: true,
      cloudWatchLogsRetention: config.logging.retentionDays as logs.RetentionDays,
      enableFileValidation: true,
    });
    const cfnTrail = trail.node.defaultChild as cloudtrail.CfnTrail;
    // Advanced selectors replace classic ones: data events on this access point only, no
    // management events (the account's organization trail already records those).
    cfnTrail.addPropertyDeletionOverride('EventSelectors');
    cfnTrail.advancedEventSelectors = [{
      name: 'FSx ONTAP access point object activity',
      fieldSelectors: [
        { field: 'eventCategory', equalTo: ['Data'] },
        // Verified empirically: events through an FSx-attached access point are typed
        // AWS::S3::Object with ARNs under arn:...:accesspoint/<name>/ (the volume and the
        // access point are listed as additional resources).
        { field: 'resources.type', equalTo: ['AWS::S3::Object'] },
        { field: 'resources.ARN', startsWith: [`${apArn}/`] },
      ],
    }];

    this.serverId = server.attrServerId;
    this.accessPointAlias = alias;
    this.smbIp = share.getAtt('SmbIp');
    new CfnOutput(this, 'ServerId', { value: server.attrServerId });
    new CfnOutput(this, 'AccessPointAlias', { value: alias });
    new CfnOutput(this, 'AccessPointArn', { value: attachment.attrS3AccessPointResourceArn });
    new CfnOutput(this, 'SmbIp', { value: this.smbIp });
    new CfnOutput(this, 'ReadWriteRoleArn', { value: roles.readwrite.roleArn });
    new CfnOutput(this, 'ReadOnlyRoleArn', { value: roles.readonly.roleArn });
    new CfnOutput(this, 'TransferLogGroup', { value: transferLogs.logGroupName });
    new CfnOutput(this, 'AuditTrailLogGroup', { value: trail.logGroup!.logGroupName });
  }
}
