import { Stack, StackProps, CfnOutput } from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import * as ssm from 'aws-cdk-lib/aws-ssm';
import { config, hostParam, svmCertPinParam } from './config';

interface ClientStackProps extends StackProps {
  vpc: ec2.Vpc;
  adminSg: ec2.SecurityGroup;
  clientSg: ec2.SecurityGroup;
  sftpClientSg: ec2.SecurityGroup;
  adminSecret: secretsmanager.ISecret;
  userSecrets: Record<string, secretsmanager.ISecret>;
}

/**
 * Three hosts, all in PRIVATE subnets with NO inbound rules, driven only through SSM
 * Run Command (no RDP/SSH listener exposed). Root volumes are always encrypted,
 * independent of the account's EBS default-encryption setting.
 *
 * Least privilege: each host can read only the secrets its own job needs.
 *  - Admin host (Windows): runs the AD and ONTAP bootstrap. Reads the AD admin, SVM
 *    vsadmin and demo-user secrets (it sets the demo users' passwords), and owns the SVM
 *    management certificate pin parameter.
 *  - SMB reader (Windows): reads the uploaded file over SMB. Reads reader01 only.
 *  - SFTP client (Linux): logs in over SFTP. Reads the SFTP group users and the no-group
 *    test user only.
 */
export class ClientStack extends Stack {
  public readonly adminInstance: ec2.Instance;
  public readonly windowsInstance: ec2.Instance;
  public readonly linuxInstance: ec2.Instance;

  constructor(scope: Construct, id: string, props: ClientStackProps) {
    super(scope, id, props);

    const ssmCore = iam.ManagedPolicy.fromAwsManagedPolicyName('AmazonSSMManagedInstanceCore');
    const role = (rid: string) => new iam.Role(this, rid, {
      assumedBy: new iam.ServicePrincipal('ec2.amazonaws.com'),
      managedPolicies: [ssmCore],
    });
    const encryptedRoot = (deviceName: string, sizeGiB: number): ec2.BlockDevice[] => [{
      deviceName,
      volume: ec2.BlockDeviceVolume.ebs(sizeGiB, { encrypted: true, volumeType: ec2.EbsDeviceVolumeType.GP3 }),
    }];
    // AMIs: explicit override, or the latest image looked up once and cached in
    // cdk.context.json (see config.amis), so a new AWS image release never replaces hosts.
    const windowsAmi = config.amis.windows
      ? ec2.MachineImage.genericWindows({ [this.region]: config.amis.windows })
      : ec2.MachineImage.fromSsmParameter(
        '/aws/service/ami-windows-latest/Windows_Server-2022-English-Full-Base',
        { os: ec2.OperatingSystemType.WINDOWS, cachedInContext: true });
    const linuxAmi = config.amis.linux
      ? ec2.MachineImage.genericLinux({ [this.region]: config.amis.linux })
      : ec2.MachineImage.latestAmazonLinux2023({ cpuType: ec2.AmazonLinuxCpuType.ARM_64, cachedInContext: true });
    const privateSubnets = { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS };

    // ---------- Admin host ----------
    const adminRole = role('AdminRole');
    props.adminSecret.grantRead(adminRole);
    Object.values(props.userSecrets).forEach((s) => s.grantRead(adminRole));
    // The SVM's vsadmin secret lives in the FSx stack, which deploys after this one: grant
    // by name pattern instead of a cross-stack reference (which would create a cycle).
    // The cluster-wide fsxadmin secret is NOT readable by any host.
    adminRole.addToPolicy(new iam.PolicyStatement({
      actions: ['secretsmanager:GetSecretValue', 'secretsmanager:DescribeSecret'],
      resources: [`arn:aws:secretsmanager:${this.region}:${this.account}:secret:${config.prefix}/vsadmin-*`],
    }));
    // Trust-on-first-use pin of the SVM management certificate (see share.ps1).
    adminRole.addToPolicy(new iam.PolicyStatement({
      actions: ['ssm:GetParameter', 'ssm:PutParameter', 'ssm:DeleteParameter'],
      resources: [`arn:aws:ssm:${this.region}:${this.account}:parameter${svmCertPinParam}`],
    }));
    this.adminInstance = new ec2.Instance(this, 'AdminHost', {
      vpc: props.vpc,
      vpcSubnets: privateSubnets,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
      machineImage: windowsAmi,
      securityGroup: props.adminSg,
      role: adminRole,
      requireImdsv2: true,
      blockDevices: encryptedRoot('/dev/sda1', 50),
      instanceName: `${config.prefix}-admin-host`,
    });

    // ---------- SMB reader ----------
    const readerRole = role('WindowsRole');
    props.userSecrets[config.directory.readerUser].grantRead(readerRole);
    this.windowsInstance = new ec2.Instance(this, 'SmbReader', {
      vpc: props.vpc,
      vpcSubnets: privateSubnets,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.LARGE),
      machineImage: windowsAmi,
      securityGroup: props.clientSg,
      role: readerRole,
      requireImdsv2: true,
      blockDevices: encryptedRoot('/dev/sda1', 50),
      instanceName: `${config.prefix}-smb-reader`,
    });

    // ---------- SFTP client ----------
    const linRole = role('LinuxRole');
    [...config.sftpGroups.map((g) => g.user), config.directory.noGroupUser]
      .forEach((u) => props.userSecrets[u].grantRead(linRole));
    this.linuxInstance = new ec2.Instance(this, 'SftpClientHost', {
      vpc: props.vpc,
      vpcSubnets: privateSubnets,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.T4G, ec2.InstanceSize.SMALL),
      machineImage: linuxAmi,
      securityGroup: props.sftpClientSg,
      role: linRole,
      requireImdsv2: true,
      blockDevices: encryptedRoot('/dev/xvda', 10),
      instanceName: `${config.prefix}-sftp-client`,
    });

    // Host IDs are handed to other stacks through SSM parameters, not exports, so a host
    // can be replaced without "export in use" failures in the stacks that drive it.
    const hosts: Array<['admin' | 'reader' | 'sftp-client', ec2.Instance]> = [
      ['admin', this.adminInstance], ['reader', this.windowsInstance], ['sftp-client', this.linuxInstance],
    ];
    for (const [name, inst] of hosts) {
      new ssm.StringParameter(this, `HostParam-${name}`, {
        parameterName: hostParam(name),
        stringValue: inst.instanceId,
        description: `${config.prefix} ${name} instance ID`,
      });
    }

    new CfnOutput(this, 'AdminHostId', { value: this.adminInstance.instanceId });
    new CfnOutput(this, 'WindowsReaderId', { value: this.windowsInstance.instanceId });
    new CfnOutput(this, 'SftpClientId', { value: this.linuxInstance.instanceId });
  }
}
