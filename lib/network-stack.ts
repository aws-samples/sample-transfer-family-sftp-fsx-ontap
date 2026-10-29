import { RemovalPolicy, Stack, StackProps } from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as logs from 'aws-cdk-lib/aws-logs';
import { config } from './config';

/**
 * Networking.
 *
 * Security posture:
 *  - FSx ONTAP, Managed AD and all hosts live in PRIVATE subnets.
 *  - The Transfer Family SFTP server uses a VPC endpoint (private ENIs): no public endpoint.
 *  - Security-group ingress names specific source SGs, never a CIDR, on every service port.
 *  - The NAT gateway is egress only (OS packages, SSM agent); it is not on the data path.
 *  - VPC flow logs record all traffic to CloudWatch Logs.
 */
export class NetworkStack extends Stack {
  public readonly vpc: ec2.Vpc;
  /** SG attached to the admin host that runs the AD/ONTAP bootstrap. */
  public readonly adminSg: ec2.SecurityGroup;
  /** SG attached to the FSx ONTAP file system (SVM + management endpoints). */
  public readonly fsxSg: ec2.SecurityGroup;
  /** SG attached to the Transfer Family VPC endpoint. */
  public readonly transferSg: ec2.SecurityGroup;
  /** SG attached to the internal Windows SMB reader. */
  public readonly clientSg: ec2.SecurityGroup;
  /** SG attached to the Linux SFTP client. */
  public readonly sftpClientSg: ec2.SecurityGroup;

  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    this.vpc = new ec2.Vpc(this, 'Vpc', {
      maxAzs: 2,
      natGateways: 1,
      ipAddresses: ec2.IpAddresses.cidr(config.vpcCidr),
      subnetConfiguration: [
        { name: 'public', subnetType: ec2.SubnetType.PUBLIC, cidrMask: 24 },
        { name: 'private', subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS, cidrMask: 24 },
      ],
    });
    this.vpc.addFlowLog('FlowLogs', {
      destination: ec2.FlowLogDestination.toCloudWatchLogs(new logs.LogGroup(this, 'FlowLogGroup', {
        retention: logs.RetentionDays.ONE_MONTH,
        removalPolicy: RemovalPolicy.DESTROY,
      })),
      trafficType: ec2.FlowLogTrafficType.ALL,
    });

    const sg = (id: string, desc: string) => new ec2.SecurityGroup(this, id, {
      vpc: this.vpc,
      description: `${config.prefix} ${desc}`,
      allowAllOutbound: true,
    });
    this.adminSg = sg('AdminSg', 'admin host (AD/ONTAP bootstrap) SG');
    this.fsxSg = sg('FsxSg', 'FSx ONTAP SG');
    this.transferSg = sg('TransferSg', 'Transfer Family VPC endpoint SG');
    this.clientSg = sg('ClientSg', 'internal Windows SMB reader SG');
    this.sftpClientSg = sg('SftpClientSg', 'Linux SFTP client SG');

    // FSx: the reader only needs SMB; the admin host also needs ONTAP REST (HTTPS) on the
    // SVM management endpoint. NFS is not used, so it is not opened.
    this.fsxSg.addIngressRule(this.clientSg, ec2.Port.tcp(445), 'SMB from the SMB reader');
    this.fsxSg.addIngressRule(this.adminSg, ec2.Port.tcp(445), 'SMB from the admin host (NTFS ACLs)');
    this.fsxSg.addIngressRule(this.adminSg, ec2.Port.tcp(443), 'ONTAP REST from the admin host');

    // Transfer Family VPC endpoint: SFTP only, only from the SFTP client SG.
    this.transferSg.addIngressRule(this.sftpClientSg, ec2.Port.tcp(22), 'SFTP from internal SFTP client');

    // No inbound rules on the hosts: they are driven only through SSM Run Command.
  }
}
