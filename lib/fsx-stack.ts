import { Stack, StackProps, CfnOutput } from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as fsx from 'aws-cdk-lib/aws-fsx';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import { config } from './config';
import { generatedSecret } from './directory-stack';

interface FsxStackProps extends StackProps {
  vpc: ec2.Vpc;
  fsxSg: ec2.SecurityGroup;
  domainName: string;
  dnsIps: string[];
  /** Password secret of the delegated SVM join account (svc-svmjoin). */
  svmJoinSecret: secretsmanager.ISecret;
}

/**
 * FSx for NetApp ONTAP file system + SVM (joined to the Managed AD) + NTFS volume.
 *
 * The SVM joins with svc-svmjoin, created and delegated by the identity stack (deployed
 * first). The SMB share itself is created by the sftp stack's bootstrap through the SVM's
 * ONTAP REST API as vsadmin (FSx has no API for SMB shares).
 */
export class FsxStack extends Stack {
  public readonly fileSystem: fsx.CfnFileSystem;
  public readonly svm: fsx.CfnStorageVirtualMachine;
  public readonly volume: fsx.CfnVolume;
  public readonly fsxAdminSecret: secretsmanager.Secret;
  public readonly svmAdminSecret: secretsmanager.Secret;

  constructor(scope: Construct, id: string, props: FsxStackProps) {
    super(scope, id, props);

    const privateSubnets = props.vpc.selectSubnets({ subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS });

    // ONTAP cluster admin (fsxadmin): set because FSx requires it, but no host can read it.
    this.fsxAdminSecret = generatedSecret(this, 'FsxAdminSecret', `${config.prefix}/fsxadmin`, 'fsxadmin',
      'FSx ONTAP fsxadmin password (break-glass only; not used by the deployment)');
    // SVM-scoped admin (vsadmin): the only ONTAP account the bootstrap uses, to create the
    // SMB share through the SVM's own management endpoint.
    this.svmAdminSecret = generatedSecret(this, 'SvmAdminSecret', `${config.prefix}/vsadmin`, 'vsadmin',
      'FSx ONTAP SVM vsadmin password (creates the SMB share)');

    this.fileSystem = new fsx.CfnFileSystem(this, 'OntapFs', {
      fileSystemType: 'ONTAP',
      storageCapacity: config.fsx.storageCapacityGiB,
      subnetIds: [privateSubnets.subnetIds[0]],
      securityGroupIds: [props.fsxSg.securityGroupId],
      ontapConfiguration: {
        deploymentType: config.fsx.deploymentType,
        throughputCapacity: config.fsx.throughputCapacityMBps,
        preferredSubnetId: privateSubnets.subnetIds[0],
        fsxAdminPassword: this.fsxAdminSecret.secretValueFromJson('password').unsafeUnwrap(),
      },
      tags: [{ key: 'Name', value: `${config.prefix}-ontap` }],
    });

    const domainDn = props.domainName.split('.').map((p) => `DC=${p}`).join(',');
    this.svm = new fsx.CfnStorageVirtualMachine(this, 'Svm', {
      fileSystemId: this.fileSystem.ref,
      name: config.fsx.svmName,
      rootVolumeSecurityStyle: 'NTFS',
      svmAdminPassword: this.svmAdminSecret.secretValueFromJson('password').unsafeUnwrap(),
      activeDirectoryConfiguration: {
        netBiosName: config.fsx.svmName.toUpperCase(),
        selfManagedActiveDirectoryConfiguration: {
          domainName: props.domainName,
          dnsIps: props.dnsIps,
          // Least privilege: a dedicated account with join rights on the Computers OU only
          // (delegated by the identity stack), not the directory Admin.
          userName: config.directory.svmJoinUser,
          password: props.svmJoinSecret.secretValueFromJson('password').unsafeUnwrap(),
          // AWS Managed Microsoft AD: delegated OU and delegated FSx admin group.
          organizationalUnitDistinguishedName: `OU=Computers,OU=${config.directory.netbios},${domainDn}`,
          fileSystemAdministratorsGroup: config.directory.fsxAdminsGroup,
        },
      },
    });

    this.volume = new fsx.CfnVolume(this, 'Vol1', {
      name: config.fsx.volumeName,
      volumeType: 'ONTAP',
      ontapConfiguration: {
        storageVirtualMachineId: this.svm.ref,
        junctionPath: config.fsx.junctionPath,
        securityStyle: 'NTFS',
        sizeInMegabytes: String(config.fsx.volumeSizeMiB),
        storageEfficiencyEnabled: 'true',
        // The final backup FSx takes on deletion then carries the Name tag, so it can be found.
        copyTagsToBackups: 'true',
        tieringPolicy: { name: 'AUTO' },
      },
      tags: [{ key: 'Name', value: `${config.prefix}-${config.fsx.volumeName}` }],
    });

    new CfnOutput(this, 'FileSystemId', { value: this.fileSystem.ref });
    new CfnOutput(this, 'SvmId', { value: this.svm.ref });
    new CfnOutput(this, 'VolumeId', { value: this.volume.ref });
  }
}
