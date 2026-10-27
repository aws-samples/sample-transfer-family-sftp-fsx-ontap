import { Environment } from 'aws-cdk-lib';

/**
 * Target account and region: taken from the CDK CLI's credentials and region
 * (CDK_DEFAULT_ACCOUNT / CDK_DEFAULT_REGION), or overridden with
 * `-c account=<id> -c region=<region>`. Nothing is hard-coded.
 */
export function resolveEnv(context: (key: string) => unknown): Required<Environment> {
  const account = (context('account') as string | undefined) ?? process.env.CDK_DEFAULT_ACCOUNT;
  const region = (context('region') as string | undefined) ?? process.env.CDK_DEFAULT_REGION;
  if (!account || !region) {
    throw new Error('No target account/region: configure AWS credentials and a region, or pass -c account=... -c region=...');
  }
  return { account, region };
}

export type SftpAccessLevel = 'readwrite' | 'readonly';

export const config = {
  /** Prefix applied to all resource names for easy identification / cleanup. */
  prefix: 'sftp-ontap-demo',

  /** VPC CIDR. Change it if it overlaps a network you peer with. */
  vpcCidr: '10.20.0.0/16',

  /** Active Directory config (AWS Managed Microsoft AD). */
  directory: {
    domainName: 'anybank.local',
    netbios: 'ANYBANK',
    edition: 'Standard' as const,
    /**
     * Fixed file-system (Windows/NTFS) identity used by the S3 access point for ALL file
     * operations, independent of which SFTP user authenticated.
     */
    fileSystemUser: 'svc-fsx',
    /** Service account the SVM uses to join/stay joined (delegated rights on the Computers OU only). */
    svmJoinUser: 'svc-svmjoin',
    /** Service account that sets NTFS ACLs (member of "AWS Delegated FSx Administrators"). */
    fsxAdminUser: 'svc-fsxadm',
    /** Managed AD group the SVM treats as file-system administrators. */
    fsxAdminsGroup: 'AWS Delegated FSx Administrators',
    /** AD user the internal SMB client reads the share as. */
    readerUser: 'reader01',
    /** Valid AD user in NO SFTP group: the self-test proves it cannot log in over SFTP. */
    noGroupUser: 'nogroup01',
  },

  /**
   * SFTP access is granted per AD group (Transfer "access" keyed on the group SID).
   * Each group has one user and a different permission level on the same folder.
   */
  sftpGroups: [
    { name: 'SftpPartners', user: 'partner01', access: 'readwrite' as SftpAccessLevel },
    { name: 'SftpAuditors', user: 'auditor01', access: 'readonly' as SftpAccessLevel },
  ],

  /** FSx for NetApp ONTAP config. */
  fsx: {
    storageCapacityGiB: 1024,
    throughputCapacityMBps: 128,
    deploymentType: 'SINGLE_AZ_1' as const,
    svmName: 'svm01',
    volumeName: 'vol1',
    volumeSizeMiB: 102400,
    junctionPath: '/vol1',
    /** SMB share created on the volume junction path. */
    shareName: 'share',
  },

  /** S3 Access Point attached to the ONTAP volume. */
  accessPoint: {
    name: 'sftp-ap',
    /** Folder both SFTP groups land in (created via the S3 API before first login). */
    partnerDir: 'partner01',
  },

  /**
   * Optional AMI overrides for the three hosts. When unset, the latest Windows Server 2022
   * and Amazon Linux 2023 (arm64) images are looked up ONCE and cached in cdk.context.json,
   * so a new AWS image release never replaces the hosts on a later deploy. Keep
   * cdk.context.json, or set explicit IDs here to change images deliberately.
   */
  amis: {
    windows: undefined as string | undefined,
    linux: undefined as string | undefined,
  },

  /** Audit / operations. */
  logging: {
    retentionDays: 365,
    /** Alarm when this many SFTP authentication failures happen within 5 minutes. */
    authFailureThreshold: 5,
  },

  /** Self-test (see demo stack). Files go to <partnerDir>/<selfTestDir>/ and are removed. */
  demo: {
    fileName: 'payment_batch_001.txt',
    selfTestDir: '_selftest',
    /** File at the volume root, OUTSIDE the SFTP folder; SFTP users must not reach it. */
    canaryFile: '_canary_outside_sftp_root.txt',
  },
};

/** SSM parameters carrying host instance IDs (instead of cross-stack exports). */
export const hostParam = (host: 'admin' | 'reader' | 'sftp-client') => `/${config.prefix}/hosts/${host}`;

/** SSM parameter holding the pinned SHA-256 of the SVM management certificate. */
export const svmCertPinParam = `/${config.prefix}/ontap/svm-mgmt-cert-sha256`;

/** Every AD user the demo creates (passwords generated into Secrets Manager). */
export const adUsers: string[] = [
  config.directory.fileSystemUser,
  config.directory.svmJoinUser,
  config.directory.fsxAdminUser,
  config.directory.readerUser,
  config.directory.noGroupUser,
  ...config.sftpGroups.map((g) => g.user),
];

/** Secrets Manager name of an AD user's password secret. */
export const userSecretName = (user: string) => `${config.prefix}/ad-user-${user}`;
