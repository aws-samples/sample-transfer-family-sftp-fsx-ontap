import { Stack, StackProps, CfnOutput, Fn } from 'aws-cdk-lib';
import { Construct } from 'constructs';
import { config, adUsers, hostParam } from './config';
import { SsmBootstrap } from './ssm-bootstrap';

interface IdentityStackProps extends StackProps {
  dnsIps: string[];
}

/** Attribute key a script prints for a SID, e.g. svc-fsx -> SID_SVC_FSX. */
export const sidKey = (name: string) => `SID_${name.toUpperCase().replace(/-/g, '_')}`;

/**
 * AD identities, created on the admin host (the only place the directory Admin
 * account is used):
 *  - demo users and the two SFTP groups (one member each),
 *  - svc-svmjoin with delegated rights on the Computers OU (the SVM's join account),
 *  - svc-fsxadm in the FSx delegated admins group (sets the share's NTFS ACLs).
 * Deployed before the FSx stack, so the SVM can use svc-svmjoin.
 */
export class IdentityStack extends Stack {
  public readonly groupSids: Record<string, string>;
  public readonly fsUserSid: string;
  public readonly readerSid: string;

  constructor(scope: Construct, id: string, props: IdentityStackProps) {
    super(scope, id, props);
    const d = config.directory;

    const bootstrap = new SsmBootstrap(this, 'AdIdentities', {
      hostParam: hostParam('admin'),
      hostNameTag: `${config.prefix}-admin-host`,
      script: 'identity.ps1',
      vars: {
        PREFIX: config.prefix,
        DOMAIN: d.domainName,
        NETBIOS: d.netbios,
        DC_IP: Fn.select(0, props.dnsIps),
        USERS: adUsers.join(','),
        GROUPS: config.sftpGroups.map((g) => `${g.name}:${g.user}`).join(';'),
        SVM_JOIN_USER: d.svmJoinUser,
        FSX_ADMIN_USER: d.fsxAdminUser,
        FSX_ADMINS_GROUP: d.fsxAdminsGroup,
        SID_USERS: [d.fileSystemUser, d.readerUser].join(','),
      },
    });

    this.groupSids = Object.fromEntries(config.sftpGroups.map((g) => [g.name, bootstrap.getAtt(sidKey(g.name))]));
    this.fsUserSid = bootstrap.getAtt(sidKey(d.fileSystemUser));
    this.readerSid = bootstrap.getAtt(sidKey(d.readerUser));

    for (const g of config.sftpGroups) {
      new CfnOutput(this, `${g.name}Sid`, { value: this.groupSids[g.name] });
    }
  }
}
