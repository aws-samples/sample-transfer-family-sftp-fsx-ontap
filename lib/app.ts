import { App, Environment } from 'aws-cdk-lib';
import { config } from './config';
import { NetworkStack } from './network-stack';
import { DirectoryStack } from './directory-stack';
import { ClientStack } from './client-stack';
import { IdentityStack } from './identity-stack';
import { FsxStack } from './fsx-stack';
import { SftpStack } from './sftp-stack';
import { DemoStack } from './demo-stack';

/**
 * Builds the seven stacks. Order: network -> directory -> client (hosts) -> identity (AD
 * users, groups, delegated service accounts) -> fsx (SVM joins as svc-svmjoin) -> sftp
 * -> demo (self-test).
 */
export function buildApp(app: App, env: Required<Environment>) {
  const p = config.prefix;
  // Server access logs are granted by bucket policy, not the legacy LogDeliveryWrite ACL, so
  // the log bucket can keep ACLs disabled (BucketOwnerEnforced). Set here, not only in
  // cdk.json, so unit tests synthesize the same templates.
  app.node.setContext('@aws-cdk/aws-s3:serverAccessLogsUseBucketPolicy', true);

  const network = new NetworkStack(app, `${p}-network`, { env });

  const directory = new DirectoryStack(app, `${p}-directory`, { env, vpc: network.vpc });

  const client = new ClientStack(app, `${p}-client`, {
    env,
    vpc: network.vpc,
    adminSg: network.adminSg,
    clientSg: network.clientSg,
    sftpClientSg: network.sftpClientSg,
    adminSecret: directory.adminSecret,
    userSecrets: directory.userSecrets,
  });

  const identity = new IdentityStack(app, `${p}-identity`, { env, dnsIps: directory.dnsIps });
  // Host IDs travel through SSM parameters, so this ordering is explicit.
  identity.addStackDependency(client);

  const fsx = new FsxStack(app, `${p}-fsx`, {
    env,
    vpc: network.vpc,
    fsxSg: network.fsxSg,
    domainName: config.directory.domainName,
    dnsIps: directory.dnsIps,
    svmJoinSecret: directory.userSecrets[config.directory.svmJoinUser],
  });
  // The SVM's join account must exist (and be delegated) before the SVM uses it.
  fsx.addStackDependency(identity);

  const sftp = new SftpStack(app, `${p}-sftp`, {
    env,
    vpc: network.vpc,
    transferSg: network.transferSg,
    directoryId: directory.directoryId,
    fileSystemId: fsx.fileSystem.ref,
    svmId: fsx.svm.ref,
    volumeId: fsx.volume.ref,
    groupSids: identity.groupSids,
    fsUserSid: identity.fsUserSid,
    readerSid: identity.readerSid,
  });

  // The self-test imports nothing (it discovers the environment at run time), so the
  // stacks it tests can replace resources without "export in use" failures.
  const demo = new DemoStack(app, `${p}-demo`, { env });
  demo.addStackDependency(sftp);

  return { network, directory, client, identity, fsx, sftp, demo };
}
