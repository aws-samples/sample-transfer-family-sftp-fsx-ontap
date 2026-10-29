#!/usr/bin/env python3
"""Tear down the sftp-ontap-demo stacks with Python only (no Node.js / CDK CLI needed).

Default is a DRY RUN: it lists what would be deleted and changes nothing. The target is
the account of your current AWS credentials and --region (default: your configured region).

    pip install boto3
    python3 scripts/teardown.py --region <region>                       # dry run
    python3 scripts/teardown.py --region <region> --yes                 # delete the stacks
    python3 scripts/teardown.py --region <region> --yes --purge-retained
                                                    # ... and free the secret names so a
                                                    # clean redeploy works (see below)

Stacks are deleted one at a time in reverse dependency order:
    demo -> sftp -> fsx -> identity -> client -> directory -> network
The order matters: the share and AD cleanup run on the admin host (client stack), and the
SVM unjoins with svc-svmjoin (identity stack), so those stacks must still exist.

WARNING: deleting the fsx stack permanently deletes the ONTAP file system and every file on
the volume; deleting the directory stack deletes the Managed AD. Not reversible.

--purge-retained additionally removes what CloudFormation deliberately keeps or reserves:
  - the Secrets Manager secrets sftp-ontap-demo/* (CloudFormation only schedules them for
    deletion, which reserves their names for up to 30 days and blocks a redeploy).
The Transfer log group, the CloudTrail audit bucket (and its access-log bucket) and the trail
log group are retained on
purpose (audit history) and never deleted by this script; they have generated names and do
not block a redeploy. They are listed at the end.
FSx takes a final backup of the volume when the file system is deleted; it is listed too.
"""
import argparse
import sys
import time

import boto3
from botocore.exceptions import ClientError, WaiterError

PREFIX = "sftp-ontap-demo"
VOLUME_NAME = "vol1"  # config.fsx.volumeName; matches untagged backups from older revisions
ORDER = ["demo", "sftp", "fsx", "identity", "client", "directory", "network"]


def stack_status(cfn, name):
    try:
        return cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
    except ClientError as e:
        if "does not exist" in str(e):
            return None
        raise


def failure_reasons(cfn, name):
    events = cfn.describe_stack_events(StackName=name)["StackEvents"][:50]
    return [f"  {e['LogicalResourceId']}: {e.get('ResourceStatusReason', '')}"
            for e in events if e["ResourceStatus"] == "DELETE_FAILED"]


def delete_stack(cfn, name):
    print(f"deleting {name} ...", flush=True)
    start = time.time()
    cfn.delete_stack(StackName=name)
    try:
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=name, WaiterConfig={"Delay": 30, "MaxAttempts": 120})
    except WaiterError:
        print(f"FAILED to delete {name}. Reasons:")
        print("\n".join(failure_reasons(cfn, name)) or "  (no DELETE_FAILED events found)")
        print("Fix the cause and run the script again; it resumes with the remaining stacks.")
        sys.exit(1)
    print(f"deleted {name} in {int(time.time() - start)}s", flush=True)


def purge_retained(session, apply):
    sm = session.client("secretsmanager")
    logs = session.client("logs")
    secrets = []
    for page in sm.get_paginator("list_secrets").paginate(
            IncludePlannedDeletion=True, Filters=[{"Key": "name", "Values": [f"{PREFIX}/"]}]):
        secrets += [s["Name"] for s in page["SecretList"] if s["Name"].startswith(f"{PREFIX}/")]
    for name in secrets:
        print(f"{'force-deleting' if apply else 'would force-delete'} secret {name}")
        if apply:
            try:
                sm.restore_secret(SecretId=name)  # only needed if already scheduled
            except ClientError:
                pass
            sm.delete_secret(SecretId=name, ForceDeleteWithoutRecovery=True)


def list_audit_leftovers(session):
    s3 = session.client("s3")
    buckets = [b["Name"] for b in s3.list_buckets()["Buckets"] if b["Name"].startswith((f"{PREFIX}-sftp-audittrail", f"{PREFIX}-sftp-auditaccesslog"))]
    logs = session.client("logs")
    groups = [g["logGroupName"] for g in logs.describe_log_groups(
        logGroupNamePrefix=f"{PREFIX}-sftp-AccessPointDataTrail")["logGroups"]]
    groups += [g["logGroupName"] for g in logs.describe_log_groups(
        logGroupNamePrefix=f"{PREFIX}-sftp-TransferStructuredLogs")["logGroups"]]
    if buckets or groups:
        print("\nKept on purpose (audit history, does not block a redeploy):")
        for x in buckets + groups:
            print(f"  {x}")
    backups = [b["BackupId"] for b in session.client("fsx").describe_backups(
        Filters=[{"Name": "backup-type", "Values": ["USER_INITIATED", "AUTOMATIC"]}])["Backups"]
        if any(t["Key"] == "Name" and t["Value"].startswith(PREFIX) for t in b.get("Tags", []))
        or (not b.get("Tags") and b.get("Volume", {}).get("Name") == VOLUME_NAME)]
    if backups:
        print("\nFSx backups of the demo volume (cost money; delete with 'aws fsx delete-backup --backup-id <id>'):")
        for x in backups:
            print(f"  {x}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--yes", action="store_true", help="actually delete (default: dry run)")
    ap.add_argument("--purge-retained", action="store_true",
                    help="also force-delete the demo secrets so their names are free for a redeploy")
    ap.add_argument("--profile", help="AWS CLI profile to use")
    ap.add_argument("--region", help="region the stacks are deployed in (default: configured region)")
    ap.add_argument("--account", help="refuse to run unless the credentials are for this account")
    args = ap.parse_args()

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    if not session.region_name:
        sys.exit("no region: pass --region or configure a default region")
    account = session.client("sts").get_caller_identity()["Account"]
    if args.account and account != args.account:
        sys.exit(f"refusing: credentials are for account {account}, expected {args.account}")
    cfn = session.client("cloudformation")

    present = [(f"{PREFIX}-{s}", st) for s in ORDER
               if (st := stack_status(cfn, f"{PREFIX}-{s}")) not in (None, "DELETE_COMPLETE")]
    print(f"account {account}, region {session.region_name}, mode {'DELETE' if args.yes else 'DRY RUN'}")
    for name, st in present:
        print(f"  {name:28} {st}")
    if not present:
        print("  (no demo stacks found)")

    if args.yes:
        for name, _ in present:
            delete_stack(cfn, name)
    if args.purge_retained:
        purge_retained(session, args.yes)
    list_audit_leftovers(session)
    if not args.yes:
        print("\nDry run only. Re-run with --yes (and --purge-retained for a clean redeploy).")


if __name__ == "__main__":
    main()
