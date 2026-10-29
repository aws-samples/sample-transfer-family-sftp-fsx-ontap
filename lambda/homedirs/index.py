"""Creates SFTP home directories through the S3 access point (zero-byte "dir/" objects).

A directory created over SMB/NFS has no placeholder object, so the S3 view drops it as
soon as it is empty and SFTP logins into it fail. Creating it via the S3 API first keeps
it visible. Delete is a no-op: data on the ONTAP volume is never removed by this stack.
"""
import boto3

s3 = boto3.client("s3")


def on_event(event, _context):
    p = event["ResourceProperties"]
    physical_id = f"homedirs-{p['Bucket']}"
    if event["RequestType"] == "Delete":
        return {"PhysicalResourceId": physical_id}
    for d in p["Dirs"]:
        key = d.strip("/") + "/"
        s3.put_object(Bucket=p["Bucket"], Key=key, Body=b"")
        print(f"created {key}")
    return {"PhysicalResourceId": physical_id}
