"""End-to-end self-test for the SFTP -> FSx ONTAP demo.

Two entry points:
  run_test  invoke directly at any time:  aws lambda invoke --function-name <SelfTestFunction> out.json
  on_event  CloudFormation custom resource. Runs the test only when the TEST CODE changes
            (its hash is a resource property), not on every deploy, so ordinary
            infrastructure deploys do not touch data or depend on a flaky test.

Checks (any failure raises; evidence is printed to this function's log group):
  1. SFTP endpoint is VPC-only with no public IP; host key pinned.
  2. Authentication: wrong password rejected; a valid AD user in no SFTP group rejected.
  3. partner01 (read-write) uploads <partner>/<selftest>/<file> with a fresh nonce.
  4. auditor01 (read-only) downloads it; its upload and delete are refused.
  5. Neither SFTP user can reach a canary file outside the SFTP folder.
  6. reader01 reads the same bytes over SMB and cannot write.
  7. SHA-256 identical for upload, auditor download and SMB read.
  8. This function's own role is denied at the access point (explicit deny in the
     resource policy) although its IAM policy allows the call.
  9. Cleanup: the self-test file and folder are removed via SFTP.
Everything environment-specific is discovered at RUN time (host IDs from SSM parameters,
the server by tag, the access point and SMB endpoint by name), so this stack imports
nothing from the others and they can replace resources freely. Values reach the host
scripts as base64 JSON, never by text substitution.
"""
import base64
import json
import os
import re
import time
import uuid

import boto3
from botocore.exceptions import ClientError

ssm = boto3.client("ssm")
transfer = boto3.client("transfer")
ec2 = boto3.client("ec2")
s3 = boto3.client("s3")
fsx = boto3.client("fsx")

HERE = os.path.dirname(__file__)
KEY = re.compile(r"^[A-Z][A-Z0-9_]*$")


def _cfg():
    return json.loads(os.environ["TEST_CONFIG"])


def _payload(values):
    for k in values:
        if not KEY.match(k):
            raise RuntimeError(f"invalid variable name {k!r}")
    return base64.b64encode(json.dumps({k: str(v) for k, v in values.items()}).encode()).decode()


def _bash(name, values):
    with open(os.path.join(HERE, name), encoding="utf-8") as f:
        body = f.read()
    # Single line; each value is shell-quoted with shlex, keys are validated identifiers.
    decode = "import json,sys,shlex;[print(k+'='+shlex.quote(v)) for k,v in json.load(sys.stdin).items()]"
    return (f"eval \"$(echo '{_payload(values)}' | base64 -d | python3 -c \"{decode}\")\"\n" + body)


def _powershell(name, values):
    with open(os.path.join(HERE, name), encoding="utf-8") as f:
        body = f.read()
    return ("$V = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("
            f"'{_payload(values)}')) | ConvertFrom-Json\n" + body)


def _run(instance_id, document, script, deadline):
    cmd_id = ssm.send_command(
        InstanceIds=[instance_id], DocumentName=document,
        Parameters={"commands": [script], "executionTimeout": ["600"]},
        Comment="sftp-ontap-demo self-test",
    )["Command"]["CommandId"]
    while time.time() < deadline:
        time.sleep(10)
        try:
            inv = ssm.get_command_invocation(CommandId=cmd_id, InstanceId=instance_id)
        except ssm.exceptions.InvocationDoesNotExist:
            continue
        if inv["Status"] in ("Pending", "InProgress", "Delayed"):
            continue
        out, err = inv.get("StandardOutputContent", ""), inv.get("StandardErrorContent", "")
        print(f"--- {instance_id} {document} status={inv['Status']}\n{out}\n--- stderr\n{err}")
        if inv["Status"] != "Success":
            raise RuntimeError(f"{instance_id} {inv['Status']}: {out[-1200:]} | {err[-800:]}")
        return out
    raise RuntimeError(f"{instance_id} command {cmd_id} timed out")


def _kv(out, key):
    for line in out.splitlines():
        if line.startswith(key + "="):
            return line.split("=", 1)[1].strip()
    raise RuntimeError(f"{key} not found in output")


def _host(name):
    return ssm.get_parameter(Name=f"/{_cfg()['Prefix']}/hosts/{name}")["Parameter"]["Value"]


def _discover(c):
    """Server (by Name tag), access-point alias and SMB IP (by name), resolved now."""
    server_id = None
    for page in transfer.get_paginator("list_servers").paginate():
        for srv in page["Servers"]:
            tags = transfer.list_tags_for_resource(Arn=srv["Arn"]).get("Tags", [])
            if {"Key": "Name", "Value": c["ServerTag"]} in tags:
                server_id = srv["ServerId"]
    if not server_id:
        raise RuntimeError(f"no Transfer server tagged Name={c['ServerTag']}")
    ap = fsx.describe_s3_access_point_attachments(Names=[c["AccessPointName"]])["S3AccessPointAttachments"][0]
    fs_id = next(f["FileSystemId"] for page in fsx.get_paginator("describe_file_systems").paginate()
                 for f in page["FileSystems"]
                 if {"Key": "Name", "Value": c["FileSystemTag"]} in f.get("Tags", []))
    svm = fsx.describe_storage_virtual_machines(
        Filters=[{"Name": "file-system-id", "Values": [fs_id]}])["StorageVirtualMachines"]
    smb_ip = next(v for v in svm if v["Name"] == c["SvmName"])["Endpoints"]["Smb"]["IpAddresses"][0]
    return server_id, ap["S3AccessPoint"]["Alias"], smb_ip


def _access_point_denies_me(alias, keys):
    """Our role's IAM policy allows these reads; the access-point policy must deny them."""
    results = {}
    for key in keys:
        try:
            s3.get_object(Bucket=alias, Key=key)
            results[key] = "ALLOWED"
        except ClientError as e:
            msg = e.response.get("Error", {}).get("Message", "")
            code = e.response.get("Error", {}).get("Code", "")
            results[key] = "EXPLICIT_DENY" if code == "AccessDenied" and "resource-based policy" in msg else f"{code}: {msg}"
    print("ACCESS_POINT_SELF_CHECK " + json.dumps(results))
    return results


def run_test(_event=None, _context=None):
    c = _cfg()
    deadline = time.time() + 13 * 60
    server_id, alias, smb_ip = _discover(c)
    server = transfer.describe_server(ServerId=server_id)["Server"]
    if server["EndpointType"] != "VPC":
        raise RuntimeError(f"server endpoint type is {server['EndpointType']}, expected VPC")
    vpce = ec2.describe_vpc_endpoints(VpcEndpointIds=[server["EndpointDetails"]["VpcEndpointId"]])["VpcEndpoints"][0]
    eni = ec2.describe_network_interfaces(NetworkInterfaceIds=vpce["NetworkInterfaceIds"][:1])["NetworkInterfaces"][0]
    host, public = eni["PrivateIpAddress"], eni.get("Association", {}).get("PublicIp")
    print(json.dumps({"server": server_id, "accessPointAlias": alias, "smbIp": smb_ip, "endpointType": server["EndpointType"],
                      "identityProvider": server["IdentityProviderType"],
                      "endpointPrivateIp": host, "endpointPublicIp": public}))
    if public:
        raise RuntimeError("SFTP endpoint ENI has a public IP; expected private only")

    nonce = uuid.uuid4().hex
    linux, reader = _host("sftp-client"), _host("reader")
    common = {"REGION": os.environ["AWS_REGION"], "PREFIX": c["Prefix"], "FILE": c["FileName"],
              "NONCE": nonce, "SELFTEST_DIR": c["SelfTestDir"]}
    sftp_vars = {**common, "HOST": host, "FP": server["HostKeyFingerprint"], "RW_USER": c["RwUser"],
                 "RO_USER": c["RoUser"], "NOGROUP_USER": c["NoGroupUser"], "CANARY": c["Canary"]}
    try:
        up = _run(linux, "AWS-RunShellScript", _bash("sftp_checks.sh", {**sftp_vars, "PHASE": "checks"}), deadline)
        rd = _run(reader, "AWS-RunPowerShellScript", _powershell("read.ps1", {
            **common, "SMB_IP": smb_ip, "SHARE": c["Share"], "DIR": c["PartnerDir"],
            "NETBIOS": c["Netbios"], "READER": c["Reader"]}), deadline)
    finally:
        try:
            _run(linux, "AWS-RunShellScript", _bash("sftp_checks.sh", {**sftp_vars, "PHASE": "cleanup"}), deadline)
        except Exception as e:  # report, but do not mask the real test result
            print(f"cleanup failed: {e}")

    sha = {"upload": _kv(up, "UPLOAD_SHA256"), "auditor": _kv(up, "RO_DOWNLOAD_SHA256"),
           "smb": _kv(rd, "SMB_SHA256").lower()}
    if len(set(sha.values())) != 1:
        raise RuntimeError(f"hash mismatch: {sha}")
    denials = {k: _kv(up, k) for k in ("WRONG_PASSWORD", "NO_GROUP_LOGIN", "RO_UPLOAD", "RO_DELETE")}
    denials["READER_WRITE"] = _kv(rd, "READER_WRITE")
    escapes = [l for l in up.splitlines() if l.startswith("ESCAPE_") and not l.endswith(("=DENIED", "=ABSENT"))]
    ap = _access_point_denies_me(alias,
                                 [c["Canary"], f"{c['PartnerDir']}/{c['FileName']}"])
    failed = {k: v for k, v in denials.items() if v != "DENIED"}
    if failed or escapes or any(v != "EXPLICIT_DENY" for v in ap.values()):
        raise RuntimeError(f"security checks failed: denials={failed} escapes={escapes} accessPoint={ap}")

    result = {"Result": "PASS", "Nonce": nonce, "Sha256": sha["upload"], "SmbOwner": _kv(rd, "SMB_OWNER"),
              "EndpointPrivateIp": host, "Denials": ",".join(f"{k}={v}" for k, v in denials.items()),
              "Confinement": "OK", "AccessPoint": "EXPLICIT_DENY"}
    print("E2E_RESULT " + json.dumps(result))
    return result


def on_event(event, context):
    if event["RequestType"] == "Delete":
        return {"PhysicalResourceId": event.get("PhysicalResourceId", "e2e-selftest")}
    return {"PhysicalResourceId": "e2e-selftest", "Data": run_test(event, context)}
