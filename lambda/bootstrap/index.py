"""Custom-resource provider that runs a PowerShell bootstrap script on the admin host via SSM.

Resource properties:
  HostParam     SSM parameter holding the admin host's instance ID
  Script        file name in this directory (identity.ps1 / share.ps1)
  ScriptSha256  hash of the script; changing the script re-runs the bootstrap
  Vars          {NAME: value} handed to the script as $V.NAME
  FileSystemId, SvmId (optional) -> also resolves $V.SVM_MGMT_IP / $V.SMB_IP

Lifecycle (every script implements both modes):
  Create/Update -> $V.MODE = 'apply'. On Update, $V.PREVIOUS holds the previous Vars, so
                   the script can remove objects that are no longer desired.
  Delete        -> $V.MODE = 'delete': the script removes what it created. Delete is best
                   effort: a failure is logged but never blocks stack deletion.

Least standing privilege: the admin host is kept STOPPED. on_event starts it, is_complete
stops it again once the script has finished (success or failure).

Values reach the script as base64-encoded JSON, never by text substitution, so no value
can change the script's meaning. Scripts never print secret values.
on success every "OUT_<KEY>=<value>" line of stdout becomes attribute <KEY>.
"""
import base64
import json
import os
import re
import time

import boto3

ssm = boto3.client("ssm")
ec2 = boto3.client("ec2")
fsx = boto3.client("fsx")

HERE = os.path.dirname(__file__)
OUT_LINE = re.compile(r"^OUT_([A-Z0-9_]+)=(.*)$")
KEY = re.compile(r"^[A-Z][A-Z0-9_]*$")


def _instance_id(p):
    return ssm.get_parameter(Name=p["HostParam"])["Parameter"]["Value"]


def _state(instance_id):
    r = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]
    return r["State"]["Name"]


def _start_and_wait_online(instance_id, deadline):
    while time.time() < deadline:
        st = _state(instance_id)
        if st == "stopped":
            print(f"starting {instance_id}")
            ec2.start_instances(InstanceIds=[instance_id])
        elif st == "running":
            info = ssm.describe_instance_information(
                Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]
            )["InstanceInformationList"]
            if info and info[0].get("PingStatus") == "Online":
                return True
        time.sleep(15)
    return False


def _stop(instance_id):
    try:
        if _state(instance_id) in ("running", "pending"):
            ec2.stop_instances(InstanceIds=[instance_id])
            print(f"stopped {instance_id}")
    except Exception as e:  # never fail a deployment because a stop did not go through
        print(f"stop of {instance_id} failed: {e}")


def _svm_ips(svm_id):
    """SVM management and SMB endpoint IPs (the SVM's own endpoint, not the cluster's)."""
    svm = fsx.describe_storage_virtual_machines(StorageVirtualMachineIds=[svm_id])[
        "StorageVirtualMachines"
    ][0]
    ep = svm["Endpoints"]
    return ep["Management"]["IpAddresses"][0], ep["Smb"]["IpAddresses"][0]


def _render(name, values):
    for k in values:
        if not KEY.match(k):
            raise RuntimeError(f"invalid variable name {k!r}")
    payload = base64.b64encode(json.dumps(values).encode()).decode()
    with open(os.path.join(HERE, os.path.basename(name)), encoding="utf-8") as f:
        body = f.read()
    prelude = (
        "$V = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("
        f"'{payload}')) | ConvertFrom-Json\n"
    )
    return prelude + body


def on_event(event, _context):
    request = event["RequestType"]
    physical_id = event.get("PhysicalResourceId") or f"bootstrap-{event['LogicalResourceId']}"
    p = event["ResourceProperties"]
    try:
        instance_id = _instance_id(p)
    except Exception as e:
        if request == "Delete":
            print(f"delete: host parameter unavailable ({e}); nothing to clean up")
            return {"PhysicalResourceId": physical_id, "Data": {"Skip": "1"}}
        raise

    deadline = time.time() + 12 * 60
    if not _start_and_wait_online(instance_id, deadline):
        if request == "Delete":
            print(f"delete: {instance_id} not reachable; skipping cleanup")
            return {"PhysicalResourceId": physical_id, "Data": {"Skip": "1"}}
        raise RuntimeError(f"{instance_id} did not come online in SSM in time")

    values = {k: str(v) for k, v in p.get("Vars", {}).items()}
    values["REGION"] = os.environ["AWS_REGION"]
    values["MODE"] = "delete" if request == "Delete" else "apply"
    if request == "Update":
        values["PREVIOUS"] = json.dumps(event.get("OldResourceProperties", {}).get("Vars", {}))
    data = {}
    if p.get("FileSystemId"):
        try:
            mgmt_ip, smb_ip = _svm_ips(p["SvmId"])
            values.update({"SVM_MGMT_IP": mgmt_ip, "SMB_IP": smb_ip})
            data.update({"SvmMgmtIp": mgmt_ip, "SmbIp": smb_ip})
        except Exception:
            if request != "Delete":
                raise

    cmd = ssm.send_command(
        InstanceIds=[instance_id],
        DocumentName="AWS-RunPowerShellScript",
        Parameters={"commands": [_render(p["Script"], values)], "executionTimeout": ["1800"]},
        Comment=f"bootstrap {p['Script']} ({values['MODE']})",
    )["Command"]
    return {"PhysicalResourceId": physical_id,
            "Data": {**data, "CommandId": cmd["CommandId"], "InstanceId": instance_id}}


def is_complete(event, _context):
    data = event.get("Data", {})
    if data.get("Skip"):
        return {"IsComplete": True}
    request = event["RequestType"]
    instance_id = data["InstanceId"]
    try:
        inv = ssm.get_command_invocation(CommandId=data["CommandId"], InstanceId=instance_id)
    except ssm.exceptions.InvocationDoesNotExist:
        return {"IsComplete": False}

    status = inv["Status"]
    if status in ("Pending", "InProgress", "Delayed"):
        return {"IsComplete": False}
    _stop(instance_id)
    out = inv.get("StandardOutputContent", "")
    err = inv.get("StandardErrorContent", "")
    print(out)
    if status == "Success" and "BOOTSTRAP_OK" in out:
        outputs = {}
        for line in out.splitlines():
            m = OUT_LINE.match(line.strip())
            if m:
                outputs[m.group(1)] = m.group(2).strip()
        return {"IsComplete": True, "Data": {**data, **outputs}}
    if request == "Delete":
        print(f"delete cleanup {status} (not blocking stack deletion): {err[-1500:]}")
        return {"IsComplete": True}
    raise RuntimeError(f"bootstrap {status}: stdout tail={out[-1500:]} stderr tail={err[-1500:]}")
