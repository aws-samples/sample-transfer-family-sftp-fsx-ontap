# Share bootstrap (runs on the admin host via SSM).
# Creates the SMB share on the volume through the SVM's own ONTAP REST endpoint as the
# SVM-scoped vsadmin account (not the cluster-wide fsxadmin), then sets the share's NTFS
# DACL as svc-fsxadm, a member of the FSx delegated admins group. The directory Admin
# account is not used here. Passwords come from Secrets Manager and are never printed or
# passed on a command line (the share is mapped in-process with New-SmbMapping).
#
# TLS: the SVM management endpoint presents a self-signed certificate. Instead of skipping
# validation, the certificate is pinned: its SHA-256 is recorded in an SSM parameter on the
# first run (trust on first use, while the file system is brand new) and every later
# connection must present exactly that certificate. Credentials are only sent over a
# connection that passed the pin check. If ONTAP renews the certificate, the bootstrap
# fails closed; delete the parameter to re-trust.
$ErrorActionPreference = 'Stop'
# $V (decoded JSON) is prepended by the provider; values never pass through text substitution.
# MODE=apply creates/converges the share and its DACL; MODE=delete removes the share and
# the certificate pin (the volume and its data are untouched).
$region   = $V.REGION
$prefix   = $V.PREFIX
$netbios  = $V.NETBIOS
$mgmtIp   = $V.SVM_MGMT_IP
$smbIp    = $V.SMB_IP
$svmName  = $V.SVM_NAME
$share    = $V.SHARE
$junction = $V.JUNCTION
$fsxAdm   = $V.FSX_ADMIN_USER
$sidFs     = $V.SID_FS
$sidReader = $V.SID_READER
$pinParam  = $V.CERT_PIN_PARAM

function Get-Secret([string]$id) {
  (Get-SECSecretValue -SecretId $id -Region $region).SecretString | ConvertFrom-Json
}

Write-Output "== 4. SMB share '$share' on $svmName via the SVM's ONTAP REST endpoint ($mgmtIp)"
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
# Compiled callbacks (a PowerShell scriptblock callback can fail on worker threads).
Add-Type -TypeDefinition @"
using System; using System.Net; using System.Net.Security; using System.Net.Sockets;
using System.Security.Authentication; using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
public static class OntapTls {
  public static string Host;
  public static string Pin;
  public static string Sha256Hex(X509Certificate c) {
    using (var h = SHA256.Create()) { return BitConverter.ToString(h.ComputeHash(c.GetRawCertData())).Replace("-", ""); }
  }
  // Requests to the SVM endpoint: accept exactly the pinned certificate, nothing else.
  // Any other host: normal validation.
  public static bool Check(object s, X509Certificate c, X509Chain ch, SslPolicyErrors e) {
    var r = s as HttpWebRequest;
    if (r == null || r.RequestUri.Host != Host) { return e == SslPolicyErrors.None; }
    return Pin != null && c != null && string.Equals(Sha256Hex(c), Pin, StringComparison.OrdinalIgnoreCase);
  }
  // Reads the presented certificate WITHOUT sending anything else (no credentials).
  public static string Probe(string host, int port) {
    using (var t = new TcpClient(host, port))
    using (var ssl = new SslStream(t.GetStream(), false, (a, b, c2, d) => true)) {
      ssl.AuthenticateAsClient(host, null, SslProtocols.Tls12, false);
      return Sha256Hex(ssl.RemoteCertificate);
    }
  }
}
"@
$seen = $null
for ($i = 1; $i -le 6 -and -not $seen; $i++) {
  try { $seen = [OntapTls]::Probe($mgmtIp, 443) }
  catch { Write-Host "certificate probe attempt $i failed: $($_.Exception.Message)"; if ($i -eq 6) { throw }; Start-Sleep -Seconds (10 * $i) }
}
$pinned = $null
try { $pinned = (Get-SSMParameter -Name $pinParam -Region $region).Value } catch { $pinned = $null }
if (-not $pinned) {
  if ($V.MODE -eq 'delete') { Write-Output "no certificate pin and mode=delete: nothing to clean up on ONTAP"; Write-Output "BOOTSTRAP_OK"; return }
  Write-SSMParameter -Name $pinParam -Value $seen -Type String -Region $region `
    -Description 'SHA-256 of the FSx ONTAP SVM management certificate (trust on first use)' | Out-Null
  $pinned = $seen
  Write-Output "certificate pinned on first use: $seen"
} elseif ($pinned -ne $seen) {
  throw "SVM management certificate does not match the pin in $pinParam (pinned $pinned, presented $seen). Refusing to send credentials. If ONTAP renewed its certificate, verify it and delete the parameter to re-trust."
} else { Write-Output "certificate matches pin $pinned" }
[OntapTls]::Host = $mgmtIp
[OntapTls]::Pin = $pinned
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = [System.Net.Security.RemoteCertificateValidationCallback][OntapTls].GetMethod('Check').CreateDelegate([System.Net.Security.RemoteCertificateValidationCallback])

$va = Get-Secret "$prefix/vsadmin"
$basic = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("vsadmin:$($va.password)"))
$va = $null
$hdr = @{ Authorization = "Basic $basic"; Accept = 'application/json' }
# Retries: the management LIF intermittently resets the first TLS handshake
# ("underlying connection was closed ... on a send"). Fresh connections each attempt.
[System.Net.ServicePointManager]::Expect100Continue = $false
function Invoke-Ontap([string]$method, [string]$path, [string]$body = $null) {
  for ($i = 1; $i -le 6; $i++) {
    try {
      $sp = [System.Net.ServicePointManager]::FindServicePoint([Uri]"https://$mgmtIp/")
      $sp.CloseConnectionGroup('') | Out-Null
      $req = @{ Method = $method; Headers = $hdr; Uri = "https://$mgmtIp$path"; DisableKeepAlive = $true; TimeoutSec = 60 }
      if ($body) { $req.ContentType = 'application/json'; $req.Body = $body }
      return Invoke-RestMethod @req
    } catch {
      $m = @(); $ex = $_.Exception; while ($ex) { $m += $ex.Message; $ex = $ex.InnerException }
      Write-Host "ONTAP $method $path attempt $i failed: $($m -join ' <- ')"
      if ($i -eq 6) { throw }
      Start-Sleep -Seconds (10 * $i)
    }
  }
}
$existingShares = Invoke-Ontap 'Get' "/api/protocols/cifs/shares?svm.name=$svmName&name=$share&fields=svm.uuid"
if ($V.MODE -eq 'delete') {
  if ($existingShares.num_records -gt 0) {
    $svmUuid = $existingShares.records[0].svm.uuid
    Invoke-Ontap 'Delete' "/api/protocols/cifs/shares/$svmUuid/$share" | Out-Null
    Write-Output "share $share deleted"
  } else { Write-Output "share $share not present" }
  [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
  Remove-SSMParameter -Name $pinParam -Region $region -Force
  Write-Output "certificate pin removed"
  Write-Output "BOOTSTRAP_OK"
  return
}
if ($existingShares.num_records -eq 0) {
  $body = @{ svm = @{ name = $svmName }; name = $share; path = $junction } | ConvertTo-Json
  Invoke-Ontap 'Post' '/api/protocols/cifs/shares' $body | Out-Null
  Write-Output "share created"
} else { Write-Output "share exists" }
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
$hdr = $null; $basic = $null

Write-Output "== 5. NTFS DACL on \\$smbIp\$share (as $netbios\$fsxAdm)"
$unc = "\\$smbIp\$share"
Get-SmbMapping -ErrorAction SilentlyContinue | Where-Object { $_.RemotePath -eq $unc } | Remove-SmbMapping -Force
$admPw = (Get-Secret "$prefix/ad-user-$fsxAdm").password
New-SmbMapping -RemotePath $unc -UserName "$netbios\$fsxAdm" -Password $admPw -Persistent $false | Out-Null
$admPw = $null
try {
  # Least privilege: the access-point identity can modify, the reader can only read.
  # Inheritance off and a fresh DACL (no Everyone); Administrators keep full control.
  # Built from SecurityIdentifier objects: icacls would try to resolve domain SIDs on this
  # non-domain-joined host and fail with 1332. Only the DACL section is written.
  $inh  = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
  $prop = [System.Security.AccessControl.PropagationFlags]::None
  $allow = [System.Security.AccessControl.AccessControlType]::Allow
  $R = [System.Security.AccessControl.FileSystemRights]
  $acl = New-Object System.Security.AccessControl.DirectorySecurity
  $acl.SetAccessRuleProtection($true, $false)
  foreach ($pair in @(@('S-1-5-32-544', $R::FullControl), @($sidFs, $R::Modify), @($sidReader, $R::ReadAndExecute))) {
    $sidObj = New-Object System.Security.Principal.SecurityIdentifier($pair[0])
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($sidObj, $pair[1], $inh, $prop, $allow)))
  }
  (New-Object System.IO.DirectoryInfo($unc)).SetAccessControl($acl)
  # Canary at the volume root, outside the SFTP folder: the self-test proves SFTP users
  # cannot reach it, although svc-fsx (the access point identity) could read it.
  Set-Content -Path (Join-Path $unc $V.CANARY) -Value 'canary: SFTP users must never be able to read this file'
  $sddl = (New-Object System.IO.DirectoryInfo($unc)).GetAccessControl('Access').GetSecurityDescriptorSddlForm('Access')
  Write-Output "SHARE_DACL=$sddl"
  if ($sddl -notmatch [regex]::Escape($sidFs) -or $sddl -notmatch [regex]::Escape($sidReader)) { throw "DACL verification failed" }
  if ($sddl -match ';;;WD\)') { throw "Everyone still present in DACL" }
} finally {
  Remove-SmbMapping -RemotePath $unc -Force -UpdateProfile -ErrorAction SilentlyContinue
}

Write-Output "BOOTSTRAP_OK"
