# Read the SFTP-uploaded self-test file over SMB as AD user reader01 (SMB reader, via SSM).
# $V (decoded JSON) is prepended by the test function. The password comes from Secrets
# Manager and is passed in-process to New-SmbMapping (never on a command line).
$ErrorActionPreference = 'Stop'
$unc = "\\$($V.SMB_IP)\$($V.SHARE)"
Get-SmbMapping -ErrorAction SilentlyContinue | Where-Object { $_.RemotePath -eq $unc } | Remove-SmbMapping -Force
$pw = ((Get-SECSecretValue -SecretId "$($V.PREFIX)/ad-user-$($V.READER)" -Region $V.REGION).SecretString | ConvertFrom-Json).password
New-SmbMapping -RemotePath $unc -UserName "$($V.NETBIOS)\$($V.READER)" -Password $pw -Persistent $false | Out-Null
$pw = $null
Write-Output "SMB_MAPPED=$unc as $($V.NETBIOS)\$($V.READER)"
try {
  $dir  = Join-Path $unc (Join-Path $V.DIR $V.SELFTEST_DIR)
  $path = Join-Path $dir $V.FILE
  $found = $false
  for ($i = 0; $i -lt 12 -and -not $found; $i++) { if (Test-Path $path) { $found = $true } else { Start-Sleep 5 } }
  if (-not $found) { throw "file not visible over SMB: $path" }
  Get-ChildItem $dir | Format-Table Name, Length, LastWriteTimeUtc -AutoSize | Out-String | Write-Output
  $content = Get-Content -Raw $path
  Write-Output "SMB_CONTENT_BEGIN"; Write-Output $content.TrimEnd(); Write-Output "SMB_CONTENT_END"
  if ($content -notmatch [regex]::Escape($V.NONCE)) { throw "nonce not found in file read over SMB" }
  Write-Output "SMB_SHA256=$((Get-FileHash -Algorithm SHA256 $path).Hash)"
  Write-Output "SMB_OWNER=$((Get-Acl $path).Owner)"
  # Least privilege check: the reader has read-only rights.
  try {
    Set-Content -Path (Join-Path $dir 'reader-write-test.txt') -Value 'x'
    Remove-Item -Path (Join-Path $dir 'reader-write-test.txt') -ErrorAction SilentlyContinue
    Write-Output "READER_WRITE=ALLOWED"
  } catch { Write-Output "READER_WRITE=DENIED" }
} finally {
  Remove-SmbMapping -RemotePath $unc -Force -UpdateProfile -ErrorAction SilentlyContinue
}
