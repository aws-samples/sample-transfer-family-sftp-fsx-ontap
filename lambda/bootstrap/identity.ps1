# Identity bootstrap for the SFTP -> FSx ONTAP demo (runs on the admin host via SSM).
# $V (decoded JSON) is prepended by the provider; values never pass through text substitution.
#
# MODE=apply  (Create/Update) converges AD to the desired state:
#   - demo users exist and have their Secrets Manager passwords,
#   - one AD group per SFTP permission level, each with exactly one member,
#   - svc-svmjoin holds delegated join rights on the Computers OU (used by the SVM),
#   - svc-fsxadm is a member of the FSx delegated admins group (used for NTFS ACLs),
#   - users/groups present in the PREVIOUS desired state but not the current one are removed.
# MODE=delete (stack deletion) removes everything this script created.
# This is the ONLY step that uses the directory's Admin account. Nothing secret is printed.
# The host is not domain-joined, so every AD call names the DC and passes a credential.
$ErrorActionPreference = 'Stop'
$users     = @($V.USERS.Split(',') | Where-Object { $_ })
$groups    = @($V.GROUPS.Split(';') | Where-Object { $_ } | ForEach-Object { $n, $m = $_.Split(':'); [pscustomobject]@{ Name = $n; Member = $m } })
$prev      = if ($V.PSObject.Properties['PREVIOUS']) { $V.PREVIOUS | ConvertFrom-Json } else { $null }

function Get-Secret([string]$id) {
  (Get-SECSecretValue -SecretId $id -Region $V.REGION).SecretString | ConvertFrom-Json
}

Write-Output "== 1. AD tooling (mode=$($V.MODE))"
Install-WindowsFeature RSAT-AD-PowerShell | Out-Null
$WarningPreference = 'SilentlyContinue'   # no default AD drive on a non-joined host
Import-Module ActiveDirectory
$WarningPreference = 'Continue'
$adm  = Get-Secret "$($V.PREFIX)/ad-admin"
$cred = New-Object System.Management.Automation.PSCredential("$($V.NETBIOS)\Admin", (ConvertTo-SecureString $adm.password -AsPlainText -Force))
$adm  = $null
$ad   = @{ Server = $V.DC_IP; Credential = $cred }
$dnParts = ($V.DOMAIN.Split('.') | ForEach-Object { "DC=$_" }) -join ','
$usersOu = "OU=Users,OU=$($V.NETBIOS),$dnParts"
$computersOu = "OU=Computers,OU=$($V.NETBIOS),$dnParts"

# Delegation for the SVM join account: rights FSx documents for a delegated service
# account, scoped to computer objects in the Computers OU.
$computer      = [Guid]'bf967a86-0de6-11d0-a285-00aa003049e2'
$resetPassword = [Guid]'00299570-246d-11d0-a768-00aa006e0529'
$acctRestrict  = [Guid]'4c164200-20c0-11d0-a768-00aa006e0529'
$dnsHostName   = [Guid]'72e39547-7b18-11d1-adef-00c04fd8d5cd'
$spn           = [Guid]'f3a64788-5306-11d1-a9c5-0060b0b5c4de'
function Get-JoinRules([System.Security.Principal.SecurityIdentifier]$sid) {
  $R = [System.DirectoryServices.ActiveDirectoryRights]
  $A = [System.Security.AccessControl.AccessControlType]::Allow
  $I = [System.DirectoryServices.ActiveDirectorySecurityInheritance]
  @(
    (New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid, ($R::CreateChild -bor $R::DeleteChild), $A, $computer, $I::All)),
    (New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid, $R::ExtendedRight, $A, $resetPassword, $I::Descendents, $computer)),
    (New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid, ($R::ReadProperty -bor $R::WriteProperty), $A, $acctRestrict, $I::Descendents, $computer)),
    (New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid, $R::Self, $A, $dnsHostName, $I::Descendents, $computer)),
    (New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid, $R::Self, $A, $spn, $I::Descendents, $computer))
  )
}
function Set-JoinDelegation([string]$user, [bool]$present) {
  $u = Get-ADUser -Filter "SamAccountName -eq '$user'" @ad
  if (-not $u) { return 0 }
  New-PSDrive -Name ADX -PSProvider ActiveDirectory -Root '//RootDSE/' -Server $V.DC_IP -Credential $cred | Out-Null
  try {
    $path = "ADX:\$computersOu"
    $sid = New-Object System.Security.Principal.SecurityIdentifier($u.SID.Value)
    $acl = Get-Acl -Path $path
    if ($present) { Get-JoinRules $sid | ForEach-Object { $acl.AddAccessRule($_) } }
    else { $acl.PurgeAccessRules($sid) }
    Set-Acl -Path $path -AclObject $acl
    @((Get-Acl -Path $path).Access | Where-Object {
      $_.IdentityReference.Value -eq $sid.Value -or $_.IdentityReference.Value -like "*\$user" }).Count
  } finally { Remove-PSDrive ADX }
}
function Remove-UserIfPresent([string]$u) {
  if (Get-ADUser -Filter "SamAccountName -eq '$u'" @ad) { Remove-ADUser -Identity $u -Confirm:$false @ad; Write-Output "removed user $u" }
}
function Remove-GroupIfPresent([string]$g) {
  if (Get-ADGroup -Filter "Name -eq '$g'" @ad) { Remove-ADGroup -Identity $g -Confirm:$false @ad; Write-Output "removed group $g" }
}

if ($V.MODE -eq 'delete') {
  Write-Output "== delete: OU delegation, group memberships, groups, users"
  Set-JoinDelegation $V.SVM_JOIN_USER $false | Out-Null
  foreach ($g in $groups) { Remove-GroupIfPresent $g.Name }
  foreach ($u in $users) { Remove-UserIfPresent $u }   # also drops svc-fsxadm's FSx-admins membership
  Write-Output "BOOTSTRAP_OK"
  return
}

Write-Output "== 2. Users ($($users -join ', '))"
foreach ($u in $users) {
  $pw = ConvertTo-SecureString (Get-Secret "$($V.PREFIX)/ad-user-$u").password -AsPlainText -Force
  if (Get-ADUser -Filter "SamAccountName -eq '$u'" @ad) {
    Set-ADAccountPassword -Identity $u -Reset -NewPassword $pw @ad
    Enable-ADAccount -Identity $u @ad
    Write-Output "updated $u"
  } else {
    New-ADUser -Name $u -SamAccountName $u -UserPrincipalName "$u@$($V.DOMAIN)" -Path $usersOu `
      -AccountPassword $pw -Enabled $true -PasswordNeverExpires $true @ad
    Write-Output "created $u"
  }
}

Write-Output "== 3. SFTP groups (exactly one member each)"
foreach ($g in $groups) {
  if (-not (Get-ADGroup -Filter "Name -eq '$($g.Name)'" @ad)) {
    New-ADGroup -Name $g.Name -SamAccountName $g.Name -GroupScope Global -GroupCategory Security -Path $usersOu @ad
    Write-Output "created group $($g.Name)"
  }
  $current = @(Get-ADGroupMember -Identity $g.Name @ad | ForEach-Object { $_.SamAccountName })
  $extra = @($current | Where-Object { $_ -ne $g.Member })
  if ($extra.Count) { Remove-ADGroupMember -Identity $g.Name -Members $extra -Confirm:$false @ad }
  if ($current -notcontains $g.Member) { Add-ADGroupMember -Identity $g.Name -Members $g.Member @ad }
  $sid = (Get-ADGroup -Identity $g.Name @ad).SID.Value
  Write-Output "$($g.Name) = $($g.Member) ($sid)"
  Write-Output "OUT_SID_$($g.Name.ToUpper())=$sid"
}

if ($prev) {
  Write-Output "== 3b. Reconcile against the previous desired state"
  $prevGroups = @($prev.GROUPS.Split(';') | Where-Object { $_ } | ForEach-Object { $_.Split(':')[0] })
  foreach ($g in ($prevGroups | Where-Object { $groups.Name -notcontains $_ })) { Remove-GroupIfPresent $g }
  $prevUsers = @($prev.USERS.Split(',') | Where-Object { $_ })
  foreach ($u in ($prevUsers | Where-Object { $users -notcontains $_ })) { Remove-UserIfPresent $u }
  if ($prev.SVM_JOIN_USER -and $prev.SVM_JOIN_USER -ne $V.SVM_JOIN_USER) { Set-JoinDelegation $prev.SVM_JOIN_USER $false | Out-Null }
}

Write-Output "== 4. $($V.FSX_ADMIN_USER) -> '$($V.FSX_ADMINS_GROUP)'"
if (@(Get-ADGroupMember -Identity $V.FSX_ADMINS_GROUP @ad | ForEach-Object { $_.SamAccountName }) -notcontains $V.FSX_ADMIN_USER) {
  Add-ADGroupMember -Identity $V.FSX_ADMINS_GROUP -Members $V.FSX_ADMIN_USER @ad
}

Write-Output "== 5. Delegate $computersOu to $($V.SVM_JOIN_USER) (SVM join account)"
$count = Set-JoinDelegation $V.SVM_JOIN_USER $true
Write-Output "delegated ACEs for $($V.SVM_JOIN_USER): $count"
if ($count -lt 5) { throw "OU delegation verification failed ($count of 5 ACEs)" }

Write-Output "== 6. SIDs for NTFS ACLs"
foreach ($u in $V.SID_USERS.Split(',')) {
  Write-Output "OUT_SID_$($u.ToUpper() -replace '-', '_')=$((Get-ADUser -Identity $u @ad).SID.Value)"
}

Write-Output "BOOTSTRAP_OK"
