param(
  [string]$ProviderName,
  [string]$Output,
  [string]$Server,
  [switch]$AllowPartial
)

$ErrorActionPreference = "Stop"

function Get-RidFromSid {
  param([Parameter(Mandatory=$true)][string]$Sid)
  return ($Sid -split '-')[-1]
}

function Get-DomainSidFromSid {
  param([Parameter(Mandatory=$true)][string]$Sid)
  $parts = $Sid -split '-'
  if ($parts.Count -lt 2) { throw "Invalid SID: $Sid" }
  return ($parts[0..($parts.Count - 2)] -join '-')
}

function Get-PrimaryGroupSid {
  param(
    [Parameter(Mandatory=$true)][string]$PrincipalSid,
    [Parameter(Mandatory=$true)][string]$PrimaryGroupID
  )
  return "$(Get-DomainSidFromSid -Sid $PrincipalSid)-$PrimaryGroupID"
}


function ConvertTo-InvariantAdDate {
  param($Value)
  if ($null -eq $Value) { return $null }
  if ($Value -is [datetime]) {
    return $Value.ToUniversalTime().ToString("o", [System.Globalization.CultureInfo]::InvariantCulture)
  }
  return $Value
}

function ConvertTo-AdCsvMultiValue {
  param($Value)
  if ($null -eq $Value) { return $null }
  if ($Value -is [string]) { return $Value }
  return @($Value) -join ';'
}

function New-CollectionError {
  param($ObjectType, $ObjectIdentifier, $ObjectSID, $Operation, $ErrorRecord)
  [PSCustomObject]@{
    ObjectType = $ObjectType
    ObjectIdentifier = $ObjectIdentifier
    ObjectSID = $ObjectSID
    Operation = $Operation
    ErrorCode = $ErrorRecord.FullyQualifiedErrorId
    ErrorMessage = $ErrorRecord.Exception.Message
  }
}

function Write-Manifest {
  param($Path, $Stats, $Completeness, $Domain, $DomainSid)
  $generatedAt = (Get-Date).ToUniversalTime().ToString("o", [System.Globalization.CultureInfo]::InvariantCulture)
  @"
schema_version: 1
source_type: active_directory
provider: $ProviderName
domain: $Domain
domain_sid: $DomainSid
generated_at: $generatedAt
completeness: $Completeness
statistics:
  users: $($Stats.Users)
  groups: $($Stats.Groups)
  service_accounts: $($Stats.ServiceAccounts)
  referenced_computers: $($Stats.ReferencedComputers)
  memberships: $($Stats.Memberships)
  collection_errors: $($Stats.CollectionErrors)
"@ | Out-File -Encoding utf8 $Path
}


function Add-PrimaryGroupMembership {
  param($Memberships, $Principal, $GroupsBySid)
  if (-not $Principal.SID -or -not $Principal.PrimaryGroupID) { return $Memberships }
  $primaryGroupSid = Get-PrimaryGroupSid -PrincipalSid $Principal.SID.Value -PrimaryGroupID ([string]$Principal.PrimaryGroupID)
  if (-not $GroupsBySid.ContainsKey($primaryGroupSid)) { return $Memberships }
  $group = $GroupsBySid[$primaryGroupSid]
  $exists = $Memberships | Where-Object { $_.GroupSID -eq $primaryGroupSid -and $_.MemberSID -eq $Principal.SID.Value } | Select-Object -First 1
  if ($exists) { return $Memberships }
  $Memberships += [PSCustomObject]@{
    Group = $group.SamAccountName
    GroupSID = $group.SID.Value
    Member = $Principal.SamAccountName
    MemberSID = $Principal.SID.Value
    MemberType = $Principal.ObjectClass
    MemberDN = $Principal.DistinguishedName
    MembershipType = 'primary_group'
  }
  return $Memberships
}

function Add-ServerArg {
  $params = @{}
  if ($Server) { $params.Server = $Server }
  return $params
}

function Invoke-ActiveDirectoryExport {
  param(
    [Parameter(Mandatory=$true)][string]$ProviderName,
    [Parameter(Mandatory=$true)][string]$Output,
    [string]$Server,
    [switch]$AllowPartial
  )

  $tmp = New-Item -ItemType Directory -Path ([System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), [System.Guid]::NewGuid().ToString()))
$errors = @()
try {
  Import-Module ActiveDirectory -ErrorAction Stop
  $serverArg = Add-ServerArg
  $domain = Get-ADDomain @serverArg
  $domainName = $domain.DNSRoot
  $domainSid = $domain.DomainSID.Value

  $userProps = @('DisplayName','Mail','Enabled','SID','DistinguishedName','LastLogonDate','PasswordLastSet','AccountExpirationDate','WhenCreated','Description','UserPrincipalName','PrimaryGroupID','LockedOut','ServicePrincipalName','ObjectGUID')
  $users = Get-ADUser -Filter * -Properties $userProps @serverArg
  $users | Select-Object SamAccountName,UserPrincipalName,DisplayName,Mail,Enabled,SID,DistinguishedName,Description,PrimaryGroupID,LockedOut,ObjectGUID,
    @{Name='LastLogonDate';Expression={ ConvertTo-InvariantAdDate $_.LastLogonDate }},
    @{Name='PasswordLastSet';Expression={ ConvertTo-InvariantAdDate $_.PasswordLastSet }},
    @{Name='AccountExpirationDate';Expression={ ConvertTo-InvariantAdDate $_.AccountExpirationDate }},
    @{Name='WhenCreated';Expression={ ConvertTo-InvariantAdDate $_.WhenCreated }},
    @{Name='ServicePrincipalName';Expression={ ConvertTo-AdCsvMultiValue $_.ServicePrincipalName }} |
    Export-Csv -NoTypeInformation -Encoding UTF8 "$tmp/users.csv"

  $groupProps = @('SamAccountName','Name','SID','DistinguishedName','Description','GroupScope','GroupCategory')
  $groups = Get-ADGroup -Filter * -Properties $groupProps @serverArg
  $groups | Select-Object SamAccountName,Name,SID,DistinguishedName,Description,GroupScope,GroupCategory |
    Export-Csv -NoTypeInformation -Encoding UTF8 "$tmp/groups.csv"

  $svcProps = @('SamAccountName','SID','DistinguishedName','Enabled','Description','ServicePrincipalName','ObjectClass','ObjectGUID','Name','DisplayName','PrimaryGroupID')
  $serviceAccounts = Get-ADServiceAccount -Filter * -Properties $svcProps @serverArg
  $serviceAccounts | Select-Object SamAccountName,Name,DisplayName,SID,DistinguishedName,Enabled,Description,ObjectClass,ObjectGUID,PrimaryGroupID,
    @{Name='ServicePrincipalName';Expression={ ConvertTo-AdCsvMultiValue $_.ServicePrincipalName }} |
    Export-Csv -NoTypeInformation -Encoding UTF8 "$tmp/service_accounts.csv"

  $memberships = @()
  $computerSids = @{}
  foreach ($group in $groups) {
    try {
      $members = Get-ADGroupMember -Identity $group -ErrorAction Stop @serverArg
      foreach ($member in $members) {
        $memberSid = if ($member.SID) { $member.SID.Value } else { $null }
        if ($member.objectClass -eq 'computer' -and $memberSid) { $computerSids[$memberSid] = $member.SamAccountName }
        $memberships += [PSCustomObject]@{
          Group = $group.SamAccountName
          GroupSID = $group.SID.Value
          Member = $member.SamAccountName
          MemberSID = $memberSid
          MemberType = $member.objectClass
          MemberDN = $member.distinguishedName
          MembershipType = 'direct'
        }
      }
    }
    catch {
      $errors += New-CollectionError -ObjectType 'group' -ObjectIdentifier $group.SamAccountName -ObjectSID $group.SID.Value -Operation 'Get-ADGroupMember' -ErrorRecord $_
    }
  }

  $groupsBySid = @{}
  foreach ($group in $groups) { $groupsBySid[$group.SID.Value] = $group }
  foreach ($principal in @($users) + @($serviceAccounts)) {
    $memberships = Add-PrimaryGroupMembership -Memberships $memberships -Principal $principal -GroupsBySid $groupsBySid
  }

  $computers = @()
  foreach ($sid in $computerSids.Keys) {
    try {
      $computers += Get-ADComputer -Identity $sid -Properties SamAccountName,SID,DistinguishedName,Enabled,DNSHostName,Description,ObjectGUID,PrimaryGroupID @serverArg
    }
    catch {
      $errors += New-CollectionError -ObjectType 'computer' -ObjectIdentifier $computerSids[$sid] -ObjectSID $sid -Operation 'Get-ADComputer' -ErrorRecord $_
    }
  }
  foreach ($principal in @($computers)) {
    $memberships = Add-PrimaryGroupMembership -Memberships $memberships -Principal $principal -GroupsBySid $groupsBySid
  }
  $computers | Select-Object SamAccountName,Name,SID,DistinguishedName,Enabled,DNSHostName,Description,ObjectGUID,PrimaryGroupID |
    Export-Csv -NoTypeInformation -Encoding UTF8 "$tmp/computers.csv"

  $memberships | Export-Csv -NoTypeInformation -Encoding UTF8 "$tmp/memberships.csv"
  $errors | Export-Csv -NoTypeInformation -Encoding UTF8 "$tmp/collection-errors.csv"

  $completeness = if ($errors.Count -eq 0) { 'full' } else { 'unknown' }
  $stats = [PSCustomObject]@{
    Users = @($users).Count
    Groups = @($groups).Count
    ServiceAccounts = @($serviceAccounts).Count
    ReferencedComputers = @($computers).Count
    Memberships = @($memberships).Count
    CollectionErrors = @($errors).Count
  }
  Write-Manifest -Path "$tmp/manifest.yaml" -Stats $stats -Completeness $completeness -Domain $domainName -DomainSid $domainSid

  if ($errors.Count -gt 0 -and -not $AllowPartial) {
    throw "Active Directory collection failed for $($errors.Count) object(s). Re-run with -AllowPartial to keep a diagnostic ZIP marked completeness: unknown."
  }

  Compress-Archive -Path "$tmp/manifest.yaml","$tmp/users.csv","$tmp/groups.csv","$tmp/service_accounts.csv","$tmp/computers.csv","$tmp/memberships.csv","$tmp/collection-errors.csv" -DestinationPath $Output -Force
}
finally {
    Remove-Item -Recurse -Force $tmp
  }
}

if ($MyInvocation.InvocationName -eq '.') { return }
if (-not $ProviderName) { throw "ProviderName is required" }
if (-not $Output) { throw "Output is required" }
Invoke-ActiveDirectoryExport -ProviderName $ProviderName -Output $Output -Server $Server -AllowPartial:$AllowPartial
