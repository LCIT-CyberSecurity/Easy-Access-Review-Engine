param(
  [string]$ProviderName,
  [string]$Output,
  [string]$Server,
  [int]$OperationTimeoutSeconds = 300,
  [switch]$AllowPartial,
  [switch]$CheckOnly
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

function New-MembershipKey {
  param(
    [Parameter(Mandatory=$true)][string]$GroupSID,
    [Parameter(Mandatory=$true)][string]$MemberSID
  )
  return "$GroupSID|$MemberSID"
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
  $message = if ($ErrorRecord.Exception) { $ErrorRecord.Exception.Message } else { [string]$ErrorRecord }
  $code = if ($ErrorRecord.FullyQualifiedErrorId) { $ErrorRecord.FullyQualifiedErrorId } else { $ErrorRecord.GetType().FullName }
  [PSCustomObject]@{
    ObjectType = $ObjectType
    ObjectIdentifier = $ObjectIdentifier
    ObjectSID = $ObjectSID
    Operation = $Operation
    ErrorCode = $code
    ErrorMessage = $message
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
  computers: $($Stats.Computers)
  memberships: $($Stats.Memberships)
  collection_errors: $($Stats.CollectionErrors)
"@ | Out-File -Encoding utf8 $Path
}


function ConvertTo-AuthDurationSeconds {
  param($Value)
  if ($null -eq $Value) { return $null }
  if ($Value -is [timespan]) { return [int][math]::Round($Value.TotalSeconds) }
  return $Value
}

function Get-AuthenticationPosture {
  param($ServerArg, $OperationTimeoutSeconds)
  $script:authenticationErrors = @()
  $passwordPolicy = $null
  $fineGrained = @()
  try {
    $passwordPolicy = Invoke-AdCollectorOperation -Operation 'Get-ADDefaultDomainPasswordPolicy' -OperationTimeoutSeconds $OperationTimeoutSeconds -ScriptBlock {
      param($ServerArg)
      Get-ADDefaultDomainPasswordPolicy @ServerArg
    } -ArgumentList @($ServerArg)
  } catch { $script:authenticationErrors += New-CollectionError -ObjectType 'authentication' -ObjectIdentifier '*' -Operation 'Get-ADDefaultDomainPasswordPolicy' -ErrorRecord $_ }
  try {
    $fineGrained = @(Invoke-AdCollectorOperation -Operation 'Get-ADFineGrainedPasswordPolicy' -OperationTimeoutSeconds $OperationTimeoutSeconds -ScriptBlock {
      param($ServerArg)
      Get-ADFineGrainedPasswordPolicy -Filter * @ServerArg
    } -ArgumentList @($ServerArg))
  } catch { $script:authenticationErrors += New-CollectionError -ObjectType 'authentication' -ObjectIdentifier '*' -Operation 'Get-ADFineGrainedPasswordPolicy' -ErrorRecord $_ }
  $policy = if ($passwordPolicy) { [PSCustomObject]@{ status='collected'; minimum_length=$passwordPolicy.MinPasswordLength; history=$passwordPolicy.PasswordHistoryCount; minimum_age_seconds=(ConvertTo-AuthDurationSeconds $passwordPolicy.MinPasswordAge); maximum_age_seconds=(ConvertTo-AuthDurationSeconds $passwordPolicy.MaxPasswordAge); complexity=$passwordPolicy.ComplexityEnabled; reversible_encryption=$passwordPolicy.ReversibleEncryptionEnabled; lockout_threshold=$passwordPolicy.LockoutThreshold; lockout_duration_seconds=(ConvertTo-AuthDurationSeconds $passwordPolicy.LockoutDuration); lockout_observation_window_seconds=(ConvertTo-AuthDurationSeconds $passwordPolicy.LockoutObservationWindow) } } else { [PSCustomObject]@{ status='unknown' } }
  [PSCustomObject]@{ provider=$ProviderName; source='active_directory'; completeness='full'; controls=@{ password_policy=$policy; mfa=@{ status='not_supported' }; federation=@{ status='not_supported' }; tokens=@{ status='not_supported' }; session_policy=@{ status='not_supported' } }; fine_grained_policies=@($fineGrained | ForEach-Object { [PSCustomObject]@{ name=$_.Name; precedence=$_.Precedence; minimum_length=$_.MinPasswordLength; history=$_.PasswordHistoryCount; minimum_age_seconds=(ConvertTo-AuthDurationSeconds $_.MinPasswordAge); maximum_age_seconds=(ConvertTo-AuthDurationSeconds $_.MaxPasswordAge); complexity=$_.ComplexityEnabled; lockout_threshold=$_.LockoutThreshold; lockout_duration_seconds=(ConvertTo-AuthDurationSeconds $_.LockoutDuration); lockout_observation_window_seconds=(ConvertTo-AuthDurationSeconds $_.LockoutObservationWindow) } }) }
}

function Add-PrimaryGroupMembership {
  param($Memberships, $MembershipIndex, $Principal, $GroupsBySid)
  if (-not $Principal.SID -or -not $Principal.PrimaryGroupID) { return }
  $primaryGroupSid = Get-PrimaryGroupSid -PrincipalSid $Principal.SID.Value -PrimaryGroupID ([string]$Principal.PrimaryGroupID)
  if (-not $GroupsBySid.ContainsKey($primaryGroupSid)) { return }
  $key = New-MembershipKey -GroupSID $primaryGroupSid -MemberSID $Principal.SID.Value
  if ($MembershipIndex.Contains($key)) { return }
  $group = $GroupsBySid[$primaryGroupSid]
  $membership = [PSCustomObject]@{
    Group = $group.SamAccountName
    GroupSID = $group.SID.Value
    Member = $Principal.SamAccountName
    MemberSID = $Principal.SID.Value
    MemberType = $Principal.ObjectClass
    MemberDN = $Principal.DistinguishedName
    MembershipType = 'primary_group'
  }
  $null = $Memberships.Add($membership)
  $null = $MembershipIndex.Add($key)
}

function Add-ServerArg {
  $params = @{}
  if ($Server) { $params.Server = $Server }
  return $params
}

function Invoke-AdOperationWithTimeout {
  param(
    [Parameter(Mandatory=$true)][string]$Operation,
    [Parameter(Mandatory=$true)][scriptblock]$ScriptBlock,
    [object[]]$ArgumentList = @(),
    [int]$OperationTimeoutSeconds = 300,
    [switch]$ImportActiveDirectoryModule
  )

  if ($OperationTimeoutSeconds -le 0) {
    return & $ScriptBlock @ArgumentList
  }

  $powerShell = [PowerShell]::Create()
  $null = $powerShell.AddScript({
    param($InnerScriptBlock, $InnerArgumentList, $ShouldImportActiveDirectoryModule)
    if ($ShouldImportActiveDirectoryModule) {
      Import-Module ActiveDirectory -ErrorAction Stop
    }
    & $InnerScriptBlock @InnerArgumentList
  }).AddArgument($ScriptBlock).AddArgument($ArgumentList).AddArgument([bool]$ImportActiveDirectoryModule)
  $handle = $powerShell.BeginInvoke()
  try {
    if (-not $handle.AsyncWaitHandle.WaitOne([TimeSpan]::FromSeconds($OperationTimeoutSeconds))) {
      $powerShell.Stop()
      throw [System.TimeoutException]::new("Active Directory operation '$Operation' exceeded timeout of $OperationTimeoutSeconds second(s)")
    }
    $result = $powerShell.EndInvoke($handle)
    if ($powerShell.Streams.Error.Count -gt 0) {
      throw $powerShell.Streams.Error[0]
    }
    return $result
  }
  finally {
    if ($handle.AsyncWaitHandle) {
      $handle.AsyncWaitHandle.Close()
    }
    $powerShell.Dispose()
  }
}

function Invoke-AdCollectorOperation {
  param(
    [Parameter(Mandatory=$true)][string]$Operation,
    [Parameter(Mandatory=$true)][scriptblock]$ScriptBlock,
    [object[]]$ArgumentList = @(),
    [int]$OperationTimeoutSeconds = 300
  )
  Invoke-AdOperationWithTimeout -Operation $Operation -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList -OperationTimeoutSeconds $OperationTimeoutSeconds -ImportActiveDirectoryModule
}

function Invoke-ActiveDirectoryExport {
  param(
    [Parameter(Mandatory=$true)][string]$ProviderName,
    [Parameter(Mandatory=$true)][string]$Output,
    [string]$Server,
    [int]$OperationTimeoutSeconds = 300,
    [switch]$AllowPartial,
    [switch]$CheckOnly
  )

  if ($CheckOnly) {
    Import-Module ActiveDirectory -ErrorAction Stop
    $serverArg = Add-ServerArg
    $domain = Invoke-AdCollectorOperation -Operation "Get-ADDomain" -OperationTimeoutSeconds $OperationTimeoutSeconds -ScriptBlock {
      param($ServerArg)
      Get-ADDomain @ServerArg
    } -ArgumentList @($serverArg)
    Write-Output ("Active Directory check succeeded for " + $domain.DNSRoot)
    return
  }

  $tmp = New-Item -ItemType Directory -Path ([System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), [System.Guid]::NewGuid().ToString()))
$errors = @()
try {
  Import-Module ActiveDirectory -ErrorAction Stop
  $serverArg = Add-ServerArg
  $domainName = ''
  $domainSid = ''
  try {
    $domain = Invoke-AdCollectorOperation -Operation 'Get-ADDomain' -OperationTimeoutSeconds $OperationTimeoutSeconds -ScriptBlock {
      param($ServerArg)
      Get-ADDomain @ServerArg
    } -ArgumentList @($serverArg)
    $domainName = $domain.DNSRoot
    $domainSid = $domain.DomainSID.Value
  }
  catch {
    $errors += New-CollectionError -ObjectType 'domain' -ObjectIdentifier '*' -ObjectSID $null -Operation 'Get-ADDomain' -ErrorRecord $_
  }

  $userProps = @('DisplayName','Mail','Enabled','SID','DistinguishedName','LastLogonDate','PasswordLastSet','AccountExpirationDate','WhenCreated','Description','UserPrincipalName','PrimaryGroupID','LockedOut','ServicePrincipalName','ObjectGUID')
  try {
    $users = Invoke-AdCollectorOperation -Operation 'Get-ADUser' -OperationTimeoutSeconds $OperationTimeoutSeconds -ScriptBlock {
      param($OperationArgs)
      $serverArg = $OperationArgs.ServerArg
      Get-ADUser -Filter * -Properties $OperationArgs.Properties @serverArg
    } -ArgumentList @(@{ Properties = $userProps; ServerArg = $serverArg })
  }
  catch {
    $users = @()
    $errors += New-CollectionError -ObjectType 'user' -ObjectIdentifier '*' -ObjectSID $null -Operation 'Get-ADUser -Filter *' -ErrorRecord $_
  }
  $users | Select-Object SamAccountName,UserPrincipalName,DisplayName,Mail,Enabled,SID,DistinguishedName,Description,PrimaryGroupID,LockedOut,ObjectGUID,
    @{Name='LastLogonDate';Expression={ ConvertTo-InvariantAdDate $_.LastLogonDate }},
    @{Name='PasswordLastSet';Expression={ ConvertTo-InvariantAdDate $_.PasswordLastSet }},
    @{Name='AccountExpirationDate';Expression={ ConvertTo-InvariantAdDate $_.AccountExpirationDate }},
    @{Name='WhenCreated';Expression={ ConvertTo-InvariantAdDate $_.WhenCreated }},
    @{Name='ServicePrincipalName';Expression={ ConvertTo-AdCsvMultiValue $_.ServicePrincipalName }} |
    Export-Csv -NoTypeInformation -Encoding UTF8 "$tmp/users.csv"

  $groupProps = @('SamAccountName','Name','SID','DistinguishedName','Description','GroupScope','GroupCategory')
  try {
    $groups = Invoke-AdCollectorOperation -Operation 'Get-ADGroup' -OperationTimeoutSeconds $OperationTimeoutSeconds -ScriptBlock {
      param($OperationArgs)
      $serverArg = $OperationArgs.ServerArg
      Get-ADGroup -Filter * -Properties $OperationArgs.Properties @serverArg
    } -ArgumentList @(@{ Properties = $groupProps; ServerArg = $serverArg })
  }
  catch {
    $groups = @()
    $errors += New-CollectionError -ObjectType 'group' -ObjectIdentifier '*' -ObjectSID $null -Operation 'Get-ADGroup -Filter *' -ErrorRecord $_
  }
  $groups | Select-Object SamAccountName,Name,SID,DistinguishedName,Description,GroupScope,GroupCategory |
    Export-Csv -NoTypeInformation -Encoding UTF8 "$tmp/groups.csv"

  $svcProps = @('SamAccountName','SID','DistinguishedName','Enabled','Description','ServicePrincipalName','ObjectClass','ObjectGUID','Name','DisplayName','PrimaryGroupID')
  try {
    $serviceAccounts = Invoke-AdCollectorOperation -Operation 'Get-ADServiceAccount' -OperationTimeoutSeconds $OperationTimeoutSeconds -ScriptBlock {
      param($OperationArgs)
      $serverArg = $OperationArgs.ServerArg
      Get-ADServiceAccount -Filter * -Properties $OperationArgs.Properties @serverArg
    } -ArgumentList @(@{ Properties = $svcProps; ServerArg = $serverArg })
  }
  catch {
    $serviceAccounts = @()
    $errors += New-CollectionError -ObjectType 'service_account' -ObjectIdentifier '*' -ObjectSID $null -Operation 'Get-ADServiceAccount -Filter *' -ErrorRecord $_
  }
  $serviceAccounts | Select-Object SamAccountName,Name,DisplayName,SID,DistinguishedName,Enabled,Description,ObjectClass,ObjectGUID,PrimaryGroupID,
    @{Name='ServicePrincipalName';Expression={ ConvertTo-AdCsvMultiValue $_.ServicePrincipalName }} |
    Export-Csv -NoTypeInformation -Encoding UTF8 "$tmp/service_accounts.csv"

  $memberships = [System.Collections.Generic.List[object]]::new()
  $membershipIndex = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
  foreach ($group in $groups) {
    try {
      $members = Invoke-AdCollectorOperation -Operation "Get-ADGroupMember $($group.SamAccountName)" -OperationTimeoutSeconds $OperationTimeoutSeconds -ScriptBlock {
        param($Identity, $ServerArg)
        Get-ADGroupMember -Identity $Identity -ErrorAction Stop @ServerArg
      } -ArgumentList @($group, $serverArg)
      foreach ($member in $members) {
        $memberSid = if ($member.SID) { $member.SID.Value } else { $null }
        $membership = [PSCustomObject]@{
          Group = $group.SamAccountName
          GroupSID = $group.SID.Value
          Member = $member.SamAccountName
          MemberSID = $memberSid
          MemberType = $member.objectClass
          MemberDN = $member.distinguishedName
          MembershipType = 'direct'
        }
        $null = $memberships.Add($membership)
        if ($group.SID -and $group.SID.Value -and $memberSid) {
          $null = $membershipIndex.Add((New-MembershipKey -GroupSID $group.SID.Value -MemberSID $memberSid))
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
    Add-PrimaryGroupMembership -Memberships $memberships -MembershipIndex $membershipIndex -Principal $principal -GroupsBySid $groupsBySid
  }

  try {
    $computers = Invoke-AdCollectorOperation -Operation 'Get-ADComputer' -OperationTimeoutSeconds $OperationTimeoutSeconds -ScriptBlock {
      param($ServerArg)
      Get-ADComputer -Filter * -Properties SamAccountName,SID,DistinguishedName,Enabled,DNSHostName,Description,ObjectGUID,PrimaryGroupID @ServerArg
    } -ArgumentList @($serverArg)
  }
  catch {
    $computers = @()
    $errors += New-CollectionError -ObjectType 'computer' -ObjectIdentifier '*' -ObjectSID $null -Operation 'Get-ADComputer -Filter *' -ErrorRecord $_
  }
  foreach ($principal in @($computers)) {
    Add-PrimaryGroupMembership -Memberships $memberships -MembershipIndex $membershipIndex -Principal $principal -GroupsBySid $groupsBySid
  }
  $computers | Select-Object SamAccountName,Name,SID,DistinguishedName,Enabled,DNSHostName,Description,ObjectGUID,PrimaryGroupID |
    Export-Csv -NoTypeInformation -Encoding UTF8 "$tmp/computers.csv"

  $memberships | Export-Csv -NoTypeInformation -Encoding UTF8 "$tmp/memberships.csv"
  $authenticationPosture = Get-AuthenticationPosture -ServerArg $serverArg -OperationTimeoutSeconds $OperationTimeoutSeconds
  $errors += @($script:authenticationErrors)
  $authenticationPosture | ConvertTo-Json -Depth 12 | Out-File -Encoding utf8 "$tmp/authentication-posture.json"
  $errors | Export-Csv -NoTypeInformation -Encoding UTF8 "$tmp/collection-errors.csv"

  $completeness = if ($errors.Count -eq 0) { 'full' } else { 'unknown' }
  $stats = [PSCustomObject]@{
    Users = @($users).Count
    Groups = @($groups).Count
    ServiceAccounts = @($serviceAccounts).Count
    Computers = @($computers).Count
    Memberships = @($memberships).Count
    CollectionErrors = @($errors).Count
  }
  Write-Manifest -Path "$tmp/manifest.yaml" -Stats $stats -Completeness $completeness -Domain $domainName -DomainSid $domainSid

  if ($errors.Count -gt 0 -and -not $AllowPartial) {
    throw "Active Directory collection failed for $($errors.Count) object(s). Re-run with -AllowPartial to keep a diagnostic ZIP marked completeness: unknown."
  }

  Compress-Archive -Path "$tmp/manifest.yaml","$tmp/users.csv","$tmp/groups.csv","$tmp/service_accounts.csv","$tmp/computers.csv","$tmp/memberships.csv","$tmp/collection-errors.csv","$tmp/authentication-posture.json" -DestinationPath $Output -Force
}
finally {
    Remove-Item -Recurse -Force $tmp
  }
}

if ($MyInvocation.InvocationName -eq '.') { return }
if (-not $ProviderName) { throw "ProviderName is required" }
if (-not $Output) { throw "Output is required" }
Invoke-ActiveDirectoryExport -ProviderName $ProviderName -Output $Output -Server $Server -OperationTimeoutSeconds $OperationTimeoutSeconds -AllowPartial:$AllowPartial -CheckOnly:$CheckOnly
