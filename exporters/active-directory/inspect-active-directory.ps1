param(
  [string]$Server,
  [ValidateSet('user','group')][string]$Kind,
  [string]$Search = '',
  [string]$Identifier = '',
  [ValidateRange(1,601)][int]$Limit = 25,
  [string]$Attributes = '',
  [switch]$Discover
)

$ErrorActionPreference = 'Stop'

function ConvertTo-LdapFilterValue {
  param([string]$Value)
  $builder = [System.Text.StringBuilder]::new()
  foreach ($character in $Value.ToCharArray()) {
    switch ($character) {
      ([char]0) { $null = $builder.Append('\00') }
      '(' { $null = $builder.Append('\28') }
      ')' { $null = $builder.Append('\29') }
      '*' { $null = $builder.Append('\2a') }
      '\' { $null = $builder.Append('\5c') }
      default { $null = $builder.Append($character) }
    }
  }
  return $builder.ToString()
}

function Test-SafeAttributeName {
  param([string]$Name)
  if ($Name -notmatch '^[A-Za-z][A-Za-z0-9-]{0,63}$') { return $false }
  $normalized = ($Name -replace '[^A-Za-z0-9]', '').ToLowerInvariant()
  $forbidden = @(
    'unicodepwd','supplementalcredentials','userpassword','authpassword','ntpwdhistory',
    'dbcspwd','passwordhash','accesstoken','refreshtoken','clientsecret','apikey',
    'privatekey','credentials'
  )
  if ($forbidden -contains $normalized) { return $false }
  return $normalized -notmatch '(password|token|secret|privatekey|credential)'
}

function ConvertTo-SafeValues {
  param($Value)
  $values = @()
  foreach ($item in @($Value) | Select-Object -First 20) {
    if ($null -eq $item -or $item -is [byte[]]) { continue }
    $text = if ($item -is [System.Security.Principal.SecurityIdentifier]) {
      $item.Value
    } elseif ($item -is [datetime]) {
      $item.ToUniversalTime().ToString('o', [System.Globalization.CultureInfo]::InvariantCulture)
    } else {
      [string]$item
    }
    if ($text.Length -gt 500) { $text = $text.Substring(0, 500) + '…' }
    $values += $text
  }
  return @($values)
}

Import-Module ActiveDirectory -ErrorAction Stop
$serverArg = @{}
if ($Server) { $serverArg.Server = $Server }

$requested = @()
foreach ($attribute in @($Attributes -split ',')) {
  $attribute = $attribute.Trim()
  if (-not $attribute) { continue }
  if (-not (Test-SafeAttributeName -Name $attribute)) { throw 'Invalid or forbidden inspector attribute' }
  $requested += $attribute
}
$baseProperties = if ($Kind -eq 'group') {
  @('SamAccountName','Name','DisplayName','Description','SID','ObjectGUID','DistinguishedName','managedBy')
} else {
  @('SamAccountName','UserPrincipalName','Name','DisplayName','Description','Mail','SID','ObjectGUID','DistinguishedName','Enabled')
}
$properties = @($baseProperties + $requested | Select-Object -Unique)

if ($Identifier) {
  $objects = if ($Kind -eq 'group') {
    @(Get-ADGroup -Identity $Identifier -Properties $properties @serverArg)
  } else {
    @(Get-ADUser -Identity $Identifier -Properties $properties @serverArg)
  }
} else {
  $class = if ($Kind -eq 'group') { 'group' } else { 'user' }
  $filter = "(objectClass=$class)"
  if ($Search) {
    $escaped = ConvertTo-LdapFilterValue -Value $Search
    $filter = "(&(objectClass=$class)(|(name=*$escaped*)(sAMAccountName=*$escaped*)(displayName=*$escaped*)))"
  }
  $objects = if ($Kind -eq 'group') {
    @(Get-ADGroup -LDAPFilter $filter -Properties $properties -ResultSetSize $Limit @serverArg)
  } else {
    @(Get-ADUser -LDAPFilter $filter -Properties $properties -ResultSetSize $Limit @serverArg)
  }
}

$rows = foreach ($object in @($objects) | Select-Object -First $Limit) {
  $safe = [ordered]@{}
  foreach ($property in $object.PSObject.Properties) {
    if (-not (Test-SafeAttributeName -Name $property.Name)) { continue }
    $values = @(ConvertTo-SafeValues -Value $property.Value)
    if ($values.Count -gt 0) { $safe[$property.Name] = $values }
  }
  $sid = if ($object.SID) { $object.SID.Value } else { '' }
  [PSCustomObject]@{
    kind = $Kind
    identifier = if ($sid) { $sid } else { [string]$object.ObjectGUID }
    display_name = if ($object.DisplayName) { $object.DisplayName } elseif ($object.Name) { $object.Name } else { $object.SamAccountName }
    technical_identifier = $sid
    attributes = $safe
  }
}

@($rows) | ConvertTo-Json -Depth 6 -Compress
