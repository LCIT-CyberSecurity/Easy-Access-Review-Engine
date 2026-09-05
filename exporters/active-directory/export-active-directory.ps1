param(
  [Parameter(Mandatory=$true)][string]$ProviderName,
  [Parameter(Mandatory=$true)][string]$Output
)

$ErrorActionPreference = "Stop"
$tmp = New-Item -ItemType Directory -Path ([System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), [System.Guid]::NewGuid().ToString()))
try {
  "provider: $ProviderName`nsource_type: active_directory`ncompleteness: full`nscope: all" | Out-File -Encoding utf8 "$tmp/manifest.yaml"
  Get-ADUser -Filter * -Properties DisplayName,Mail,Enabled,SID,DistinguishedName,LastLogonDate,PasswordLastSet,AccountExpirationDate,WhenCreated,Description,UserPrincipalName |
    Select-Object SamAccountName,UserPrincipalName,DisplayName,Mail,Enabled,SID,DistinguishedName,LastLogonDate,PasswordLastSet,AccountExpirationDate,WhenCreated,Description |
    Export-Csv -NoTypeInformation -Encoding UTF8 "$tmp/users.csv"
  Get-ADGroup -Filter * -Properties SamAccountName,Name,SID,DistinguishedName,Description,GroupScope,GroupCategory |
    Select-Object SamAccountName,Name,SID,DistinguishedName,Description,GroupScope,GroupCategory |
    Export-Csv -NoTypeInformation -Encoding UTF8 "$tmp/groups.csv"
  $memberships = foreach ($group in Get-ADGroup -Filter * -Properties SID) {
    Get-ADGroupMember -Identity $group -ErrorAction SilentlyContinue | ForEach-Object {
      [PSCustomObject]@{
        Group = $group.SamAccountName
        GroupSID = $group.SID.Value
        Member = $_.SamAccountName
        MemberSID = $_.SID.Value
        MemberType = $_.objectClass
        MemberDN = $_.distinguishedName
      }
    }
  }
  $memberships | Export-Csv -NoTypeInformation -Encoding UTF8 "$tmp/memberships.csv"
  Compress-Archive -Path "$tmp/manifest.yaml","$tmp/users.csv","$tmp/groups.csv","$tmp/memberships.csv" -DestinationPath $Output -Force
}
finally {
  Remove-Item -Recurse -Force $tmp
}
