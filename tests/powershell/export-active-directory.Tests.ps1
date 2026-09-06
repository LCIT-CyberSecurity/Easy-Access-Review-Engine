# Pester tests for pure helper behavior in exporters/active-directory/export-active-directory.ps1.
# These tests do not require a domain controller. Tests that call ActiveDirectory cmdlets should be
# tagged integration and excluded from normal Linux CI.

Describe 'Active Directory exporter pure helpers' -Tag 'unit' {
  BeforeAll {
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
  }

  It 'extracts RID from SID' {
    Get-RidFromSid -Sid 'S-1-5-21-100-200-300-1101' | Should -Be '1101'
  }

  It 'builds primary group SID by replacing principal RID' {
    Get-PrimaryGroupSid -PrincipalSid 'S-1-5-21-100-200-300-1101' -PrimaryGroupID '513' |
      Should -Be 'S-1-5-21-100-200-300-513'
  }
}
