# Pester tests for exporters/active-directory/export-active-directory.ps1 without a domain controller.
# ActiveDirectory cmdlets are mocked; the production script is dot-sourced.

Describe 'Active Directory exporter' -Tag 'unit' {
  BeforeAll {
    $Script:RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '../..')
    $Script:Exporter = Join-Path $Script:RepoRoot 'exporters/active-directory/export-active-directory.ps1'
    . $Script:Exporter
  }

  BeforeEach {
    Mock Import-Module {}
    Mock Get-ADDomain {
      [PSCustomObject]@{
        DNSRoot = 'corp.example.test'
        DomainSID = [PSCustomObject]@{ Value = 'S-1-5-21-100-200-300' }
      }
    }
    Mock Get-ADUser {
      @(
        [PSCustomObject]@{
          SamAccountName = 'jdupont'
          UserPrincipalName = 'jdupont@example.test'
          DisplayName = 'Jean Dupont'
          Mail = 'jdupont@example.test'
          Enabled = $true
          SID = [PSCustomObject]@{ Value = 'S-1-5-21-100-200-300-1101' }
          DistinguishedName = 'CN=Jean Dupont,DC=corp,DC=example,DC=test'
          LastLogonDate = [datetime]'2024-01-02T03:04:05Z'
          PasswordLastSet = [datetime]'2024-01-03T03:04:05Z'
          AccountExpirationDate = [datetime]'2026-01-02T03:04:05Z'
          WhenCreated = [datetime]'2020-01-02T03:04:05Z'
          Description = ''
          PrimaryGroupID = '513'
          LockedOut = $false
          ServicePrincipalName = @()
          ObjectGUID = '11111111-1111-1111-1111-111111111111'
          ObjectClass = 'user'
        }
      )
    }
    Mock Get-ADGroup {
      @(
        [PSCustomObject]@{
          SamAccountName = 'Domain Users'
          Name = 'Domain Users'
          SID = [PSCustomObject]@{ Value = 'S-1-5-21-100-200-300-513' }
          DistinguishedName = 'CN=Domain Users,CN=Users,DC=corp,DC=example,DC=test'
          Description = 'Primary users'
          GroupScope = 'Global'
          GroupCategory = 'Security'
        },
        [PSCustomObject]@{
          SamAccountName = 'Domain Computers'
          Name = 'Domain Computers'
          SID = [PSCustomObject]@{ Value = 'S-1-5-21-100-200-300-515' }
          DistinguishedName = 'CN=Domain Computers,CN=Users,DC=corp,DC=example,DC=test'
          Description = 'Primary computers'
          GroupScope = 'Global'
          GroupCategory = 'Security'
        },
        [PSCustomObject]@{
          SamAccountName = 'GG_COMPUTERS'
          Name = 'GG_COMPUTERS'
          SID = [PSCustomObject]@{ Value = 'S-1-5-21-100-200-300-2200' }
          DistinguishedName = 'CN=GG_COMPUTERS,DC=corp,DC=example,DC=test'
          Description = 'Computer access'
          GroupScope = 'Global'
          GroupCategory = 'Security'
        },
        [PSCustomObject]@{
          SamAccountName = 'GG_FOREIGN'
          Name = 'GG_FOREIGN'
          SID = [PSCustomObject]@{ Value = 'S-1-5-21-100-200-300-2300' }
          DistinguishedName = 'CN=GG_FOREIGN,DC=corp,DC=example,DC=test'
          Description = 'Foreign access'
          GroupScope = 'Global'
          GroupCategory = 'Security'
        }
      )
    }
    Mock Get-ADServiceAccount {
      @(
        [PSCustomObject]@{
          SamAccountName = 'gmsa_web$'
          Name = 'gmsa_web$'
          DisplayName = 'gmsa_web$'
          SID = [PSCustomObject]@{ Value = 'S-1-5-21-100-200-300-3101' }
          DistinguishedName = 'CN=gmsa_web,CN=Managed Service Accounts,DC=corp,DC=example,DC=test'
          Enabled = $true
          Description = 'Web gMSA'
          ServicePrincipalName = @('HTTP/web.example.test')
          ObjectClass = 'msDS-GroupManagedServiceAccount'
          ObjectGUID = '22222222-2222-2222-2222-222222222222'
          PrimaryGroupID = '513'
        }
      )
    }
    Mock Get-ADGroupMember {
      param($Identity)
      if ($Identity.SamAccountName -eq 'GG_COMPUTERS') {
        return @(
          [PSCustomObject]@{
            SamAccountName = 'PC001$'
            SID = [PSCustomObject]@{ Value = 'S-1-5-21-100-200-300-4101' }
            objectClass = 'computer'
            distinguishedName = 'CN=PC001,DC=corp,DC=example,DC=test'
          }
        )
      }
      if ($Identity.SamAccountName -eq 'GG_FOREIGN') {
        return @(
          [PSCustomObject]@{
            SamAccountName = 'S-1-5-21-900-800-700-1501'
            SID = [PSCustomObject]@{ Value = 'S-1-5-21-900-800-700-1501' }
            objectClass = 'foreignSecurityPrincipal'
            distinguishedName = 'CN=S-1-5-21-900-800-700-1501,CN=ForeignSecurityPrincipals,DC=corp,DC=example,DC=test'
          }
        )
      }
      return @()
    }
    Mock Get-ADComputer {
      @(
        [PSCustomObject]@{
          SamAccountName = 'PC001$'
          Name = 'PC001'
          SID = [PSCustomObject]@{ Value = 'S-1-5-21-100-200-300-4101' }
          DistinguishedName = 'CN=PC001,DC=corp,DC=example,DC=test'
          Enabled = $true
          DNSHostName = 'pc001.example.test'
          Description = 'Workstation'
          ObjectGUID = '33333333-3333-3333-3333-333333333333'
          PrimaryGroupID = '515'
          ObjectClass = 'computer'
        },
        [PSCustomObject]@{
          SamAccountName = 'PC002$'
          Name = 'PC002'
          SID = [PSCustomObject]@{ Value = 'S-1-5-21-100-200-300-4102' }
          DistinguishedName = 'CN=PC002,DC=corp,DC=example,DC=test'
          Enabled = $true
          DNSHostName = 'pc002.example.test'
          Description = 'Ungrouped workstation'
          ObjectGUID = '44444444-4444-4444-4444-444444444444'
          PrimaryGroupID = '515'
          ObjectClass = 'computer'
        }
      )
    }
  }

  It 'uses the real primary group helper' {
    Get-PrimaryGroupSid -PrincipalSid 'S-1-5-21-100-200-300-1101' -PrimaryGroupID '513' |
      Should -Be 'S-1-5-21-100-200-300-513'
  }

  It 'fails closed when group member collection fails without AllowPartial' {
    Mock Get-ADGroupMember { throw 'membership failed' }
    $out = Join-Path $TestDrive 'ad.zip'
    { Invoke-ActiveDirectoryExport -ProviderName 'corp-ad' -Output $out -OperationTimeoutSeconds 0 } |
      Should -Throw '*collection failed*'
  }

  It 'writes an unknown completeness manifest when partial collection is allowed' {
    Mock Get-ADGroupMember { throw 'membership failed' }
    $out = Join-Path $TestDrive 'partial.zip'
    $expanded = Join-Path $TestDrive 'partial'

    Invoke-ActiveDirectoryExport -ProviderName 'corp-ad' -Output $out -AllowPartial -OperationTimeoutSeconds 0
    Expand-Archive -Path $out -DestinationPath $expanded

    Get-Content (Join-Path $expanded 'manifest.yaml') -Raw | Should -Match 'completeness: unknown'
    Get-Content (Join-Path $expanded 'manifest.yaml') -Raw | Should -Match 'collection_errors: 4'
    Import-Csv (Join-Path $expanded 'collection-errors.csv') | Should -HaveCount 4
  }



  It 'interrupts an AD operation that exceeds the configured timeout' {
    $elapsed = [System.Diagnostics.Stopwatch]::StartNew()
    {
      Invoke-AdOperationWithTimeout -Operation 'Get-ADUser' -OperationTimeoutSeconds 1 -ScriptBlock {
        Start-Sleep -Seconds 10
        'completed'
      }
    } | Should -Throw '*exceeded timeout*'
    $elapsed.Stop()
    $elapsed.Elapsed.TotalSeconds | Should -BeLessThan 5
  }

  It 'allows an AD operation that completes before the configured timeout' {
    $result = Invoke-AdOperationWithTimeout -Operation 'Get-ADUser' -OperationTimeoutSeconds 2 -ScriptBlock {
      Start-Sleep -Milliseconds 200
      'completed'
    }
    $result | Should -Be 'completed'
  }

  It 'marks the export unknown and writes safe diagnostics when an AD operation times out' {
    Mock Invoke-AdCollectorOperation {
      param($Operation, $ScriptBlock, $ArgumentList, $OperationTimeoutSeconds)
      if ($Operation -eq 'Get-ADUser') {
        throw [System.TimeoutException]::new("Active Directory operation 'Get-ADUser' exceeded timeout of 1 second(s)")
      }
      & $ScriptBlock @ArgumentList
    }
    $out = Join-Path $TestDrive 'timeout-partial.zip'
    $expanded = Join-Path $TestDrive 'timeout-partial'

    Invoke-ActiveDirectoryExport -ProviderName 'corp-ad' -Output $out -AllowPartial -OperationTimeoutSeconds 1
    Expand-Archive -Path $out -DestinationPath $expanded

    $manifest = Get-Content (Join-Path $expanded 'manifest.yaml') -Raw
    $errors = Import-Csv (Join-Path $expanded 'collection-errors.csv')
    $rawErrors = Get-Content (Join-Path $expanded 'collection-errors.csv') -Raw

    $manifest | Should -Match 'completeness: unknown'
    $errors | Where-Object { $_.Operation -eq 'Get-ADUser -Filter *' } | Should -HaveCount 1
    $rawErrors | Should -Match 'exceeded timeout'
    $rawErrors | Should -Not -Match 'password|secret|credential|token'
  }


  It 'exports gMSA, all computers, dates, FSP SID and primary group memberships through the real exporter' {
    $out = Join-Path $TestDrive 'full.zip'
    $expanded = Join-Path $TestDrive 'full'

    Invoke-ActiveDirectoryExport -ProviderName 'corp-ad' -Output $out -AllowPartial -OperationTimeoutSeconds 0
    Expand-Archive -Path $out -DestinationPath $expanded

    $users = Import-Csv (Join-Path $expanded 'users.csv')
    $serviceAccounts = Import-Csv (Join-Path $expanded 'service_accounts.csv')
    $computers = Import-Csv (Join-Path $expanded 'computers.csv')
    $memberships = Import-Csv (Join-Path $expanded 'memberships.csv')

    $users[0].AccountExpirationDate | Should -Match '^2026-01-02T03:04:05\.0000000Z$'
    $serviceAccounts[0].ObjectClass | Should -Be 'msDS-GroupManagedServiceAccount'
    $serviceAccounts[0].PrimaryGroupID | Should -Be '513'
    $computers | Should -HaveCount 2
    ($computers | Where-Object { $_.SamAccountName -eq 'PC001$' }).PrimaryGroupID | Should -Be '515'
    ($computers | Where-Object { $_.SamAccountName -eq 'PC002$' }).PrimaryGroupID | Should -Be '515'
    ($memberships | Where-Object { $_.MemberSID -eq 'S-1-5-21-900-800-700-1501' }).MemberType |
      Should -Be 'foreignSecurityPrincipal'
    ($memberships | Where-Object { $_.Member -eq 'gmsa_web$' -and $_.MembershipType -eq 'primary_group' }).GroupSID |
      Should -Be 'S-1-5-21-100-200-300-513'
    ($memberships | Where-Object { $_.Member -eq 'PC001$' -and $_.MembershipType -eq 'primary_group' }).GroupSID |
      Should -Be 'S-1-5-21-100-200-300-515'
    ($memberships | Where-Object { $_.Member -eq 'PC002$' -and $_.MembershipType -eq 'primary_group' }).GroupSID |
      Should -Be 'S-1-5-21-100-200-300-515'
    Get-Content (Join-Path $expanded 'manifest.yaml') -Raw | Should -Match 'computers: 2'
    Get-Content (Join-Path $expanded 'manifest.yaml') -Raw | Should -Match 'completeness: full'
  }
}
