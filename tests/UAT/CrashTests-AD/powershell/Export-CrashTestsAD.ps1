param(
  [string]$ProviderName = "crashtests-ad",
  [string]$Output,
  [string]$Server,
  [int]$OperationTimeoutSeconds = 300,
  [switch]$AllowPartial
)

$ErrorActionPreference = "Stop"

function Resolve-RepositoryRoot {
  $current = Split-Path -Parent $PSScriptRoot
  while ($current) {
    if (Test-Path (Join-Path $current "pyproject.toml")) {
      return $current
    }
    $parent = Split-Path -Parent $current
    if ($parent -eq $current) { break }
    $current = $parent
  }
  throw "Cannot locate repository root from $PSScriptRoot"
}

$repoRoot = Resolve-RepositoryRoot
$exporter = Join-Path $repoRoot "exporters/active-directory/export-active-directory.ps1"
if (-not (Test-Path $exporter)) {
  throw "Active Directory exporter not found: $exporter"
}

if (-not $Output) {
  $artifactDir = Join-Path $repoRoot "tests/UAT/CrashTests-AD/artifacts"
  New-Item -ItemType Directory -Force -Path $artifactDir | Out-Null
  $Output = Join-Path $artifactDir "ad-export.zip"
}

. $exporter

Invoke-ActiveDirectoryExport `
  -ProviderName $ProviderName `
  -Output $Output `
  -Server $Server `
  -OperationTimeoutSeconds $OperationTimeoutSeconds `
  -AllowPartial:$AllowPartial

Write-Host "CrashTests-AD export written to $Output"
