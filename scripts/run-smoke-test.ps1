# -----------------------------------------------------------------------------
# Runner — loads scripts\smoke-test.config.ps1 and runs the four-pillar test.
# Just run:  .\scripts\run-smoke-test.ps1
# -----------------------------------------------------------------------------

$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path

$configPath = Join-Path $here "smoke-test.config.ps1"
$testPath   = Join-Path $here "agentguard-four-pillar-smoke-test.ps1"

if (-not (Test-Path $configPath)) {
  Write-Error "Config not found: $configPath  (copy from smoke-test.config.ps1 and fill in your keys)"
  exit 1
}

. $configPath

if ($Config.PublicKey -like "*REPLACE-ME*" -or $Config.SecretKey -like "*REPLACE-ME*") {
  Write-Error "Edit $configPath and set your real PublicKey / SecretKey first."
  exit 1
}

$params = @{
  BaseUrl        = $Config.BaseUrl
  PublicKey      = $Config.PublicKey
  SecretKey      = $Config.SecretKey
  Environment    = $Config.Environment
  TimeoutSeconds = $Config.TimeoutSeconds
}
if ($Config.SecondaryPublicKey) { $params.SecondaryPublicKey = $Config.SecondaryPublicKey }
if ($Config.SecondarySecretKey) { $params.SecondarySecretKey = $Config.SecondarySecretKey }

& $testPath @params
exit $LASTEXITCODE
