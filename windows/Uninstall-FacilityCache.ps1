#Requires -RunAsAdministrator
[CmdletBinding()]
param([switch]$KeepDocker)

$ErrorActionPreference = 'Stop'
$dest = Join-Path $env:ProgramData 'FacilityCache'
$module = Join-Path $dest 'FacilityCache.psm1'
if (Test-Path $module) {
    Import-Module $module -Force
    Write-FcHeader 'facility-cache-client' 'uninstall'
    $script:FcStepN = 5
    Write-FcStep 'policy' 'Delivery Optimization'
    Remove-DeliveryOptimizationDhcpDiscovery
    Write-FcStepOk 'DOCacheHostSource removed'
    Write-FcStep 'docker' 'registry-mirrors'
    if (-not $KeepDocker) {
        Remove-DockerMirrors
        Write-FcStepOk 'facility mirrors stripped'
    } else {
        Write-FcStepOk 'kept (-KeepDocker)'
    }
} else {
    Write-Host '  facility-cache-client  uninstall' -ForegroundColor Cyan
}

if (-not (Get-Command Write-FcStep -ErrorAction SilentlyContinue)) {
    function Write-FcStep { param($Name, $Message = '') Write-Host "  * $Name  $Message" }
    function Write-FcStepOk { param($Message = 'done') Write-Host "  + $Message" -ForegroundColor Green }
    function Write-FcFinish { param([bool]$Ok = $true, [string]$Message = '') Write-Host "  $Message" }
    function Write-FcNote { param($Message) Write-Host "    $Message" -ForegroundColor DarkGray }
}

Write-FcStep 'tasks' 'scheduled tasks'
# Stop a mid-flight run first — an Apply task still executing after Unregister
# could rewrite env vars / pip.ini / npm's registry after the cleanup below runs.
Stop-ScheduledTask -TaskName 'FacilityCache-Apply' -ErrorAction SilentlyContinue
Stop-ScheduledTask -TaskName 'FacilityCache-Update' -ErrorAction SilentlyContinue
Stop-ScheduledTask -TaskName 'FacilityCache-SessionReset' -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName 'FacilityCache-Apply' -Confirm:$false -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName 'FacilityCache-Update' -Confirm:$false -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName 'FacilityCache-SessionReset' -Confirm:$false -ErrorAction SilentlyContinue
Write-FcStepOk 'Apply + Update + SessionReset unregistered'

# Shared-machine GitHub sign-in: delete every profile's session, drop
# the user-scope env vars (also from hives of accounts not logged on) and the
# system git include, while the module is still loaded.
if (Get-Command Disable-TreehouseGitSharedMachine -ErrorAction SilentlyContinue) {
    Disable-TreehouseGitSharedMachine -IncludeUnloaded
}
Remove-Item -LiteralPath (Join-Path $env:SystemRoot 'treehouse-git.cmd') -Force -ErrorAction SilentlyContinue

foreach ($name in @(
    'PIP_INDEX_URL', 'PIP_TRUSTED_HOST', 'UV_INDEX_URL', 'UV_INSECURE_HOST', 'NPM_CONFIG_REGISTRY',
    'GH_CONFIG_DIR', 'GIT_CONFIG_GLOBAL'
)) {
    [Environment]::SetEnvironmentVariable($name, $null, 'Machine')
}

foreach ($path in @(
    (Join-Path $env:ProgramData 'pip\pip.ini'),
    (Join-Path $env:ProgramData 'uv\uv.toml')
)) {
    if (Test-Path $path) {
        $head = Get-Content -LiteralPath $path -TotalCount 2 -ErrorAction SilentlyContinue
        if ($head -match 'facility-cache-managed') {
            Remove-Item -LiteralPath $path -Force
        }
    }
}

$npmCmd = Get-Command npm -ErrorAction SilentlyContinue
if ($npmCmd) {
    # Only clear the global npm registry if it's still pointed at ours — never
    # blow away a registry someone else configured.
    $npmRegistry = $null
    if (Get-Command Get-FacilityCacheConfig -ErrorAction SilentlyContinue) {
        $fcCfg = Get-FacilityCacheConfig
        $npmRegistry = "http://$($fcCfg.CacheHost):$($fcCfg.NpmPort)/"
    }
    # Continue in a child scope: npm warnings on stderr must not abort uninstall under Stop (PS 5.1).
    & {
        $ErrorActionPreference = 'Continue'
        $currentRegistry = (& npm config get registry --location=global 2>$null)
        if ($npmRegistry -and $currentRegistry -and ([string]$currentRegistry).Trim() -eq $npmRegistry) {
            & npm config delete registry --location=global 2>$null
        }
    }
}

$logHint = $null
if (Get-Command Get-FacilityCacheLogPath -ErrorAction SilentlyContinue) {
    $logHint = Get-FacilityCacheLogPath
}

Write-FcStep 'files' $dest
if (Test-Path $dest) {
    # logs\ and config.json live inside the same ProgramData folder as the binaries —
    # keep them (config.json mirrors Linux keeping /etc/facility-cache/config; logs\
    # mirrors Linux leaving /var/log/facility-cache/ alone).
    Get-ChildItem -LiteralPath $dest -Force |
        Where-Object { $_.Name -notin @('logs', 'config.json') } |
        Remove-Item -Recurse -Force
}
Write-FcStepOk 'client files removed'

Write-FcStep 'keep' 'local config'
Write-FcStepOk "$(Join-Path $dest 'config.json') left in place"

if (Get-Command Write-FcFinish -ErrorAction SilentlyContinue) {
    Write-FcFinish -Ok $true -Message 'uninstalled'
    if ($logHint) { Write-FcNote "logs remain at $logHint" }
} else {
    Write-Host 'Uninstalled facility-cache client.'
}
