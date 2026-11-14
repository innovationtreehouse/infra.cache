#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Install facility cache client settings on Windows.

.DESCRIPTION
  - Delivery Optimization: DHCP option 235 only (no static cache host)
  - Docker Hub registry-mirrors (engine falls back to docker.io off-site)
  - pip / uv / npm: enabled only while cache.facility.innovationtreehouse.org
    resolves to 10.41.1.50 and the service port answers
#>
[CmdletBinding()]
param(
    [switch]$NoDocker,
    [switch]$NoRestartDocker
)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Split-Path -Parent $here
$dest = Join-Path $env:ProgramData 'FacilityCache'
Import-Module (Join-Path $here 'FacilityCache.psm1') -Force
$script:FcStepN = 7
# Release zips ship a generated VERSION file; a git checkout has none — the
# version lives in git tags. Fall back to git describe, then a dev marker.
$verFile = Join-Path $root 'VERSION'
$ver = '0.0.0-dev'
if (Test-Path $verFile) {
    $ver = (Get-Content $verFile -Raw).Trim().TrimStart('v')
} elseif (Get-Command git -ErrorAction SilentlyContinue) {
    # Child scope with Continue: under Stop, PS 5.1 turns a native command's
    # redirected stderr ("fatal: not a git repository") into a terminating error.
    $described = & { $ErrorActionPreference = 'Continue'; & git -C $root describe --tags --match 'v*' --dirty 2>$null }
    if ($LASTEXITCODE -eq 0 -and $described) { $ver = ([string]$described).Trim().TrimStart('v') }
}
# Before anything (even the log) touches it: SYSTEM tasks run code and read
# config/token from here, so non-admins must not own or create anything in it.
$hardenNotes = @(Protect-FacilityCacheInstallDir)
Write-FcHeader 'facility-cache-client' "install  v$ver"
foreach ($n in $hardenNotes) { Write-FcWarn $n }

Write-FcStep 'files' 'copying into ProgramData'
foreach ($name in @(
    'FacilityCache.psm1',
    'FacilityCache-Apply.ps1',
    'FacilityCache-Update.ps1',
    'Install-FacilityCache.ps1',
    'Status-FacilityCache.ps1',
    'Treehouse-Git.ps1',
    'Uninstall-FacilityCache.ps1'
)) {
    $src = Join-Path $here $name
    if (Test-Path $src) {
        Copy-Item -LiteralPath $src -Destination (Join-Path $dest $name) -Force
    }
}
$srcDefaults = Join-Path $root 'defaults.json'
if (Test-Path $srcDefaults) {
    Copy-Item -LiteralPath $srcDefaults -Destination (Join-Path $dest 'defaults.json') -Force
}
$srcShared = Join-Path $root 'shared.gitconfig'
if (Test-Path $srcShared) {
    Copy-Item -LiteralPath $srcShared -Destination (Join-Path $dest 'shared.gitconfig') -Force
}
# SystemRoot is on every PATH for every user from the first logon, and members
# cannot modify it, so no PATH edits are needed. Git Bash does not apply PATHEXT:
# there the command is `treehouse-git.cmd`. powershell.exe by absolute path: cmd
# would otherwise pick up a powershell.exe in the current directory (a clone).
@(
    '@echo off',
    '"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%ProgramData%\FacilityCache\Treehouse-Git.ps1" %*'
) | Set-Content -LiteralPath (Join-Path $env:SystemRoot 'treehouse-git.cmd') -Encoding ASCII
# Always record the resolved version (zip VERSION, git describe, or dev).
$ver | Set-Content -LiteralPath (Join-Path $dest 'VERSION') -Encoding ASCII

$cfgPath = Join-Path $dest 'config.json'
if (-not (Test-Path $cfgPath)) {
    '{}' | Set-Content -LiteralPath $cfgPath -Encoding ASCII
}
Write-FcStepOk "v$ver -> $dest"
Import-Module (Join-Path $dest 'FacilityCache.psm1') -Force

Write-FcStep 'gh' 'GitHub CLI'
if (Sync-FacilityCacheGitHubCli) {
    Write-FcStepOk 'gh'
} else {
    Write-FcWarn 'gh install skipped — attestations may be unavailable'
}

Write-FcStep 'delivery-opt' 'DHCP option 235'
Set-DeliveryOptimizationDhcpDiscovery
Write-FcStepOk 'DOCacheHostSource=2 (no static host)'

Write-FcStep 'docker' 'registry-mirrors'
if (-not $NoDocker) {
    $changed = Merge-DockerDaemonJson
    if ($changed) {
        if (-not $NoRestartDocker) {
            $svc = Get-Service -Name 'docker' -ErrorAction SilentlyContinue
            if ($svc -and $svc.Status -eq 'Running') {
                Restart-Service docker
                Write-FcStepOk 'mirrors written · docker restarted'
            } else {
                Write-FcStepOk 'mirrors written · restart Docker Desktop if you use it'
            }
        } else {
            Write-FcStepOk 'mirrors written · restart docker when convenient'
        }
    } else {
        Write-FcStepOk 'already configured (or Docker not installed)'
    }
} else {
    Write-Host '  skipped --NoDocker' -ForegroundColor DarkGray
}

Write-FcStep 'apply' 'LAN drop-ins'
Invoke-FacilityCacheApply
Write-FcStepOk 'pip/npm/uv follow the facility LAN'

Write-FcStep 'tasks' 'apply + update + session reset'
# Absolute, so no PATH entry or working directory can supply the interpreter.
$powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$taskName = 'FacilityCache-Apply'
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

$arg = "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$(Join-Path $dest 'FacilityCache-Apply.ps1')`""
$action = New-ScheduledTaskAction -Execute $powershell -Argument $arg
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
# Default task settings skip runs on battery: a laptop that leaves the facility
# unplugged would keep pip/npm pointed at the cache, and a missed session reset
# would leave a member signed in. StartWhenAvailable catches up a missed daily run.
$taskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
$repeat = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
    -RepetitionInterval (New-TimeSpan -Minutes 5) `
    -RepetitionDuration (New-TimeSpan -Days 3650)
$triggers = @(
    (New-ScheduledTaskTrigger -AtStartup),
    $repeat
)

try {
    $eventXml = @'
<QueryList>
  <Query Id="0" Path="Microsoft-Windows-NetworkProfile/Operational">
    <Select Path="Microsoft-Windows-NetworkProfile/Operational">*[System[(EventID=10000 or EventID=10001)]]</Select>
  </Query>
</QueryList>
'@
    $eventClass = Get-CimClass -ClassName MSFT_TaskEventTrigger -Namespace root/Microsoft/Windows/TaskScheduler
    $cimTrigger = New-CimInstance -CimClass $eventClass -ClientOnly
    $cimTrigger.Enabled = $true
    $cimTrigger.Subscription = $eventXml
    $triggers += $cimTrigger
} catch {
    Write-Host 'Could not register a network-change trigger; using boot + 5-minute timer only.'
}

Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $triggers -Principal $principal -Settings $taskSettings `
    -Description 'Enable Innovation Treehouse cache drop-ins only on the facility LAN' | Out-Null

$updateName = 'FacilityCache-Update'
Unregister-ScheduledTask -TaskName $updateName -Confirm:$false -ErrorAction SilentlyContinue
$updateArg = "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$(Join-Path $dest 'FacilityCache-Update.ps1')`""
$updateAction = New-ScheduledTaskAction -Execute $powershell -Argument $updateArg
# -RandomDelay must be given to the cmdlet: assigning the property afterwards
# serializes the TimeSpan as '00:30:00' instead of ISO8601 'PT30M' on some
# Windows builds (seen on servercore ltsc2022), and Register-ScheduledTask
# then rejects the task XML with HRESULT 0x80041318.
$updateDaily = New-ScheduledTaskTrigger -Daily -At 3:17am -RandomDelay (New-TimeSpan -Minutes 30)
$updateTriggers = @(
    (New-ScheduledTaskTrigger -AtStartup),
    $updateDaily
)
Register-ScheduledTask -TaskName $updateName -Action $updateAction -Trigger $updateTriggers -Principal $principal -Settings $taskSettings `
    -Description 'Install newer facility-cache-client GitHub Releases' | Out-Null

# Shared-machine GitHub session wipe (no-op when no session exists). Startup,
# any logon, and logoff only: lock/unlock and reconnect must NOT reset it.
$resetName = 'FacilityCache-SessionReset'
Unregister-ScheduledTask -TaskName $resetName -Confirm:$false -ErrorAction SilentlyContinue
$resetArg = "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -Command `"Import-Module '$(Join-Path $dest 'FacilityCache.psm1')'; Reset-TreehouseGitSession`""
$resetAction = New-ScheduledTaskAction -Execute $powershell -Argument $resetArg
$resetTriggers = @(
    (New-ScheduledTaskTrigger -AtStartup),
    (New-ScheduledTaskTrigger -AtLogOn)
)
try {
    $logoffXml = @'
<QueryList>
  <Query Id="0" Path="System">
    <Select Path="System">*[System[Provider[@Name='Microsoft-Windows-Winlogon'] and EventID=7002]]</Select>
  </Query>
</QueryList>
'@
    $logoffClass = Get-CimClass -ClassName MSFT_TaskEventTrigger -Namespace root/Microsoft/Windows/TaskScheduler
    $logoffTrigger = New-CimInstance -CimClass $logoffClass -ClientOnly
    $logoffTrigger.Enabled = $true
    $logoffTrigger.Subscription = $logoffXml
    $resetTriggers += $logoffTrigger
} catch {
    Write-Host 'Could not register a logoff trigger; session resets at startup, logon and expiry only.'
}
Register-ScheduledTask -TaskName $resetName -Action $resetAction -Trigger $resetTriggers -Principal $principal `
    -Settings $taskSettings -Description 'Sign shared-machine members out of GitHub at startup, logon and logoff' | Out-Null
Write-FcStepOk 'FacilityCache-Apply 5m · FacilityCache-Update daily · FacilityCache-SessionReset logon/logoff'

if ((Get-FacilityCacheConfig).SharedMachine -eq $true -and -not (Get-FcTrustedCommand git)) {
    Write-FcWarn 'SharedMachine is on but Git for Windows is not installed machine-wide: treehouse-git signin will refuse and git is not routed through the member sign-in until it is (the next apply picks it up). See docs/SHARED-MACHINES.md.'
}
Write-FcFinish -Ok $true -Message "v$ver ready"
Write-FcNote 'Status-FacilityCache.ps1     dashboard'
Write-FcNote 'FacilityCache-Update.ps1     GitHub Releases'
Write-FcNote 'Show-FacilityCacheLog        fetchable event log'
