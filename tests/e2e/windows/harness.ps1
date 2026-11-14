# Windows client end-to-end harness. Windows PowerShell 5.1, must run ELEVATED
# (a Windows container's ContainerAdministrator qualifies). Exercises the real
# install / apply / update / uninstall flows including scheduled tasks, HKLM
# and machine-scope environment variables — run only on a throwaway machine.
param(
    [Parameter(Mandatory = $true)][string]$CacheHost,
    [Parameter(Mandatory = $true)][string]$ExpectedIp,
    [Parameter(Mandatory = $true)][string]$RepoRoot
)
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$script:pass = 0; $script:fail = 0
function Check([string]$name, [bool]$cond, [string]$detail = '') {
    if ($cond) { $script:pass++; Write-Host "PASS  $name  $detail" } else { $script:fail++; Write-Host "FAIL  $name  $detail" }
}
function Section($t) { Write-Host ''; Write-Host "##### $t" }
function Get-MachineEnvVar([string]$n) { [Environment]::GetEnvironmentVariable($n, 'Machine') }
function Get-UserEnvVar([string]$n) { [Environment]::GetEnvironmentVariable($n, 'User') }
$fcDir = Join-Path $env:ProgramData 'FacilityCache'
# Any allow ACE granting write/delete/ACL rights to someone other than SYSTEM/Administrators.
function Get-NonAdminWriters([string]$p) {
    $w = [Security.AccessControl.FileSystemRights]'WriteData, AppendData, WriteExtendedAttributes, WriteAttributes, Delete, DeleteSubdirectoriesAndFiles, ChangePermissions, TakeOwnership'
    @((Get-Acl -LiteralPath $p).GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | Where-Object {
        $_.AccessControlType -eq 'Allow' -and @('S-1-5-18', 'S-1-5-32-544') -notcontains $_.IdentityReference.Value -and ($_.FileSystemRights -band $w)
    } | ForEach-Object { "$p $($_.IdentityReference.Value) $($_.FileSystemRights)" })
}
function Write-FcConfig($extra) {
    $cfg = @{ CacheHost = $CacheHost; ExpectedIp = $ExpectedIp }
    if ($extra) { foreach ($k in $extra.Keys) { $cfg[$k] = $extra[$k] } }
    $cfg | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $env:ProgramData 'FacilityCache\config.json') -Encoding ASCII
}

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$admin = (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Section 'T0 environment'
Check 'elevated' $admin "$($id.Name)"
if (-not $admin) { Write-Host 'RESULT pass=0 fail=1 (not elevated)'; exit 1 }
try { Start-Service Schedule -ErrorAction SilentlyContinue } catch { }
$ips = [System.Net.Dns]::GetHostAddresses($CacheHost) | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | ForEach-Object ToString
Check "CacheHost resolves to ExpectedIp" ($ips -contains $ExpectedIp) ($ips -join ',')
$tcp = New-Object Net.Sockets.TcpClient; $iar = $tcp.BeginConnect($ExpectedIp, 3141, $null, $null)
Check 'cache port 3141 reachable' ($iar.AsyncWaitHandle.WaitOne(3000) -and ($tcp.Connected)); $tcp.Close()

Section 'T1 install (real scheduled tasks, HKLM, machine env)'
New-Item -ItemType Directory -Force -Path (Join-Path $env:ProgramData 'FacilityCache') | Out-Null
Write-FcConfig $null
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $RepoRoot 'windows\Install-FacilityCache.ps1') -NoRestartDocker
Check 'installer exit 0' ($LASTEXITCODE -eq 0) "exit=$LASTEXITCODE"
foreach ($f in 'FacilityCache.psm1', 'FacilityCache-Apply.ps1', 'FacilityCache-Update.ps1', 'VERSION', 'defaults.json') {
    Check "installed: $f" (Test-Path (Join-Path $env:ProgramData "FacilityCache\$f"))
}
Check 'task FacilityCache-Apply registered' ([bool](Get-ScheduledTask -TaskName 'FacilityCache-Apply' -ErrorAction SilentlyContinue))
Check 'task FacilityCache-Update registered' ([bool](Get-ScheduledTask -TaskName 'FacilityCache-Update' -ErrorAction SilentlyContinue))
$fcAcl = Get-Acl -LiteralPath $fcDir
Check 'install dir owner is Administrators' ($fcAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value -eq 'S-1-5-32-544') $fcAcl.Owner
Check 'install dir ACL protected (not inherited from ProgramData)' $fcAcl.AreAccessRulesProtected
$writers = @(@($fcDir) + @(Get-ChildItem -LiteralPath $fcDir -Recurse -Force | ForEach-Object FullName) | ForEach-Object { Get-NonAdminWriters $_ })
Check 'non-admins cannot write anything in the install dir' ($writers.Count -eq 0) ($writers -join '; ')
$exe = Get-ScheduledTask -TaskName 'FacilityCache-Apply' -ErrorAction SilentlyContinue | ForEach-Object { $_.Actions[0].Execute }
Check 'task runs powershell.exe by absolute path' ($exe -eq (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe')) $exe
$do = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization' -ErrorAction SilentlyContinue
Check 'DO: DOCacheHostSource=2, no static host' ($do.DOCacheHostSource -eq 2 -and -not $do.DOCacheHost)
Check 'machine env PIP_INDEX_URL set' ((Get-MachineEnvVar 'PIP_INDEX_URL') -eq "http://${CacheHost}:3141/root/pypi/+simple/") (Get-MachineEnvVar 'PIP_INDEX_URL')
Check 'machine env UV_INSECURE_HOST set' ((Get-MachineEnvVar 'UV_INSECURE_HOST') -eq $CacheHost)
Check 'pip.ini written' (Test-Path (Join-Path $env:ProgramData 'pip\pip.ini'))
Check 'uv.toml written' (Test-Path (Join-Path $env:ProgramData 'uv\uv.toml'))
$dj = Join-Path $env:ProgramData 'Docker\config\daemon.json'
$djOk = $false
if (Test-Path $dj) {
    $j = Get-Content $dj -Raw | ConvertFrom-Json
    $djOk = ($j.'registry-mirrors' -contains "http://${CacheHost}:5000") -and ($j.'insecure-registries' -contains "${CacheHost}:5001")
}
Check 'daemon.json mirrors written' $djOk

Section 'T2 status + module probes (on-site)'
Import-Module (Join-Path $env:ProgramData 'FacilityCache\FacilityCache.psm1') -Force
$st = Get-FacilityCacheStatus
Check 'DnsOk' $st.DnsOk "resolved=$($st.Resolved)"
Check 'pypi port on' ([bool]$st.Ports['pypi'])
Check 'npm port on' ([bool]$st.Ports['npm'])
Show-FacilityCacheDashboard
$r = Invoke-WebRequest -UseBasicParsing -Uri (Get-MachineEnvVar 'PIP_INDEX_URL') -TimeoutSec 10
Check 'pip index URL served by fake cache' ($r.StatusCode -eq 200)

Section 'T3 wrong address (negative)'
Write-FcConfig @{ ExpectedIp = '10.9.9.9' }
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $env:ProgramData 'FacilityCache\FacilityCache-Apply.ps1')
Check 'apply exit 0' ($LASTEXITCODE -eq 0)
Check 'pip.ini removed' (-not (Test-Path (Join-Path $env:ProgramData 'pip\pip.ini')))
Check 'machine env cleared' (-not (Get-MachineEnvVar 'PIP_INDEX_URL'))
Import-Module (Join-Path $env:ProgramData 'FacilityCache\FacilityCache.psm1') -Force
Check 'status: wrong address' ((Get-FacilityCacheStatus).DnsOk -eq $false)

Section 'T4 off-site NXDOMAIN (negative)'
Write-FcConfig @{ CacheHost = 'cache.nonexistent-offsite.invalid' }
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $env:ProgramData 'FacilityCache\FacilityCache-Apply.ps1')
Check 'apply exit 0' ($LASTEXITCODE -eq 0)
Check 'uv.toml removed' (-not (Test-Path (Join-Path $env:ProgramData 'uv\uv.toml')))

Section 'T5 back on-site; foreign file protection'
Write-FcConfig $null
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $env:ProgramData 'FacilityCache\FacilityCache-Apply.ps1')
Check 'drop-ins re-applied' (Test-Path (Join-Path $env:ProgramData 'pip\pip.ini'))
'# not ours' | Set-Content (Join-Path $env:ProgramData 'pip\pip.ini') -Encoding ASCII
Write-FcConfig @{ CacheHost = 'cache.nonexistent-offsite.invalid' }
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $env:ProgramData 'FacilityCache\FacilityCache-Apply.ps1')
Check 'foreign pip.ini left alone off-site' (Test-Path (Join-Path $env:ProgramData 'pip\pip.ini'))
Remove-Item (Join-Path $env:ProgramData 'pip\pip.ini') -Force
Write-FcConfig $null

Section 'T6 update: -Check, repo-id pin refusal (negative), full update (real GitHub + attestation)'
'1.0.0' | Set-Content (Join-Path $env:ProgramData 'FacilityCache\VERSION') -Encoding ASCII
& powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Import-Module '$env:ProgramData\FacilityCache\FacilityCache.psm1'; Update-FacilityCacheClient -Check" | Tee-Object -Variable chk | Out-Host
Check 'update -Check exit 0' ($LASTEXITCODE -eq 0)
Check 'reports update available' ([bool]($chk -match 'update available'))
Write-FcConfig @{ GitHubRepoId = 999 }
& powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Import-Module '$env:ProgramData\FacilityCache\FacilityCache.psm1'; Update-FacilityCacheClient -Check" | Out-Host
Check 'repo-id pin mismatch refuses (nonzero exit)' ($LASTEXITCODE -ne 0)
Write-FcConfig $null
& powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Import-Module '$env:ProgramData\FacilityCache\FacilityCache.psm1'; Update-FacilityCacheClient" | Tee-Object -Variable upd | Out-Host
$updExit = $LASTEXITCODE
$state = Get-Content (Join-Path $env:ProgramData 'FacilityCache\state.json') -Raw | ConvertFrom-Json
$v = (Get-Content (Join-Path $env:ProgramData 'FacilityCache\VERSION') -Raw).Trim()
# The latest release (v1.0.3 at the time of writing) was built before the repo
# rename: its certificate names innovationtreehouse/cache. The check is by
# repo/owner id + release.yml at refs/tags/v<version>, so it must still verify.
Check 'full update: clean (state=updated, VERSION advanced)' ($updExit -eq 0 -and $state.last_result -eq 'updated' -and $v -ne '1.0.0') "exit=$updExit result=$($state.last_result) now $v"
Check 'attestation verified by repo id during update' ($state.attestation -eq 'verified' -and [bool]($upd -match 'verified')) "attestation=$($state.attestation)"
Check 'update re-registered tasks' ([bool](Get-ScheduledTask -TaskName 'FacilityCache-Apply' -ErrorAction SilentlyContinue))

Section 'T7 install-dir hardening + shared machine: per-user gh session, env, reset task, shim'
# Plant what a non-admin could have left in an unhardened install dir.
$planted = Join-Path $fcDir 'planted.ps1'
'# planted' | Set-Content -LiteralPath $planted -Encoding ASCII
& icacls.exe $planted /setowner '*S-1-5-32-545' | Out-Null
$plantedOwned = ($LASTEXITCODE -eq 0)
$junkTarget = 'C:\fc-e2e-junk-target'
New-Item -ItemType Directory -Force -Path $junkTarget | Out-Null
'keep' | Set-Content -LiteralPath (Join-Path $junkTarget 'keep.txt') -Encoding ASCII
New-Item -ItemType Junction -Path (Join-Path $fcDir 'junk-link') -Target $junkTarget | Out-Null
'not-a-real-token' | Set-Content -LiteralPath (Join-Path $fcDir 'github-token') -Encoding ASCII
# The pre-per-user machine-wide session dir and its machine-scope env.
$oldSess = Join-Path $fcDir 'gh-session'
New-Item -ItemType Directory -Force -Path (Join-Path $oldSess 'gh') | Out-Null
[Environment]::SetEnvironmentVariable('GH_CONFIG_DIR', (Join-Path $oldSess 'gh'), 'Machine')
[Environment]::SetEnvironmentVariable('GIT_CONFIG_GLOBAL', (Join-Path $oldSess 'gitconfig'), 'Machine')
# T6 installed the latest RELEASE; reinstall this tree so the feature under test is present.
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $RepoRoot 'windows\Install-FacilityCache.ps1') -NoRestartDocker -NoDocker
Check 'reinstall from tree exit 0' ($LASTEXITCODE -eq 0) "exit=$LASTEXITCODE"
if ($plantedOwned) { Check 'file owned by a non-admin removed from install dir' (-not (Test-Path -LiteralPath $planted)) } else { Write-Host 'SKIP  could not set a non-admin owner on the planted file' }
Check 'planted junction removed, its target untouched' (-not (Test-Path -LiteralPath (Join-Path $fcDir 'junk-link')) -and (Test-Path -LiteralPath (Join-Path $junkTarget 'keep.txt')))
$tokAcl = Get-Acl -LiteralPath (Join-Path $fcDir 'github-token')
$tokOther = @($tokAcl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | Where-Object { @('S-1-5-18', 'S-1-5-32-544') -notcontains $_.IdentityReference.Value })
Check 'github-token readable by SYSTEM/Administrators only' ($tokAcl.AreAccessRulesProtected -and $tokOther.Count -eq 0)
Remove-Item -LiteralPath (Join-Path $fcDir 'github-token') -Force
Check 'old in-tree gh-session removed' (-not (Test-Path -LiteralPath $oldSess))
Check 'stale machine-scope GH_CONFIG_DIR / GIT_CONFIG_GLOBAL cleared' (-not (Get-MachineEnvVar 'GH_CONFIG_DIR') -and -not (Get-MachineEnvVar 'GIT_CONFIG_GLOBAL'))
$apply = Join-Path $fcDir 'FacilityCache-Apply.ps1'
$sess = Join-Path $env:USERPROFILE 'AppData\Local\FacilityCache\gh-session'
$include = (Join-Path $fcDir 'shared.gitconfig').Replace('\', '/')
Check 'installed: Treehouse-Git.ps1, shared.gitconfig' ((Test-Path (Join-Path $fcDir 'Treehouse-Git.ps1')) -and (Test-Path (Join-Path $fcDir 'shared.gitconfig')))
Check 'task FacilityCache-SessionReset registered' ([bool](Get-ScheduledTask -TaskName 'FacilityCache-SessionReset' -ErrorAction SilentlyContinue))
$shim = Join-Path $env:SystemRoot 'treehouse-git.cmd'
Check 'shim treehouse-git.cmd in SystemRoot' (Test-Path $shim)
Check 'shim runs powershell.exe by absolute path' ([bool]((Get-Content -LiteralPath $shim -Raw) -match '"%SystemRoot%\\System32\\WindowsPowerShell\\v1\.0\\powershell\.exe"'))
Check 'not shared by default: no user GH_CONFIG_DIR' (-not (Get-UserEnvVar 'GH_CONFIG_DIR'))
Write-FcConfig @{ SharedMachine = $true }
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $apply
Check 'apply (shared) exit 0' ($LASTEXITCODE -eq 0)
Check 'never machine scope: no machine GH_CONFIG_DIR / GIT_CONFIG_GLOBAL' (-not (Get-MachineEnvVar 'GH_CONFIG_DIR') -and -not (Get-MachineEnvVar 'GIT_CONFIG_GLOBAL'))
Check 'user env GH_CONFIG_DIR -> own profile' ((Get-UserEnvVar 'GH_CONFIG_DIR') -eq (Join-Path $sess 'gh')) (Get-UserEnvVar 'GH_CONFIG_DIR')
Check 'user env GIT_CONFIG_GLOBAL -> own profile' ((Get-UserEnvVar 'GIT_CONFIG_GLOBAL') -eq (Join-Path $sess 'gitconfig')) (Get-UserEnvVar 'GIT_CONFIG_GLOBAL')
if (Get-Command git -ErrorAction SilentlyContinue) {
    Check 'git system include added' (@(& git config --system --get-all include.path) -contains $include)
}
$runKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
$runVal = (Get-ItemProperty -LiteralPath $runKey -Name FacilityCacheGitHubSignIn -ErrorAction SilentlyContinue).FacilityCacheGitHubSignIn
Check 'login sign-in prompt registered (HKLM Run, absolute paths)' ([bool]($runVal -match '^"[A-Z]:\\Windows\\System32\\WindowsPowerShell\\v1\.0\\powershell\.exe" .*-File "[A-Z]:\\ProgramData\\FacilityCache\\Treehouse-Git\.ps1" welcome$')) $runVal
$hintOut = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $fcDir 'Treehouse-Git.ps1') hint
Check 'treehouse-git hint (no session)' ($hintOut -eq 'Not signed in to GitHub. Run: treehouse-git signin') "$hintOut"
Write-FcConfig @{ SharedMachine = $true; SignInPromptAtLogin = $false }
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $apply
Check 'SignInPromptAtLogin false removes the login prompt' (-not (Get-ItemProperty -LiteralPath $runKey -Name FacilityCacheGitHubSignIn -ErrorAction SilentlyContinue))
Write-FcConfig @{ SharedMachine = $true }
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $apply
New-Item -ItemType Directory -Force -Path (Join-Path $sess 'gh') | Out-Null
# Deliberately NOT token-shaped, so the reset posts nothing to GitHub.
"github.com:`n    user: e2e`n    oauth_token: not-a-real-token" | Set-Content (Join-Path $sess 'gh\hosts.yml') -Encoding ASCII
'[alias]' | Set-Content (Join-Path $sess 'gitconfig') -Encoding ASCII
'1' | Set-Content (Join-Path $sess 'expires') -Encoding ASCII
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $apply
Check 'apply (expired session) exit 0' ($LASTEXITCODE -eq 0)
Check 'expired session dir removed' (-not (Test-Path -LiteralPath $sess))
New-Item -ItemType Directory -Force -Path $sess | Out-Null
([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() + 3600) | Set-Content (Join-Path $sess 'expires') -Encoding ASCII
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $apply
Check 'live session kept by apply' (Test-Path -LiteralPath (Join-Path $sess 'expires'))
& powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Import-Module '$fcDir\FacilityCache.psm1'; if (-not (Reset-TreehouseGitSession)) { exit 1 }"
Check 'reset (logon/logoff/startup task command) exit 0, session removed' ($LASTEXITCODE -eq 0 -and -not (Test-Path -LiteralPath $sess))
Check 'sessions are only deleted, never revoked on GitHub (no revoke call in the module)' (-not (Select-String -LiteralPath (Join-Path $fcDir 'FacilityCache.psm1') -SimpleMatch 'api.github.com/credentials' -Quiet))
# A member-planted junction inside the session must be removed, never followed.
$ghTarget = 'C:\fc-e2e-gh-target'
New-Item -ItemType Directory -Force -Path $ghTarget | Out-Null
'oauth_token: not-a-real-token' | Set-Content (Join-Path $ghTarget 'hosts.yml') -Encoding ASCII
New-Item -ItemType Directory -Force -Path $sess | Out-Null
New-Item -ItemType Junction -Path (Join-Path $sess 'gh') -Target $ghTarget | Out-Null
'1' | Set-Content (Join-Path $sess 'expires') -Encoding ASCII
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $apply
Check 'session with planted gh junction removed, junction target untouched' (-not (Test-Path -LiteralPath $sess) -and (Test-Path -LiteralPath (Join-Path $ghTarget 'hosts.yml')))
Write-FcConfig $null
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $apply
Check 'apply (not shared) exit 0' ($LASTEXITCODE -eq 0)
Check 'user env GH_CONFIG_DIR / GIT_CONFIG_GLOBAL cleared' (-not (Get-UserEnvVar 'GH_CONFIG_DIR') -and -not (Get-UserEnvVar 'GIT_CONFIG_GLOBAL'))
if (Get-Command git -ErrorAction SilentlyContinue) {
    Check 'git system include removed' (@(& git config --system --get-all include.path) -notcontains $include)
}
Check 'not shared: no login prompt' (-not (Get-ItemProperty -LiteralPath $runKey -Name FacilityCacheGitHubSignIn -ErrorAction SilentlyContinue))
Write-FcConfig @{ SharedMachine = $true }
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $apply
New-Item -ItemType Directory -Force -Path $sess | Out-Null

Section 'T7b install from a plain tree (no VERSION, not a checkout) with git on PATH'
# git describe writes "fatal: not a git repository" to stderr; under Stop on PS 5.1
# that used to abort the installer (NativeCommandError). A stub git reproduces it
# whether or not the runner has git.
$plain = Join-Path $env:TEMP 'fc-e2e-plain-tree'
$stub = Join-Path $env:TEMP 'fc-e2e-git-stub'
& robocopy.exe $RepoRoot $plain /E /XD .git /NFL /NDL /NJH /NJS /NP | Out-Null
Remove-Item -LiteralPath (Join-Path $plain 'VERSION') -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $stub | Out-Null
"@echo fatal: not a git repository 1>&2`r`n@exit /b 128" | Set-Content (Join-Path $stub 'git.cmd') -Encoding ASCII
$oldPath = $env:Path
$env:Path = "$stub;$env:Path"
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $plain 'windows\Install-FacilityCache.ps1') -NoRestartDocker -NoDocker
$plainExit = $LASTEXITCODE
$env:Path = $oldPath
$plainVer = (Get-Content (Join-Path $fcDir 'VERSION') -Raw).Trim()
Check 'install from plain tree with failing git: exit 0, VERSION 0.0.0-dev' ($plainExit -eq 0 -and $plainVer -eq '0.0.0-dev') "exit=$plainExit version=$plainVer"
Remove-Item -LiteralPath $plain, $stub -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $sess | Out-Null

Section 'T8 uninstall'
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $env:ProgramData 'FacilityCache\Uninstall-FacilityCache.ps1')
Check 'uninstall exit 0' ($LASTEXITCODE -eq 0)
Check 'tasks unregistered' (-not (Get-ScheduledTask -TaskName 'FacilityCache-Apply' -ErrorAction SilentlyContinue) -and -not (Get-ScheduledTask -TaskName 'FacilityCache-Update' -ErrorAction SilentlyContinue))
$do2 = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization' -ErrorAction SilentlyContinue
Check 'DO policy removed' (-not $do2 -or -not $do2.PSObject.Properties['DOCacheHostSource'])
Check 'machine env cleared' (-not (Get-MachineEnvVar 'PIP_INDEX_URL') -and -not (Get-MachineEnvVar 'NPM_CONFIG_REGISTRY'))
Check 'task FacilityCache-SessionReset unregistered' (-not (Get-ScheduledTask -TaskName 'FacilityCache-SessionReset' -ErrorAction SilentlyContinue))
Check 'shim treehouse-git.cmd removed' (-not (Test-Path (Join-Path $env:SystemRoot 'treehouse-git.cmd')))
Check 'uninstall: login prompt removed' (-not (Get-ItemProperty -LiteralPath $runKey -Name FacilityCacheGitHubSignIn -ErrorAction SilentlyContinue))
Check 'uninstall: user env GH_CONFIG_DIR / GIT_CONFIG_GLOBAL removed' (-not (Get-UserEnvVar 'GH_CONFIG_DIR') -and -not (Get-UserEnvVar 'GIT_CONFIG_GLOBAL'))
Check 'uninstall: gh session removed' (-not (Test-Path -LiteralPath $sess))
Check 'module removed' (-not (Test-Path (Join-Path $env:ProgramData 'FacilityCache\FacilityCache.psm1')))
Check 'config.json kept' (Test-Path (Join-Path $env:ProgramData 'FacilityCache\config.json'))
Check 'logs kept' (Test-Path (Join-Path $env:ProgramData 'FacilityCache\logs'))

Write-Host ''
Write-Host "RESULT pass=$($script:pass) fail=$($script:fail)"
exit $script:fail
