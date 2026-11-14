# Facility cache client helpers. Windows PowerShell 5.1 compatible.

$script:DefaultConfig = @{
    CacheHost        = 'cache.facility.innovationtreehouse.org'
    ExpectedIp       = '10.41.1.50'
    AptPort          = 3142
    PypiPort         = 3141
    NpmPort          = 4873
    DockerHubPort    = 5000
    DockerGhcrPort   = 5001
    ProbeTimeoutMs   = 5000
    # Display only: updates resolve the current name from GitHubRepoId.
    GitHubRepo       = 'innovationtreehouse/infra.cache'
    GitHubRepoId     = 1343160243
    AutoUpdate       = $true
    SharedMachine    = $false
    GhSessionHours   = 36
    SignInPromptAtLogin = $true
}

# Well-known SIDs: names are localized, SIDs are not.
$script:SidSystem = 'S-1-5-18'
$script:SidAdmins = 'S-1-5-32-544'
$script:SidUsers = 'S-1-5-32-545'
$script:SidTrustedInstaller = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
# Per-user, under the member's own profile (see Get-TreehouseGitSessionDir).
$script:SessionRel = 'AppData\Local\FacilityCache\gh-session'

function Merge-FacilityCacheObject {
    param($Cfg, $Obj)
    if ($null -eq $Obj) { return }
    $Obj.PSObject.Properties | ForEach-Object {
        $Cfg[$_.Name] = $_.Value
    }
}

function Get-FacilityCacheInstallDir {
    return (Join-Path $env:ProgramData 'FacilityCache')
}

function Test-FcElevated {
    # True for SYSTEM and elevated admins; false for a member's limited token.
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-FcLink {
    param($Item)
    return [bool]($Item.Attributes -band [IO.FileAttributes]::ReparsePoint)
}

function Test-FcDir {
    # By attribute: raw .NET FileSystemInfo objects (GetFileSystemInfos) have no PSIsContainer.
    param($Item)
    return [bool]($Item.Attributes -band [IO.FileAttributes]::Directory)
}

function Remove-FcLink {
    # Deletes a junction/symlink itself, never its target. A directory link
    # needs the non-recursive Directory.Delete; File.Delete on it is access denied.
    param($Item)
    if ($Item.Attributes -band [IO.FileAttributes]::ReadOnly) { $Item.Attributes = $Item.Attributes -band -bnot [IO.FileAttributes]::ReadOnly }
    if (Test-FcDir $Item) { [IO.Directory]::Delete($Item.FullName, $false) } else { [IO.File]::Delete($Item.FullName) }
}

function Get-FcTrustedOwnerSids {
    # Owners whose files SYSTEM may trust: SYSTEM, Administrators, TrustedInstaller,
    # the (admin) account running this, and local Administrators members.
    $s = @($script:SidSystem, $script:SidAdmins, $script:SidTrustedInstaller,
        [Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
    try { $s += @(Get-LocalGroupMember -SID $script:SidAdmins -ErrorAction Stop | ForEach-Object { $_.SID.Value }) } catch { }
    return $s
}

function Test-FcTrustedOwner {
    param([string]$Path, [string[]]$Trusted)
    try {
        $owner = (Get-Acl -LiteralPath $Path).GetOwner([Security.Principal.SecurityIdentifier]).Value
    } catch {
        return $false
    }
    return ($Trusted -contains $owner)
}

function Set-FcAcl {
    # Owner -> Administrators and drop every explicit ACE. -Protect: then grant
    # exactly SYSTEM + Administrators full control (+ Users read/execute unless
    # -NoUsers) with inheritance from the parent cut; otherwise inherit only.
    # Windows PowerShell 5.1 (.NET Framework instance methods; Set-Acl in 5.1
    # wrongly tries to write the SACL when the DACL is protected).
    param([string]$Path, [switch]$Protect, [switch]$NoUsers)
    $item = Get-Item -LiteralPath $Path -Force
    $acl = $item.GetAccessControl()
    $sidType = [Security.Principal.SecurityIdentifier]
    foreach ($r in @($acl.GetAccessRules($true, $false, $sidType))) { $acl.RemoveAccessRuleSpecific($r) }
    $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier $script:SidAdmins))
    $acl.SetAccessRuleProtection([bool]$Protect, $false)
    if ($Protect) {
        $inherit = 'None'
        if ($item.PSIsContainer) { $inherit = 'ContainerInherit, ObjectInherit' }
        $grants = @(@($script:SidSystem, 'FullControl'), @($script:SidAdmins, 'FullControl'))
        if (-not $NoUsers) { $grants += , @($script:SidUsers, 'ReadAndExecute') }
        foreach ($g in $grants) {
            $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
                (New-Object Security.Principal.SecurityIdentifier $g[0]), $g[1], $inherit, 'None', 'Allow')))
        }
    }
    $item.SetAccessControl($acl)
}

function Protect-FcTree {
    # Below an already-protected dir (so nobody can add entries while we walk):
    # links go, items a non-admin owns are deleted (config.json / github-token set
    # aside as *.untrusted), everything else gets owner Administrators + inherited ACL.
    param([string]$Dir, [string[]]$Trusted, $Notes, [string[]]$Skip = @())
    foreach ($c in @((Get-Item -LiteralPath $Dir -Force).GetFileSystemInfos())) {
        $p = $c.FullName
        if ($Skip -contains $c.Name) { continue }
        if (Test-FcLink $c) {
            Remove-FcLink $c
            [void]$Notes.Add("removed planted link $p")
            continue
        }
        if (-not (Test-FcTrustedOwner -Path $p -Trusted $Trusted)) {
            if (@('config.json', 'github-token') -contains $c.Name) {
                $aside = "$p.untrusted"
                if (Test-Path -LiteralPath $aside) { [IO.File]::Delete($aside) }
                [IO.File]::Move($p, $aside)
                [void]$Notes.Add("$p was not created by an administrator; ignored and moved to $aside")
            } else {
                if (Test-FcDir $c) { [IO.Directory]::Delete($p, $true) } else { $c.Attributes = 'Normal'; [IO.File]::Delete($p) }
                [void]$Notes.Add("removed $p (not created by an administrator)")
            }
            continue
        }
        $secret = ($c.Name -eq 'github-token')
        Set-FcAcl -Path $p -Protect:$secret -NoUsers:$secret
        if (Test-FcDir $c) { Protect-FcTree -Dir $p -Trusted $Trusted -Notes $Notes }
    }
}

function Protect-FacilityCacheInstallDir {
    # SYSTEM tasks run scripts and read config/token from here, so non-admins
    # must not create, own or replace anything in it. Returns notes to report.
    $dir = Get-FacilityCacheInstallDir
    $notes = New-Object 'System.Collections.Generic.List[string]'
    $trusted = Get-FcTrustedOwnerSids
    $item = Get-Item -LiteralPath $dir -Force -ErrorAction SilentlyContinue
    if ($item -and (Test-FcLink $item)) {
        Remove-FcLink $item
        [void]$notes.Add("removed planted link $dir")
        $item = $null
    } elseif ($item -and (-not $item.PSIsContainer -or -not (Test-FcTrustedOwner -Path $dir -Trusted $trusted))) {
        # Pre-created by a non-admin. Set it aside untouched and start fresh: fixing
        # it in place would leave any handle they already hold with its access.
        $aside = "$dir.untrusted-" + [DateTime]::UtcNow.ToString('yyyyMMddHHmmss')
        if ($item.PSIsContainer) { [IO.Directory]::Move($dir, $aside) } else { [IO.File]::Move($dir, $aside) }
        [void]$notes.Add("$dir was not created by an administrator; moved to $aside (nothing in it is used)")
        $item = $null
    }
    if (-not $item) { [void][IO.Directory]::CreateDirectory($dir) }
    Set-FcAcl -Path $dir -Protect
    # The pre-hardening shared-machine session dir is handled (token revoked) below.
    Protect-FcTree -Dir $dir -Trusted $trusted -Notes $notes -Skip @('gh-session')
    [void](Remove-TreehouseGitSessionDir -Base $dir -Rel 'gh-session')
    return $notes.ToArray()
}

function New-FacilityCacheTempDir {
    # Fresh, random, SYSTEM+Administrators-only dir for downloads/extraction,
    # inside the hardened install dir (non-admins cannot create anything there,
    # unlike SYSTEM's %TEMP% = C:\Windows\Temp).
    $p = Join-Path (Get-FacilityCacheInstallDir) ('tmp-' + [guid]::NewGuid().ToString('N'))
    if (Test-Path -LiteralPath $p) { throw "temp dir $p already exists" }
    [void][IO.Directory]::CreateDirectory($p)
    Set-FcAcl -Path $p -Protect -NoUsers
    return $p
}

function Get-FcTrustedCommand {
    # SYSTEM must not run a binary from a PATH entry a non-admin can write (a
    # folder an admin made under C:\ inherits Authenticated Users modify). Only
    # accept tools under Program Files, Windows, or this account's own profile.
    param([string]$Name)
    $roots = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:SystemRoot, $env:LOCALAPPDATA) |
        Where-Object { $_ } | ForEach-Object { $_.TrimEnd('\') + '\' }
    foreach ($c in @(Get-Command $Name -CommandType Application -All -ErrorAction SilentlyContinue)) {
        $full = [IO.Path]::GetFullPath($c.Path)
        foreach ($r in $roots) {
            if ($full.StartsWith($r, [StringComparison]::OrdinalIgnoreCase)) { return $full }
        }
    }
    return $null
}

function Invoke-FcNative {
    # Every native call from install/apply/update/uninstall goes through here.
    # Under $ErrorActionPreference = 'Stop' (the scripts' setting, which these
    # functions see), Windows PowerShell 5.1 turns a native command's redirected
    # stderr into a terminating NativeCommandError, so one warning line from
    # git/npm/winget/reg aborted Apply or the installer. Continue is local to
    # this function; stderr is discarded; callers that care check $LASTEXITCODE.
    # Usage: Invoke-FcNative <exe> <args...>. No param block on purpose: every
    # token (including ones like -e) must reach the native command untouched.
    $ErrorActionPreference = 'Continue'
    $exe = $args[0]
    $rest = @($args | Select-Object -Skip 1)
    & $exe @rest 2>$null
}

function Invoke-FcSystemGit {
    # git as SYSTEM/admin: never parse a global config (HOME or GIT_CONFIG_GLOBAL)
    # that someone else could have written. Returns stdout; sets $LASTEXITCODE
    # (left at 127 when there is no trusted git).
    $git = Get-FcTrustedCommand git
    if (-not $git) { $global:LASTEXITCODE = 127; return }
    $prev = $env:GIT_CONFIG_GLOBAL
    $env:GIT_CONFIG_GLOBAL = '/dev/null'
    try { Invoke-FcNative $git @args } finally { $env:GIT_CONFIG_GLOBAL = $prev }
}

function New-FcGitHubHeaders {
    # The token is attached only to https://api.github.com. Windows PowerShell's
    # web cmdlets drop Authorization on every redirect, so it never follows an
    # asset download to objects.githubusercontent.com — and a redirected API call
    # (old repo name) arrives unauthenticated, which is why callers avoid them.
    param([string]$Uri, [string]$Token, [string]$Accept = 'application/vnd.github+json', [string]$Agent = 'facility-cache-client')
    $h = @{ 'User-Agent' = $Agent; Accept = $Accept }
    $u = [Uri]$Uri
    if ($Token -and $u.Scheme -eq 'https' -and $u.Host -eq 'api.github.com') { $h['Authorization'] = "Bearer $Token" }
    return $h
}

$script:FcCmd = ''
$script:FcStepI = 0
$script:FcStepN = 0
$script:FcOk = [string][char]0x2713
$script:FcFail = [string][char]0x2717
$script:FcWork = [string][char]0x25CF
$script:FcOff = [string][char]0x25CB

function Get-FacilityCacheLogPath {
    $dir = Join-Path (Get-FacilityCacheInstallDir) 'logs'
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    return (Join-Path $dir 'client.jsonl')
}

function Write-FacilityCacheLog {
    param(
        [string]$Level = 'info',
        [string]$Event = 'info',
        [string]$Message,
        $Extra = $null
    )
    $rec = @{
        ts    = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
        level = $Level
        cmd   = $script:FcCmd
        event = $Event
        msg   = $Message
        extra = $Extra
    }
    try {
        $path = Get-FacilityCacheLogPath
        ($rec | ConvertTo-Json -Compress -Depth 6) | Add-Content -LiteralPath $path -Encoding UTF8
        if ((Get-Item $path).Length -gt 2000000) {
            $bak = "$path.1"
            if (Test-Path $bak) { Remove-Item $bak -Force }
            Move-Item $path $bak
        }
    } catch { }
}

function Write-FcHeader {
    param([string]$Title, [string]$Subtitle = '')
    $script:FcCmd = $Title
    Write-Host ''
    Write-Host -NoNewline '  '
    Write-Host -NoNewline $Title -ForegroundColor Cyan
    if ($Subtitle) {
        Write-Host -NoNewline "  $Subtitle" -ForegroundColor DarkGray
    }
    Write-Host ''
    Write-Host ('  ' + ('-' * 48)) -ForegroundColor DarkGray
    Write-FacilityCacheLog -Level info -Event start -Message "$Title $Subtitle"
}

function Write-FcKv {
    param([string]$Key, [string]$Value, [string]$Kind = '')
    $mark = ''
    $color = 'Gray'
    switch ($Kind) {
        'ok'   { $mark = " $($script:FcOk)"; $color = 'Green' }
        'fail' { $mark = " $($script:FcFail)"; $color = 'Red' }
        'warn' { $mark = ' !'; $color = 'Yellow' }
        'on'   { $mark = " $($script:FcWork)"; $color = 'Green' }
        'off'  { $mark = " $($script:FcOff)"; $color = 'DarkGray' }
        'work' { $mark = " $($script:FcWork)"; $color = 'Cyan' }
    }
    Write-Host -NoNewline '  '
    Write-Host -NoNewline ('{0,-12}' -f $Key) -ForegroundColor DarkGray
    Write-Host -NoNewline " $Value"
    if ($mark) { Write-Host $mark -ForegroundColor $color } else { Write-Host '' }
}

function Write-FcOk   { param([string]$Message) Write-Host "  $($script:FcOk) $Message" -ForegroundColor Green; Write-FacilityCacheLog -Event ok -Message $Message }
function Write-FcFail { param([string]$Message) Write-Host "  $($script:FcFail) $Message" -ForegroundColor Red; Write-FacilityCacheLog -Level error -Event fail -Message $Message }
function Write-FcWarn { param([string]$Message) Write-Host "  ! $Message" -ForegroundColor Yellow; Write-FacilityCacheLog -Level warn -Event warn -Message $Message }
function Write-FcNote { param([string]$Message) Write-Host "    $Message" -ForegroundColor DarkGray }

function Write-FcStep {
    param([string]$Name, [string]$Message = '')
    $script:FcStepI++
    $prefix = ''
    if ($script:FcStepN -gt 0) { $prefix = "$($script:FcStepI)/$($script:FcStepN)  " }
    Write-Host "  $($script:FcWork) $prefix$Name  $Message" -ForegroundColor Cyan
    Write-FacilityCacheLog -Event step_start -Message "$Name $Message"
}

function Write-FcStepOk {
    param([string]$Message = 'done')
    Write-Host "  $($script:FcOk) $Message" -ForegroundColor Green
    Write-FacilityCacheLog -Event step_ok -Message $Message
}

function Write-FcBar {
    param([int]$Current, [int]$Total, [string]$Label = '')
    if ($Total -le 0) { $Total = 1 }
    $pct = [Math]::Min(100, [int]($Current * 100 / $Total))
    Write-Progress -Activity 'facility-cache' -Status $Label -PercentComplete $pct
    $width = 24
    $filled = [int]($width * $pct / 100)
    $bar = ('#' * $filled) + ('-' * ($width - $filled))
    Write-Host -NoNewline "`r  $($script:FcWork) $bar  $pct%  $Label   "
    if ($Current -ge $Total) {
        Write-Host ''
        Write-Progress -Activity 'facility-cache' -Completed
    }
}

function Write-FcFinish {
    param([bool]$Ok = $true, [string]$Message = '')
    Write-Host ('  ' + ('-' * 48)) -ForegroundColor DarkGray
    if ($Ok) {
        if (-not $Message) { $Message = 'done' }
        Write-Host "  $($script:FcOk) $Message" -ForegroundColor Green
    } else {
        if (-not $Message) { $Message = 'failed' }
        Write-Host "  $($script:FcFail) $Message" -ForegroundColor Red
    }
    Write-Host "    log $(Get-FacilityCacheLogPath)" -ForegroundColor DarkGray
    Write-Host ''
    Write-FacilityCacheLog -Event finish -Message $Message -Extra @{ ok = $Ok }
}

function Show-FacilityCacheLog {
    param(
        [int]$Count = 40,
        [switch]$Follow,
        [switch]$Json,
        [switch]$PathOnly
    )
    $path = Get-FacilityCacheLogPath
    if ($PathOnly) { Write-Output $path; return }
    if (-not (Test-Path $path)) {
        Write-FcWarn "no log yet at $path"
        return
    }
    if ($Json -and -not $Follow) {
        Get-Content -LiteralPath $path
        return
    }
    Write-FcHeader 'facility-cache log' $path
    $emit = {
        param($line)
        if (-not $line) { return }
        if ($Json) { Write-Output $line; return }
        try { $rec = $line | ConvertFrom-Json } catch { Write-Host "  $line"; return }
        $ts = ([string]$rec.ts)
        if ($ts.Length -ge 19) { $ts = $ts.Substring(11, 8) }
        $color = 'Cyan'
        $mark = $script:FcWork
        if ($rec.level -eq 'error') { $color = 'Red'; $mark = $script:FcFail }
        elseif ($rec.level -eq 'warn') { $color = 'Yellow'; $mark = '!' }
        elseif ($rec.event -in @('ok', 'step_ok', 'finish')) { $color = 'Green'; $mark = $script:FcOk }
        Write-Host -NoNewline "  $mark " -ForegroundColor $color
        Write-Host -NoNewline "$ts  $($rec.cmd)  " -ForegroundColor DarkGray
        Write-Host $rec.msg
    }
    Get-Content -LiteralPath $path -Tail $Count | ForEach-Object { & $emit $_ }
    if ($Follow) {
        Write-Host '  following  Ctrl-C to stop' -ForegroundColor DarkGray
        Get-Content -LiteralPath $path -Wait -Tail 0 | ForEach-Object { & $emit $_ }
    }
}

function Show-FacilityCacheDashboard {
    $st = Get-FacilityCacheStatus
    Write-FcHeader 'facility-cache-client' ("v" + $st.Version)
    $net = 'off-site'
    $kind = 'off'
    if ($st.DnsOk) { $net = 'on-site'; $kind = 'on' }
    elseif ($st.Resolved) { $net = 'wrong address'; $kind = 'fail' }
    Write-FcKv 'network' $net $kind
    Write-FcKv 'host' $st.Host
    Write-FcKv 'expect' $st.ExpectedIp
    $resKind = 'fail'
    if ($st.DnsOk) { $resKind = 'ok' }
    Write-FcKv 'resolved' $(if ($st.Resolved) { $st.Resolved } else { 'none' }) $resKind
    Write-Host ''
    foreach ($name in @('apt', 'pypi', 'npm', 'dockerhub', 'ghcr')) {
        $open = [bool]$st.Ports[$name]
        $label = $(if ($open) { 'on ' } else { 'off' })
        $kind = $(if ($open) { 'on' } else { 'off' })
        Write-FcKv $name $label $kind
    }
    Write-Host ''
    Write-FcKv 'updates' $(if ($st.AutoUpdate) { 'auto on' } else { 'auto off' }) $(if ($st.AutoUpdate) { 'on' } else { 'off' })
    Write-FcKv 'shared' $(if ($st.SharedMachine) { 'on  treehouse-git signin' } else { 'off' }) $(if ($st.SharedMachine) { 'on' } else { 'off' })
    Write-FcKv 'repo' $st.GitHubRepo
    $last = 'never'
    if ($st.Update) {
        $last = "$($st.Update.last_result)  $($st.Update.latest_version)  $($st.Update.updated_at)"
    }
    Write-FcKv 'last' $last
    Write-FcKv 'log' (Get-FacilityCacheLogPath)
    Write-Host ''
}

function Get-FacilityCacheConfig {
    $dir = Get-FacilityCacheInstallDir
    $cfg = $script:DefaultConfig.Clone()
    $defaultsPath = Join-Path $dir 'defaults.json'
    $cfgPath = Join-Path $dir 'config.json'
    if (Test-Path $defaultsPath) {
        Merge-FacilityCacheObject -Cfg $cfg -Obj (Get-Content -LiteralPath $defaultsPath -Raw | ConvertFrom-Json)
    }
    if (Test-Path $cfgPath) {
        Merge-FacilityCacheObject -Cfg $cfg -Obj (Get-Content -LiteralPath $cfgPath -Raw | ConvertFrom-Json)
    }
    $tokenFile = Join-Path $dir 'github-token'
    if (Test-Path $tokenFile) {
        # SYSTEM/Administrators only: members (Status, treehouse-git) cannot read it.
        try { $cfg['GitHubToken'] = ([string](Get-Content -LiteralPath $tokenFile -Raw -ErrorAction Stop)).Trim() } catch { }
    }
    if ($env:GITHUB_TOKEN) { $cfg['GitHubToken'] = $env:GITHUB_TOKEN }
    return $cfg
}

function Get-FacilityCacheInstalledVersion {
    $path = Join-Path (Get-FacilityCacheInstallDir) 'VERSION'
    if (Test-Path $path) {
        return ((Get-Content -LiteralPath $path -Raw).Trim().TrimStart('v'))
    }
    return '0.0.0'
}

function Get-FacilityCacheIPv4 {
    param([string]$HostName)
    try {
        return [System.Net.Dns]::GetHostAddresses($HostName) |
            Where-Object { $_.AddressFamily -eq 'InterNetwork' } |
            ForEach-Object { $_.ToString() }
    } catch {
        return @()
    }
}

function Test-FacilityCachePort {
    param(
        [Parameter(Mandatory = $true)][string]$Ip,
        [Parameter(Mandatory = $true)][int]$Port,
        [int]$TimeoutMs = 5000
    )
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $client.BeginConnect($Ip, $Port, $null, $null)
        $ok = $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
        if (-not $ok) { return $false }
        $client.EndConnect($iar)
        return $true
    } catch {
        return $false
    } finally {
        $client.Close()
    }
}

function Test-FacilityCache {
    param([int]$Port = 0)
    $cfg = Get-FacilityCacheConfig
    $ips = @(Get-FacilityCacheIPv4 -HostName $cfg.CacheHost)
    $dnsOk = $ips -contains [string]$cfg.ExpectedIp
    if (-not $dnsOk) { return $false }
    if ($Port -gt 0) {
        return (Test-FacilityCachePort -Ip $cfg.ExpectedIp -Port $Port -TimeoutMs $cfg.ProbeTimeoutMs)
    }
    return $true
}

function Get-FacilityCacheStatus {
    $cfg = Get-FacilityCacheConfig
    $ips = @(Get-FacilityCacheIPv4 -HostName $cfg.CacheHost)
    $dnsOk = $ips -contains [string]$cfg.ExpectedIp
    $ports = @{
        apt       = $cfg.AptPort
        pypi      = $cfg.PypiPort
        npm       = $cfg.NpmPort
        dockerhub = $cfg.DockerHubPort
        ghcr      = $cfg.DockerGhcrPort
    }
    $open = @{}
    foreach ($name in $ports.Keys) {
        $open[$name] = $false
        if ($dnsOk) {
            $open[$name] = Test-FacilityCachePort -Ip $cfg.ExpectedIp -Port $ports[$name] -TimeoutMs $cfg.ProbeTimeoutMs
        }
    }
    $state = $null
    $statePath = Join-Path (Get-FacilityCacheInstallDir) 'state.json'
    if (Test-Path $statePath) {
        $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
    }
    [pscustomobject]@{
        Host       = $cfg.CacheHost
        ExpectedIp = $cfg.ExpectedIp
        Resolved   = ($ips -join ',')
        DnsOk      = $dnsOk
        Ports      = $open
        Version    = Get-FacilityCacheInstalledVersion
        GitHubRepo = $cfg.GitHubRepo
        AutoUpdate = $cfg.AutoUpdate
        SharedMachine = ($cfg.SharedMachine -eq $true)
        Update     = $state
    }
}

function Set-MachineEnv {
    param([string]$Name, [string]$Value)
    $target = if ($null -eq $Value -or $Value -eq '') { $null } else { $Value }
    $current = [Environment]::GetEnvironmentVariable($Name, 'Machine')
    if ($current -eq $target) { return }
    # SetEnvironmentVariable(..., 'Machine') broadcasts WM_SETTINGCHANGE to every top-level
    # window; only call it when the value actually changes (this runs every 5 minutes).
    [Environment]::SetEnvironmentVariable($Name, $target, 'Machine')
}

function Write-ManagedFile {
    param([string]$Path, [string]$Content)
    $dir = Split-Path -Parent $Path
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    Set-Content -LiteralPath $Path -Value $Content -Encoding ASCII
}

function Remove-ManagedFile {
    param([string]$Path)
    if (Test-Path $Path) {
        $head = Get-Content -LiteralPath $Path -TotalCount 2 -ErrorAction SilentlyContinue
        if ($head -match 'facility-cache-managed') {
            Remove-Item -LiteralPath $Path -Force
        }
    }
}

function Merge-DockerDaemonJson {
    Add-Type -AssemblyName System.Web.Extensions -ErrorAction Stop
    $ser = New-Object System.Web.Script.Serialization.JavaScriptSerializer
    $paths = @(
        (Join-Path $env:ProgramData 'Docker\config\daemon.json'),
        (Join-Path $env:USERPROFILE '.docker\daemon.json')
    )
    $cfg = Get-FacilityCacheConfig
    $mirror = "http://$($cfg.CacheHost):$($cfg.DockerHubPort)"
    $insecureWanted = @(
        "$($cfg.CacheHost):$($cfg.DockerHubPort)",
        "$($cfg.CacheHost):$($cfg.DockerGhcrPort)"
    )
    $changed = $false
    foreach ($path in $paths) {
        $dir = Split-Path -Parent $path
        $exists = Test-Path $path
        if (-not $exists -and $path -like '*\.docker\*') { continue }
        if (-not (Test-Path $dir)) {
            if ($path -like '*\Docker\config\*') {
                New-Item -ItemType Directory -Path $dir -Force | Out-Null
            } else {
                continue
            }
        }
        $hash = New-Object 'System.Collections.Generic.Dictionary[string,object]'
        if ($exists) {
            $raw = Get-Content -LiteralPath $path -Raw
            if ($raw -and $raw.Trim()) {
                $loaded = $ser.DeserializeObject($raw)
                foreach ($key in $loaded.Keys) { $hash[$key] = $loaded[$key] }
            }
        }
        $mirrors = New-Object 'System.Collections.Generic.List[string]'
        if ($hash.ContainsKey('registry-mirrors') -and $null -ne $hash['registry-mirrors']) {
            foreach ($m in @($hash['registry-mirrors'])) { [void]$mirrors.Add($m) }
        }
        if (-not $mirrors.Contains($mirror)) { $mirrors.Insert(0, $mirror) }
        $regs = New-Object 'System.Collections.Generic.List[string]'
        if ($hash.ContainsKey('insecure-registries') -and $null -ne $hash['insecure-registries']) {
            foreach ($r in @($hash['insecure-registries'])) { [void]$regs.Add($r) }
        }
        foreach ($item in $insecureWanted) {
            if (-not $regs.Contains($item)) { [void]$regs.Add($item) }
        }
        # The .ToArray() is load-bearing, not cosmetic: a plain List[string]
        # assigned into the dictionary still crashes JavaScriptSerializer the
        # same way List[object] did (PowerShell's indexer still wraps the
        # List itself in a PSObject); .ToArray() yields a real string[],
        # which serializes cleanly.
        $hash['registry-mirrors'] = $mirrors.ToArray()
        $hash['insecure-registries'] = $regs.ToArray()
        $json = $ser.Serialize($hash)
        $old = ''
        if ($exists) { $old = (Get-Content -LiteralPath $path -Raw).Trim() }
        if ($json -ne $old) {
            $bak = "$path.facility-cache.bak"
            if ($exists -and -not (Test-Path $bak)) { Copy-Item $path $bak }
            # Set-Content -Encoding UTF8 always adds a BOM in PS 5.1, which
            # dockerd's Go JSON parser rejects. Write UTF-8 without one.
            $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
            [System.IO.File]::WriteAllText($path, $json, $utf8NoBom)
            $changed = $true
        }
    }
    return $changed
}

function Remove-DockerMirrors {
    Add-Type -AssemblyName System.Web.Extensions -ErrorAction Stop
    $ser = New-Object System.Web.Script.Serialization.JavaScriptSerializer
    $paths = @(
        (Join-Path $env:ProgramData 'Docker\config\daemon.json'),
        (Join-Path $env:USERPROFILE '.docker\daemon.json')
    )
    $cfg = Get-FacilityCacheConfig
    $mirror = "http://$($cfg.CacheHost):$($cfg.DockerHubPort)"
    $insecure = @(
        "$($cfg.CacheHost):$($cfg.DockerHubPort)",
        "$($cfg.CacheHost):$($cfg.DockerGhcrPort)"
    )
    foreach ($path in $paths) {
        if (-not (Test-Path $path)) { continue }
        $raw = Get-Content -LiteralPath $path -Raw
        if (-not $raw -or -not $raw.Trim()) { continue }
        $loaded = $ser.DeserializeObject($raw)
        $hash = New-Object 'System.Collections.Generic.Dictionary[string,object]'
        foreach ($key in $loaded.Keys) { $hash[$key] = $loaded[$key] }
        if ($hash.ContainsKey('registry-mirrors')) {
            $kept = New-Object 'System.Collections.Generic.List[string]'
            foreach ($m in @($hash['registry-mirrors'])) {
                if ($m -ne $mirror) { [void]$kept.Add($m) }
            }
            if ($kept.Count -gt 0) { $hash['registry-mirrors'] = $kept.ToArray() } else { [void]$hash.Remove('registry-mirrors') }
        }
        if ($hash.ContainsKey('insecure-registries')) {
            $kept = New-Object 'System.Collections.Generic.List[string]'
            foreach ($r in @($hash['insecure-registries'])) {
                if ($insecure -notcontains $r) { [void]$kept.Add($r) }
            }
            if ($kept.Count -gt 0) { $hash['insecure-registries'] = $kept.ToArray() } else { [void]$hash.Remove('insecure-registries') }
        }
        if ($hash.Count -eq 0) {
            Remove-Item -LiteralPath $path -Force
        } else {
            # Same BOM concern as Merge-DockerDaemonJson above.
            $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
            [System.IO.File]::WriteAllText($path, $ser.Serialize($hash), $utf8NoBom)
        }
    }
}

function Set-DeliveryOptimizationDhcpDiscovery {
    $key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization'
    if (-not (Test-Path $key)) {
        New-Item -Path $key -Force | Out-Null
    }
    # 2 = DHCP option 235 Force. Off-site, option is absent and DO uses the CDN.
    New-ItemProperty -Path $key -Name 'DOCacheHostSource' -PropertyType DWord -Value 2 -Force | Out-Null
    if (Get-ItemProperty -Path $key -Name 'DOCacheHost' -ErrorAction SilentlyContinue) {
        Remove-ItemProperty -Path $key -Name 'DOCacheHost' -Force
    }
}

function Remove-DeliveryOptimizationDhcpDiscovery {
    $key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization'
    if (Test-Path $key) {
        Remove-ItemProperty -Path $key -Name 'DOCacheHostSource' -ErrorAction SilentlyContinue
    }
}

function Invoke-FacilityCacheApply {
    $cfg = Get-FacilityCacheConfig
    $pypiOn = Test-FacilityCache -Port $cfg.PypiPort
    $npmOn = Test-FacilityCache -Port $cfg.NpmPort
    $index = "http://$($cfg.CacheHost):$($cfg.PypiPort)/root/pypi/+simple/"
    $npm = "http://$($cfg.CacheHost):$($cfg.NpmPort)/"
    $pipIni = Join-Path $env:ProgramData 'pip\pip.ini'
    $uvToml = Join-Path $env:ProgramData 'uv\uv.toml'

    if ($pypiOn) {
        Write-ManagedFile -Path $pipIni -Content @"
# facility-cache-managed
[global]
index-url = $index
trusted-host = $($cfg.CacheHost)
"@
        Write-ManagedFile -Path $uvToml -Content @"
# facility-cache-managed
index-url = "$index"
allow-insecure-host = ["$($cfg.CacheHost)"]
"@
        Set-MachineEnv -Name 'PIP_INDEX_URL' -Value $index
        Set-MachineEnv -Name 'PIP_TRUSTED_HOST' -Value $cfg.CacheHost
        Set-MachineEnv -Name 'UV_INDEX_URL' -Value $index
        Set-MachineEnv -Name 'UV_INSECURE_HOST' -Value $cfg.CacheHost
    } else {
        Remove-ManagedFile -Path $pipIni
        Remove-ManagedFile -Path $uvToml
        Set-MachineEnv -Name 'PIP_INDEX_URL' -Value $null
        Set-MachineEnv -Name 'PIP_TRUSTED_HOST' -Value $null
        Set-MachineEnv -Name 'UV_INDEX_URL' -Value $null
        Set-MachineEnv -Name 'UV_INSECURE_HOST' -Value $null
    }

    $npmCmd = Get-FcTrustedCommand npm
    if ($npmOn) {
        Set-MachineEnv -Name 'NPM_CONFIG_REGISTRY' -Value $npm
        if ($npmCmd) {
            Invoke-FcNative $npmCmd config set registry $npm --location=global | Out-Null
        }
    } else {
        Set-MachineEnv -Name 'NPM_CONFIG_REGISTRY' -Value $null
        if ($npmCmd) {
            # Only clear the global registry if it's still pointed at ours — never
            # blow away a registry someone else configured.
            $currentRegistry = (Invoke-FcNative $npmCmd config get registry --location=global)
            if ($currentRegistry -and ([string]$currentRegistry).Trim() -eq $npm) {
                Invoke-FcNative $npmCmd config delete registry --location=global | Out-Null
            }
        }
    }

    # An admin may add github-token after install; it inherits Users read. Fix that.
    $tok = Join-Path (Get-FacilityCacheInstallDir) 'github-token'
    if (Test-Path -LiteralPath $tok -PathType Leaf) {
        $other = @((Get-Acl -LiteralPath $tok).GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) |
            Where-Object { @($script:SidSystem, $script:SidAdmins) -notcontains $_.IdentityReference.Value })
        if ($other.Count -gt 0) { Set-FcAcl -Path $tok -Protect -NoUsers }
    }

    Set-TreehouseGitSharedMachine
}

# Shared-machine GitHub sign-in (treehouse-git). The session lives in each
# account's OWN profile and is published through USER-scope env vars written
# into that account's hive, never machine scope: no other account, no elevated
# shell of another account and no SYSTEM process ever reads a git/gh config a
# member could write. SYSTEM wipes every profile's session at startup, logon,
# logoff and expiry.
function Get-TreehouseGitSessionDir {
    param([string]$ProfileDir = $env:USERPROFILE)
    return (Join-Path $ProfileDir $script:SessionRel)
}

function Get-FcUserProfiles {
    # SID + profile dir of every account except SYSTEM / LocalService / NetworkService.
    $key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
    foreach ($k in @(Get-ChildItem -LiteralPath $key -ErrorAction SilentlyContinue)) {
        $sid = $k.PSChildName
        if ($sid -notmatch '^S-1-[\d-]+$' -or @('S-1-5-18', 'S-1-5-19', 'S-1-5-20') -contains $sid) { continue }
        $dir = [Environment]::ExpandEnvironmentVariables([string]$k.GetValue('ProfileImagePath'))
        if ($dir) { [pscustomobject]@{ Sid = $sid; Dir = $dir } }
    }
}

function Get-TreehouseGitSessionExpiry {
    # 0 when missing or unparseable, so callers fail closed (treat as expired).
    param([string]$Dir = (Get-TreehouseGitSessionDir))
    $exp = [long]0
    try {
        $raw = Get-Content -LiteralPath (Join-Path $Dir 'expires') -Raw -ErrorAction Stop
        [void][long]::TryParse(([string]$raw).Trim(), [ref]$exp)
    } catch { }
    return $exp
}

function Get-FcSessionToken {
    # Token-shaped strings from <session>\gh\hosts.yml. Member-writable, read by
    # SYSTEM: refuse a link or non-regular file at every component.
    param([string]$Dir)
    $gh = Get-Item -LiteralPath (Join-Path $Dir 'gh') -Force -ErrorAction SilentlyContinue
    if (-not $gh -or -not $gh.PSIsContainer -or (Test-FcLink $gh)) { return @() }
    $hosts = Get-Item -LiteralPath (Join-Path $gh.FullName 'hosts.yml') -Force -ErrorAction SilentlyContinue
    if (-not $hosts -or $hosts.PSIsContainer -or (Test-FcLink $hosts)) { return @() }
    return @(Get-Content -LiteralPath $hosts.FullName -ErrorAction SilentlyContinue | ForEach-Object {
        if ($_ -cmatch '^\s*oauth_token:\s*(gh[a-z]_[A-Za-z0-9_]+)\s*$') { $Matches[1] }
    } | Select-Object -Unique)
}

function Remove-TreehouseGitSessionDir {
    # Revokes the session's gh token on GitHub, then deletes the whole session dir
    # $Base\$Rel. Walks down from the trusted $Base so SYSTEM never follows a
    # link a member planted on the way. $true when the dir is gone afterwards.
    param([string]$Base, [string]$Rel, [switch]$OnlyIfExpired)
    $d = $Base
    $parts = $Rel.Split('\')
    for ($i = 0; $i -lt $parts.Count; $i++) {
        $d = Join-Path $d $parts[$i]
        $item = Get-Item -LiteralPath $d -Force -ErrorAction SilentlyContinue
        if (-not $item) { return $true }
        if ((Test-FcLink $item) -or -not $item.PSIsContainer) {
            # Our own FacilityCache\gh-session names: drop the planted link/file itself.
            if ($i -ge $parts.Count - 2) { Remove-FcLink $item; return $true }
            Write-FcWarn "not resetting the GitHub session under $d (it is a link)"
            return $false
        }
    }
    if ($OnlyIfExpired -and [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() -lt (Get-TreehouseGitSessionExpiry -Dir $d)) { return $true }
    $tokens = @(Get-FcSessionToken -Dir $d)
    if ($tokens.Count -gt 0) {
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            # Built by hand: the regex limits tokens to [A-Za-z0-9_], and this stays an
            # array for one token on every PowerShell version.
            $body = '{"credentials":["' + ($tokens -join '","') + '"]}'
            # Must be unauthenticated: GitHub answers 403 to any Authorization header.
            Invoke-RestMethod -Method Post -Uri 'https://api.github.com/credentials/revoke' -Body $body `
                -ContentType 'application/json' -TimeoutSec 10 `
                -Headers @{ Accept = 'application/vnd.github+json'; 'User-Agent' = 'facility-cache-client' } | Out-Null
        } catch {
            Write-FcWarn "could not revoke the GitHub token: $($_.Exception.Message)"
        }
    }
    # .NET's recursive delete removes junctions/symlinks inside without following
    # them; PS 5.1's Remove-Item -Recurse does follow them, so do not use it here.
    try {
        [IO.Directory]::Delete($d, $true)
    } catch {
        # Locked or ACL-denied leftovers: move the whole dir off the configured
        # path so nothing reads it as config, then retry deleting it below.
        try { [IO.Directory]::Move($d, "$d.stale-" + [guid]::NewGuid().ToString('N')) } catch { }
    }
    foreach ($s in @(Get-ChildItem -LiteralPath (Split-Path -Parent $d) -Force -Filter 'gh-session.stale-*' -ErrorAction SilentlyContinue)) {
        try { if (Test-FcLink $s) { Remove-FcLink $s } else { [IO.Directory]::Delete($s.FullName, $true) } } catch { }
    }
    if (Test-Path -LiteralPath $d) {
        Write-FcFail "could not remove the GitHub session at $d; sign-in stays blocked until it is gone (log off, or restart)"
        return $false
    }
    return $true
}

function Reset-TreehouseGitSession {
    # As a member (signin/signout): their own profile's session. As SYSTEM/admin
    # (tasks, install, uninstall): every profile, plus the pre-per-user location
    # inside the install dir. Returns $false if any session could not be removed.
    param([switch]$OnlyIfExpired)
    if (-not (Test-FcElevated)) {
        return (Remove-TreehouseGitSessionDir -Base $env:USERPROFILE -Rel $script:SessionRel -OnlyIfExpired:$OnlyIfExpired)
    }
    $ok = Remove-TreehouseGitSessionDir -Base (Get-FacilityCacheInstallDir) -Rel 'gh-session'
    foreach ($p in @(Get-FcUserProfiles)) {
        if (-not (Remove-TreehouseGitSessionDir -Base $p.Dir -Rel $script:SessionRel -OnlyIfExpired:$OnlyIfExpired)) { $ok = $false }
    }
    return $ok
}

function Set-TreehouseGitUserEnv {
    # Sets (or -Remove) GH_CONFIG_DIR / GIT_CONFIG_GLOBAL at USER scope in each
    # account's hive, pointing into that account's own profile. Loaded hives only
    # unless -IncludeUnloaded (uninstall). Takes effect at that account's next logon.
    param([switch]$Remove, [switch]$IncludeUnloaded)
    $users = [Microsoft.Win32.Registry]::Users
    $loaded = $users.GetSubKeyNames()
    $reg = Join-Path $env:SystemRoot 'System32\reg.exe'
    foreach ($p in @(Get-FcUserProfiles)) {
        $root = $p.Sid
        $mounted = $false
        if ($loaded -notcontains $p.Sid) {
            $hive = Join-Path $p.Dir 'NTUSER.DAT'
            if (-not $IncludeUnloaded -or -not (Test-Path -LiteralPath $hive)) { continue }
            $root = 'facility-cache-' + [guid]::NewGuid().ToString('N')
            Invoke-FcNative $reg load "HKU\$root" $hive | Out-Null
            if ($LASTEXITCODE -ne 0) { continue }
            $mounted = $true
        }
        try {
            $d = Get-TreehouseGitSessionDir -ProfileDir $p.Dir
            $want = @{ GH_CONFIG_DIR = (Join-Path $d 'gh'); GIT_CONFIG_GLOBAL = (Join-Path $d 'gitconfig') }
            $k = $users.CreateSubKey("$root\Environment")
            try {
                foreach ($n in $want.Keys) {
                    $cur = $k.GetValue($n, $null, 'DoNotExpandEnvironmentNames')
                    if ($Remove) {
                        if ($cur -eq $want[$n]) { $k.DeleteValue($n) }
                    } elseif ($cur -ne $want[$n]) {
                        $k.SetValue($n, $want[$n], 'String')
                    }
                }
            } finally {
                $k.Close()
            }
        } catch {
            Write-FcWarn "could not update GitHub session env for $($p.Sid): $($_.Exception.Message)"
        } finally {
            if ($mounted) {
                [GC]::Collect(); [GC]::WaitForPendingFinalizers()
                Invoke-FcNative $reg unload "HKU\$root" | Out-Null
            }
        }
    }
}

# Sign-in prompts for members (Linux: treehouse-git hint/welcome; same text).
# The login pop-up is a value under HKLM ...\Run: Explorer starts it in each
# interactive desktop logon only (not SSH, not tasks, not unlock), and only
# admins can change it. The Git Bash hint lives in Git for Windows' own
# etc\profile.d (Program Files: admin-only). Not covered: Windows PowerShell
# (an all-users profile is under System32 and breaks under the default
# Restricted execution policy) and cmd.exe (AutoRun runs for every cmd, scripts
# included); the login pop-up covers those users.
$script:WelcomeRunKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
$script:WelcomeRunName = 'FacilityCacheGitHubSignIn'

function Get-FcGitBashHintPath {
    # <Git for Windows root>\etc\profile.d\treehouse-git.sh, from the trusted git.
    $git = Get-FcTrustedCommand git
    if (-not $git) { return $null }
    $root = Split-Path -Parent (Split-Path -Parent $git)
    $dir = Join-Path $root 'etc\profile.d'
    if (-not (Test-Path -LiteralPath $dir -PathType Container)) { return $null }
    return (Join-Path $dir 'treehouse-git.sh')
}

function Set-TreehouseGitPrompts {
    param([switch]$Remove)
    $cfg = Get-FacilityCacheConfig
    $welcome = (-not $Remove) -and ($cfg.SignInPromptAtLogin -ne $false)
    if ($welcome) {
        $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $script = Join-Path (Get-FacilityCacheInstallDir) 'Treehouse-Git.ps1'
        $cmd = "`"$ps`" -NoProfile -ExecutionPolicy Bypass -File `"$script`" welcome"
        if ((Get-ItemProperty -LiteralPath $script:WelcomeRunKey -Name $script:WelcomeRunName -ErrorAction SilentlyContinue).$script:WelcomeRunName -ne $cmd) {
            New-ItemProperty -LiteralPath $script:WelcomeRunKey -Name $script:WelcomeRunName -Value $cmd -PropertyType String -Force | Out-Null
        }
    } else {
        Remove-ItemProperty -LiteralPath $script:WelcomeRunKey -Name $script:WelcomeRunName -ErrorAction SilentlyContinue
    }
    $hint = Get-FcGitBashHintPath
    if (-not $hint) { return }
    if ($Remove) {
        Remove-Item -LiteralPath $hint -Force -ErrorAction SilentlyContinue
        return
    }
    # Builtins only (no gh, no PowerShell): this runs at every Git Bash start.
    # Git Bash cannot run a .cmd without its extension, hence the function.
    $body = @'
# facility-cache-managed: GitHub sign-in hint for interactive Git Bash on this shared machine.
treehouse-git() { treehouse-git.cmd "$@"; }
case $- in *i*) ;; *) return 0 ;; esac
_th_s="${LOCALAPPDATA//\\//}/FacilityCache/gh-session"
_th_login="" _th_exp=0 _th_now=0
[ -s "$_th_s/login" ] && read -r _th_login <"$_th_s/login"
[ -r "$_th_s/expires" ] && read -r _th_exp <"$_th_s/expires"
_th_login="${_th_login%$'\r'}" _th_exp="${_th_exp%$'\r'}"
printf -v _th_now '%(%s)T' -1
if [ -n "$_th_login" ] && [[ "$_th_exp" =~ ^[0-9]+$ ]] && ((_th_now < _th_exp)); then
  _th_left=$((_th_exp - _th_now))
  echo "Signed in to GitHub as $_th_login ($((_th_left / 3600))h $((_th_left % 3600 / 60))m left)"
else
  echo "Not signed in to GitHub. Run: treehouse-git signin"
fi
unset _th_s _th_login _th_exp _th_now _th_left
'@
    $body = $body.Replace("`r`n", "`n")
    $cur = $null
    if (Test-Path -LiteralPath $hint) { $cur = [IO.File]::ReadAllText($hint) }
    if ($cur -ne $body) { [IO.File]::WriteAllText($hint, $body, (New-Object Text.UTF8Encoding($false))) }
}

function Get-TreehouseGitHint {
    # One line for a terminal; file reads only.
    $d = Get-TreehouseGitSessionDir
    $login = ''
    try { $login = ([string](Get-Content -LiteralPath (Join-Path $d 'login') -Raw -ErrorAction Stop)).Trim() } catch { }
    $left = (Get-TreehouseGitSessionExpiry -Dir $d) - [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    if ($login -and $left -gt 0) {
        return ('Signed in to GitHub as {0} ({1}h {2}m left)' -f $login, [Math]::Floor($left / 3600), [Math]::Floor(($left % 3600) / 60))
    }
    return 'Not signed in to GitHub. Run: treehouse-git signin'
}

function Show-TreehouseGitWelcome {
    # Login pop-up (HKLM Run): quiet unless a member on a shared machine with no live session.
    $cfg = Get-FacilityCacheConfig
    if ($cfg.SharedMachine -ne $true -or (Test-FcElevated)) { return }
    if ((Get-TreehouseGitHint) -like 'Signed in*') { return }
    Write-Host ''
    Write-Host '  This is a shared computer, and you are not signed in to GitHub.'
    Write-Host '  Sign in now so your commits and pushes are made as you. The sign-in ends'
    Write-Host "  when you log out, or after $($cfg.GhSessionHours) hours. Later: treehouse-git signin"
    Write-Host ''
    try { [void](Read-Host '  Press Enter to sign in now, or close this window to skip') } catch { return }
    [void](Start-TreehouseGitSession)
    try { [void](Read-Host '  Press Enter to close this window') } catch { }
}

function Disable-TreehouseGitSharedMachine {
    # SharedMachine off / uninstall: remove our user-scope env, the system git
    # include, the sign-in prompts, and every session.
    param([switch]$IncludeUnloaded)
    Set-TreehouseGitUserEnv -Remove -IncludeUnloaded:$IncludeUnloaded
    Set-TreehouseGitPrompts -Remove
    $include = (Join-Path (Get-FacilityCacheInstallDir) 'shared.gitconfig').Replace('\', '/')
    if (@(Invoke-FcSystemGit config --system --get-all include.path) -contains $include) {
        Invoke-FcSystemGit config --system --fixed-value --unset-all include.path $include | Out-Null
        if ($LASTEXITCODE -ne 0) { Write-FcWarn "git: could not remove the shared.gitconfig include (exit $LASTEXITCODE)" }
    }
    [void](Reset-TreehouseGitSession)
}

function Set-TreehouseGitSharedMachine {
    $cfg = Get-FacilityCacheConfig
    # Earlier versions published one member-writable dir at MACHINE scope; drop those.
    $old = Join-Path (Get-FacilityCacheInstallDir) 'gh-session'
    if ([Environment]::GetEnvironmentVariable('GH_CONFIG_DIR', 'Machine') -eq (Join-Path $old 'gh')) {
        Set-MachineEnv -Name 'GH_CONFIG_DIR' -Value $null
    }
    if ([Environment]::GetEnvironmentVariable('GIT_CONFIG_GLOBAL', 'Machine') -eq (Join-Path $old 'gitconfig')) {
        Set-MachineEnv -Name 'GIT_CONFIG_GLOBAL' -Value $null
    }
    if ($cfg.SharedMachine -ne $true) {
        Disable-TreehouseGitSharedMachine
        return
    }
    [void](Reset-TreehouseGitSession -OnlyIfExpired)
    Set-TreehouseGitUserEnv
    Set-TreehouseGitPrompts
    $include = (Join-Path (Get-FacilityCacheInstallDir) 'shared.gitconfig').Replace('\', '/')
    if (@(Invoke-FcSystemGit config --system --get-all include.path) -notcontains $include) {
        Invoke-FcSystemGit config --system --add include.path $include | Out-Null
        # 127 = no trusted git: the installer warns about that once; don't log it every 5 minutes.
        if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 127) { Write-FcWarn "git: could not add the shared.gitconfig include (exit $LASTEXITCODE)" }
    }
}

function Start-TreehouseGitSession {
    # Member sign-in (non-admin). Returns $true when signed in.
    $cfg = Get-FacilityCacheConfig
    if ($cfg.SharedMachine -ne $true) {
        Write-FcFail 'treehouse-git is only for shared machines (SharedMachine in config.json)'
        return $false
    }
    foreach ($tool in @('gh', 'git')) {
        if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
            Write-FcFail "$tool is not installed on this computer; ask an admin to install it machine-wide (docs/SHARED-MACHINES.md)"
            return $false
        }
    }
    # Fail closed: never sign in on top of anything an earlier session left behind.
    if (-not (Reset-TreehouseGitSession)) { return $false }
    $d = Get-TreehouseGitSessionDir
    New-Item -ItemType Directory -Path $d -Force | Out-Null
    if (@(Get-ChildItem -LiteralPath $d -Force).Count -ne 0) {
        Write-FcFail "$d is not empty; not signing in"
        return $false
    }
    # Written before login so an interrupted sign-in still expires.
    $expires = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() + [long]([double]$cfg.GhSessionHours * 3600)
    Set-Content -LiteralPath (Join-Path $d 'expires') -Value $expires -Encoding ASCII
    $env:GH_CONFIG_DIR = Join-Path $d 'gh'
    $env:GIT_CONFIG_GLOBAL = Join-Path $d 'gitconfig'
    $env:GH_PROMPT_DISABLED = '1'
    Remove-Item Env:GH_TOKEN, Env:GITHUB_TOKEN, Env:GH_HOST -ErrorAction SilentlyContinue

    Write-Host ''
    Write-Host '  Sign in to GitHub as yourself:' -ForegroundColor Cyan
    Write-Host '    1. ON YOUR PHONE, open https://github.com/login/device'
    Write-Host '    2. Enter the one-time code shown below and approve'
    Write-Host '  Do not sign in to GitHub in this computer''s browser.' -ForegroundColor Yellow
    Write-Host ''
    # Not redirected (gh prints the device code on stderr); Continue so 5.1 can't turn it into an error.
    & { $ErrorActionPreference = 'Continue'; & gh auth login --hostname github.com --git-protocol https --web --insecure-storage --skip-ssh-key | Out-Host }
    if ($LASTEXITCODE -ne 0) {
        [void](Reset-TreehouseGitSession)
        Write-FcFail 'GitHub sign-in did not complete'
        return $false
    }

    # gh prints UTF-8; 5.1 would decode it with the OEM code page and mangle names.
    $prevEnc = [Console]::OutputEncoding
    try {
        [Console]::OutputEncoding = [Text.Encoding]::UTF8
        $info = & { $ErrorActionPreference = 'Continue'; & gh api user --jq '[.login, .id, (.name // .login)] | @tsv' }
    } finally {
        [Console]::OutputEncoding = $prevEnc
    }
    $f = @(([string]$info).Trim() -split "`t")
    if ($f.Count -lt 2 -or $f[0] -notmatch '^[A-Za-z0-9-]+$' -or $f[1] -notmatch '^\d+$') {
        [void](Reset-TreehouseGitSession)
        Write-FcFail 'could not read your GitHub profile'
        return $false
    }
    $login = $f[0]
    $name = $login
    if ($f.Count -ge 3 -and $f[2].Trim()) { $name = $f[2].Trim() }
    Invoke-FcNative git config --global user.name $name
    Invoke-FcNative git config --global user.email "$($f[1])+$login@users.noreply.github.com"
    if ($LASTEXITCODE -ne 0) {
        [void](Reset-TreehouseGitSession)
        Write-FcFail 'could not write your git identity'
        return $false
    }
    Set-Content -LiteralPath (Join-Path $d 'login') -Value $login -Encoding ASCII
    Write-FcOk "signed in to GitHub as $login ($name)"
    Write-FcNote "until $([DateTimeOffset]::FromUnixTimeSeconds($expires).LocalDateTime.ToString('ddd HH:mm')), or until you log off or run: treehouse-git signout"
    return $true
}

function Show-TreehouseGitSession {
    $login = ''
    try {
        $login = ([string](Get-Content -LiteralPath (Join-Path (Get-TreehouseGitSessionDir) 'login') -Raw -ErrorAction Stop)).Trim()
    } catch { }
    $left = (Get-TreehouseGitSessionExpiry) - [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    if ($login -and $left -gt 0) {
        Write-FcOk ('signed in to GitHub as {0}  {1}h {2}m left' -f $login, [Math]::Floor($left / 3600), [Math]::Floor(($left % 3600) / 60))
    } else {
        Write-FcNote 'not signed in to GitHub  (treehouse-git signin)'
    }
}

function ConvertTo-FacilityCacheVersion {
    param([string]$Version)
    $Version = $Version.Trim().TrimStart('v')
    $parts = @()
    foreach ($bit in $Version.Split('.')) {
        $num = 0
        if ($bit -match '^(\d+)') { $num = [int]$Matches[1] }
        $parts += $num
    }
    while ($parts.Count -lt 3) { $parts += 0 }
    return @{ Major = $parts[0]; Minor = $parts[1]; Patch = $parts[2] }
}

function Test-FacilityCacheVersionNewer {
    param([string]$Remote, [string]$Local)
    $a = ConvertTo-FacilityCacheVersion $Remote
    $b = ConvertTo-FacilityCacheVersion $Local
    if ($a.Major -ne $b.Major) { return ($a.Major -gt $b.Major) }
    if ($a.Minor -ne $b.Minor) { return ($a.Minor -gt $b.Minor) }
    return ($a.Patch -gt $b.Patch)
}

function Update-GitHubCliPath {
    $machine = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $user = [Environment]::GetEnvironmentVariable('Path', 'User')
    if (-not $machine) { $machine = '' }
    if (-not $user) { $user = '' }
    $env:Path = "$machine;$user;$env:Path"
    $pf = Join-Path $env:ProgramFiles 'GitHub CLI'
    $exe = Join-Path $pf 'gh.exe'
    if (Test-Path -LiteralPath $exe) {
        $env:Path = "$pf;$env:Path"
    }
}

function Test-FcGitHubCliSigner {
    # gh's MSI is Authenticode-signed (Microsoft Trusted Signing as of v2.104.0)
    # with subject CN=GitHub, Inc. / O=GitHub, Inc. / C=US. Match those three RDNs
    # exactly (case-sensitive); any other signer is refused.
    param($Certificate)
    $rdn = @{}
    foreach ($line in ($Certificate.SubjectName.Format($true) -split "`r?`n")) {
        if ($line -match '^\s*([A-Za-z]+)=(.*)$') { $rdn[$Matches[1]] = $Matches[2].Trim().Trim('"') }
    }
    return ($rdn['CN'] -ceq 'GitHub, Inc.' -and $rdn['O'] -ceq 'GitHub, Inc.' -and $rdn['C'] -ceq 'US')
}

function Sync-FacilityCacheGitHubCli {
    # Install gh if missing; winget-upgrade (or GitHub Releases MSI) if present.
    # Returns $true when a trusted gh (see Get-FcTrustedCommand) exists afterwards.
    # Never throws.
    Update-GitHubCliPath
    $winget = Get-FcTrustedCommand winget
    $gh = Get-FcTrustedCommand gh
    if ($winget) {
        $wgArgs = @('--accept-package-agreements', '--accept-source-agreements')
        try {
            if ($gh) {
                Invoke-FcNative $winget upgrade --id GitHub.cli @wgArgs | Out-Null
            } else {
                Invoke-FcNative $winget install --id GitHub.cli -e --source winget @wgArgs | Out-Null
            }
        } catch { }
        Update-GitHubCliPath
        if (Get-FcTrustedCommand gh) { return $true }
    }
    $tmp = $null
    try {
        $headers = New-FcGitHubHeaders -Uri 'https://api.github.com/repos/cli/cli/releases/latest'
        $release = Invoke-RestMethod -Uri 'https://api.github.com/repos/cli/cli/releases/latest' -Headers $headers
        $asset = $release.assets | Where-Object { $_.name -like '*windows_amd64.msi' } | Select-Object -First 1
        if ($asset) {
            # Never a predictable path in SYSTEM's %TEMP% (C:\Windows\Temp is
            # Users-writable): a member could pre-create and swap the MSI.
            $tmp = New-FacilityCacheTempDir
            $msi = Join-Path $tmp 'gh.msi'
            Invoke-WebRequest -Uri $asset.browser_download_url -Headers $headers -OutFile $msi -UseBasicParsing
            $sig = Get-AuthenticodeSignature -FilePath $msi
            if ($sig.Status -ne 'Valid' -or -not $sig.SignerCertificate -or -not (Test-FcGitHubCliSigner $sig.SignerCertificate)) {
                Write-FcWarn "gh MSI signature rejected (status $($sig.Status), signer $($sig.SignerCertificate.Subject)); not installing it"
            } else {
                $msiexec = Join-Path $env:SystemRoot 'System32\msiexec.exe'
                Start-Process -FilePath $msiexec -ArgumentList @('/i', "`"$msi`"", '/qn', '/norestart') -Wait | Out-Null
                Update-GitHubCliPath
            }
        }
    } catch {
        Write-FcWarn "gh install from GitHub Releases failed: $($_.Exception.Message)"
    } finally {
        if ($tmp) { try { [IO.Directory]::Delete($tmp, $true) } catch { } }
    }
    return [bool](Get-FcTrustedCommand gh)
}

function Get-FacilityCacheAttestationBundle {
    # Fetches every attestation bundle for $Path's sha256 from the PUBLIC
    # GitHub attestations API (no credentials required — a token, if
    # supplied, only lifts the 60/hr/IP unauthenticated rate limit) and
    # returns them newline-joined as JSON Lines (one bundle object per
    # line — `gh attestation verify --bundle` accepts that form), already
    # filtered to $RepoId when one is pinned. Returns $null on any failure
    # or when nothing is left after filtering.
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [string]$Token,
        [Parameter(Mandatory = $true)][string]$RepoId
    )
    $hash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    # By immutable id: no name, no redirect.
    $uri = "https://api.github.com/repositories/$RepoId/attestations/sha256:$hash"
    $headers = New-FcGitHubHeaders -Uri $uri
    $resp = $null
    if ($Token) {
        try {
            $resp = Invoke-WebRequest -Uri $uri -Headers (New-FcGitHubHeaders -Uri $uri -Token $Token) -UseBasicParsing -TimeoutSec 30
        } catch {
            $status = 0
            if ($_.Exception.Response) { $status = [int]$_.Exception.Response.StatusCode }
            if ($status -eq 401 -or $status -eq 403) {
                # A stale/bad token — this endpoint is public, so retry once
                # without it rather than silently disabling attestation.
                $resp = Invoke-WebRequest -Uri $uri -Headers $headers -UseBasicParsing -TimeoutSec 30
            } else {
                throw
            }
        }
    } else {
        $resp = Invoke-WebRequest -Uri $uri -Headers $headers -UseBasicParsing -TimeoutSec 30
    }

    # Do NOT round-trip through ConvertFrom-Json/ConvertTo-Json here — that
    # corrupted the bundle in testing. JavaScriptSerializer preserves it
    # losslessly, as long as we only serialize the object graph that came
    # straight out of DeserializeObject rather than one PowerShell has
    # reassigned piece-by-piece (see Merge-DockerDaemonJson above for why
    # the latter breaks — PSObject wrappers make it walk a circular ref).
    Add-Type -AssemblyName System.Web.Extensions -ErrorAction Stop
    $ser = New-Object System.Web.Script.Serialization.JavaScriptSerializer
    $ser.MaxJsonLength = [int]::MaxValue
    $obj = $ser.DeserializeObject($resp.Content)
    if (-not $obj.ContainsKey('attestations') -or $obj['attestations'].Count -lt 1) { return $null }

    $lines = New-Object 'System.Collections.Generic.List[string]'
    foreach ($att in $obj['attestations']) {
        if ($RepoId -and $att.ContainsKey('repository_id') -and ([string]$att['repository_id']) -ne ([string]$RepoId)) {
            continue
        }
        if (-not $att.ContainsKey('bundle') -or $null -eq $att['bundle']) { continue }
        [void]$lines.Add($ser.Serialize($att['bundle']))
    }
    if ($lines.Count -lt 1) { return $null }
    return [string]::Join("`n", $lines.ToArray())
}

function Test-FcAttestationIdentity {
    # Checks `gh attestation verify --format json` output against IMMUTABLE
    # identity, not names (a pre-rename release names the old repo; a name can be
    # re-registered). Some verified attestation must have: source repo id =
    # $RepoId, owner id = $OwnerId, a GitHub Actions OIDC issuer, a GitHub-hosted
    # runner, source ref refs/tags/v$Version, and signer/build workflow
    # .github/workflows/release.yml of that same repo at that same tag.
    # Returns '' when satisfied, else the reason. Any missing field fails.
    param([string]$Json, [string]$RepoId, [string]$OwnerId, [string]$Version)
    if ($RepoId -notmatch '^\d+$' -or $OwnerId -notmatch '^\d+$' -or $Version -notmatch '^v?\d+\.\d+\.\d+$') { return 'pinned repo id, owner id or version missing' }
    try { $results = @(ConvertFrom-Json -InputObject $Json) } catch { return 'gh output is not JSON' }
    $ref = 'refs/tags/v' + $Version.TrimStart('v')
    $why = 'gh reported no verified attestation'
    foreach ($r in $results) {
        $c = $r.verificationResult.signature.certificate
        if (-not $c -or -not $c.sourceRepositoryIdentifier) {
            $why = 'this gh does not report the source repository id; upgrade gh'
            continue
        }
        $wf = [string]$c.sourceRepositoryURI + '/.github/workflows/release.yml@' + $ref
        if ([string]$c.sourceRepositoryIdentifier -ne $RepoId) { $why = "built in repo id $($c.sourceRepositoryIdentifier), not $RepoId" }
        elseif ([string]$c.sourceRepositoryOwnerIdentifier -ne $OwnerId) { $why = "owner id $($c.sourceRepositoryOwnerIdentifier), not $OwnerId" }
        elseif ([string]$c.issuer -cne 'https://token.actions.githubusercontent.com') { $why = "issuer $($c.issuer)" }
        elseif ([string]$c.runnerEnvironment -cne 'github-hosted') { $why = "runner $($c.runnerEnvironment)" }
        elseif ([string]$c.sourceRepositoryRef -cne $ref) { $why = "built from $($c.sourceRepositoryRef), not $ref" }
        elseif (-not ([string]$c.sourceRepositoryURI).StartsWith('https://github.com/', [StringComparison]::Ordinal)) { $why = "source $($c.sourceRepositoryURI)" }
        elseif ([string]$c.buildSignerURI -cne $wf -or [string]$c.buildConfigURI -cne $wf -or [string]$c.subjectAlternativeName -cne $wf) { $why = "signed by $($c.buildSignerURI), not $wf" }
        else { return '' }
    }
    return $why
}

function Test-FacilityCacheAttestation {
    # Never-throws build-provenance check of $Path. gh does the cryptography
    # offline (`--bundle`, no `gh auth login`); Test-FcAttestationIdentity then
    # checks the certified identity. Returns '' when verified, else the reason.
    # $Owner, $OwnerId come from /repositories/<pinned id>; $Version is the
    # version being installed.
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$RepoId,
        [Parameter(Mandatory = $true)][string]$Owner,
        [Parameter(Mandatory = $true)][string]$OwnerId,
        [Parameter(Mandatory = $true)][string]$Version,
        [string]$Token
    )
    try {
        $ghPath = Get-FcTrustedCommand gh
        if (-not $ghPath) { return 'gh not available' }
        # It is spliced into gh's command line below.
        if ($Owner -notmatch '^[A-Za-z0-9-]+$') { return "bad owner name $Owner" }

        $bundleJsonl = Get-FacilityCacheAttestationBundle -Path $Path -Token $Token -RepoId $RepoId
        if ($null -eq $bundleJsonl) { return "no attestation published for repo id $RepoId" }

        # Next to $Path: callers keep it in a SYSTEM+Administrators-only temp dir.
        $bundleFile = "$Path.bundle.jsonl"
        try {
            # The Rekor checkpoint envelope embeds a literal U+2014 em-dash,
            # so this is NOT ASCII-safe (that silently mangled it to '?' and
            # broke verification in testing). A UTF-8 BOM would also break
            # Go's JSON parser, so write UTF-8 without one via .NET directly
            # rather than Set-Content, whose -Encoding UTF8 always adds a BOM.
            $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
            [System.IO.File]::WriteAllText($bundleFile, $bundleJsonl, $utf8NoBom)
            # Process.Start + WaitForExit(timeout), not `&`, so a wedged gh
            # can't hang a scheduled task forever.
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = $ghPath
            # --owner is required by gh; the real identity check is by id below.
            $psi.Arguments = "attestation verify `"$Path`" --bundle `"$bundleFile`" --owner $Owner --deny-self-hosted-runners --format json"
            # Never let gh read a config dir someone else could write.
            $psi.EnvironmentVariables['GH_CONFIG_DIR'] = Split-Path -Parent $Path
            $psi.UseShellExecute = $false
            $psi.RedirectStandardOutput = $true
            $psi.RedirectStandardError = $true
            $proc = [System.Diagnostics.Process]::Start($psi)
            # Drain both pipes while waiting: the JSON is larger than a pipe buffer.
            $out = $proc.StandardOutput.ReadToEndAsync()
            $err = $proc.StandardError.ReadToEndAsync()
            if (-not $proc.WaitForExit(60000)) {
                $proc.Kill()
                return 'gh attestation verify timed out'
            }
            if ($proc.ExitCode -ne 0) { return "gh attestation verify failed: $(([string]$err.Result).Trim())" }
            return (Test-FcAttestationIdentity -Json $out.Result -RepoId $RepoId -OwnerId $OwnerId -Version $Version)
        } finally {
            Remove-Item -LiteralPath $bundleFile -Force -ErrorAction SilentlyContinue
        }
    } catch {
        return "attestation check error: $($_.Exception.Message)"
    }
}

function Write-FacilityCacheState {
    param($Data)
    $dir = Get-FacilityCacheInstallDir
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $Data | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $dir 'state.json') -Encoding UTF8
}

function Update-FacilityCacheClient {
    param(
        [switch]$Check,
        [switch]$Force
    )
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $cfg = Get-FacilityCacheConfig
    $local = Get-FacilityCacheInstalledVersion
    $agent = "facility-cache-client/$local"
    $token = $cfg.GitHubToken
    $repoId = [string]$cfg.GitHubRepoId
    $script:FcStepN = 6
    Write-FcHeader 'facility-cache-client' "update  v$local"
    Write-FcKv 'repo' "$($cfg.GitHubRepo)  (id $repoId)" 'work'
    Write-FcKv 'installed' $local 'ok'

    # Everything below is addressed by the immutable numeric id, never by a name:
    # a renamed repo's old name can be re-registered by anyone, and the redirect
    # GitHub sends for it makes Windows PowerShell drop the token (404 on private).
    Write-FcStep 'identity' "repo id $repoId"
    if ($repoId -notmatch '^\d+$') {
        Write-FacilityCacheState @{ installed_version = $local; last_result = 'refused: GitHubRepoId is not set' }
        Write-FcFail 'GitHubRepoId must be the numeric GitHub repository id; refusing to update from an unpinned name'
        if ($Check) { throw 'GitHubRepoId not set' }
        Write-FcFinish -Ok $false -Message 'refusing to update'
        return
    }
    try {
        $metaUri = "https://api.github.com/repositories/$repoId"
        $meta = Invoke-RestMethod -Uri $metaUri -Headers (New-FcGitHubHeaders -Uri $metaUri -Token $token -Agent $agent)
    } catch {
        Write-FacilityCacheState @{ installed_version = $local; last_result = "github error: $($_.Exception.Message)" }
        Write-FcFail $_
        if ($Check) { throw }
        Write-FcFinish -Ok $false -Message 'could not check GitHub'
        return
    }
    $repo = [string]$meta.full_name
    if ([string]$meta.id -ne $repoId -or $repo -notmatch '^[A-Za-z0-9-]+/[A-Za-z0-9._-]+$') {
        Write-FacilityCacheState @{ installed_version = $local; last_result = "refused: repo id $($meta.id) != pinned $repoId" }
        Write-FcFail "GitHub answered repo id $($meta.id) ($repo) for pinned $repoId; refusing to install from it"
        if ($Check) { throw "repo id mismatch" }
        Write-FcFinish -Ok $false -Message 'refusing to update'
        return
    }
    Write-FcStepOk "id $($meta.id)  $repo"
    if ($repo -ne $cfg.GitHubRepo) { Write-FcNote "repo is now named $repo (GitHubRepo in config is display only)" }

    Write-FcStep 'github' 'latest release'
    try {
        $relUri = "https://api.github.com/repos/$repo/releases/latest"
        $release = Invoke-RestMethod -Uri $relUri -Headers (New-FcGitHubHeaders -Uri $relUri -Token $token -Agent $agent)
    } catch {
        Write-FacilityCacheState @{ installed_version = $local; last_result = "github error: $($_.Exception.Message)" }
        Write-FcFail $_
        if ($Check) { throw }
        Write-FcFinish -Ok $false -Message 'could not check GitHub'
        return
    }

    $assets = @{}
    foreach ($a in $release.assets) { $assets[$a.name] = $a }
    if (-not $assets.ContainsKey('manifest.json')) {
        Write-FacilityCacheState @{ installed_version = $local; last_result = 'no manifest.json'; latest_tag = $release.tag_name }
        Write-FcFail 'Release has no manifest.json'
        Write-FcFinish -Ok $false -Message 'release incomplete'
        return
    }

    # Asset API URLs answer 302 to a signed objects.githubusercontent.com URL; the
    # token is only ever attached for api.github.com and is dropped on redirect.
    $save = {
        param($Url, $OutFile)
        Invoke-WebRequest -Uri $Url -Headers (New-FcGitHubHeaders -Uri $Url -Token $token -Accept 'application/octet-stream' -Agent $agent) -OutFile $OutFile -UseBasicParsing
    }

    $tmp = $null
    $remote = $local
    try {
        $tmp = New-FacilityCacheTempDir
        $tmpMan = Join-Path $tmp 'manifest.json'
        & $save $assets['manifest.json'].url $tmpMan
        $manifest = Get-Content -LiteralPath $tmpMan -Raw | ConvertFrom-Json
        $remote = ([string]$manifest.version).TrimStart('v')
        Write-FcStepOk "$($release.tag_name)  v$remote"
        Write-FcKv 'latest' "v$remote" $(if (Test-FacilityCacheVersionNewer $remote $local) { 'ok' } else { 'on' })
        if ($Check) {
            if (Test-FacilityCacheVersionNewer $remote $local) {
                Write-FcOk "update available  v$local -> v$remote"
            } else {
                Write-FcOk 'already the latest release'
            }
            Write-FcFinish -Ok $true -Message "log $(Get-FacilityCacheLogPath)"
            return
        }

        $auto = $true
        if ($null -ne $cfg.AutoUpdate) {
            $auto = [bool]$cfg.AutoUpdate
            if ($cfg.AutoUpdate -is [string]) {
                $auto = @('0', 'false', 'no', 'off') -notcontains $cfg.AutoUpdate.ToLowerInvariant()
            }
        }
        if (-not $auto -and -not $Force) {
            Write-FacilityCacheState @{
                installed_version = $local
                latest_version    = $remote
                last_result       = 'auto-update disabled'
            }
            Write-FcWarn 'AutoUpdate is disabled — pass -Force to install'
            Write-FcFinish -Ok $true -Message 'no changes'
            return
        }
        if (-not $Force -and -not (Test-FacilityCacheVersionNewer -Remote $remote -Local $local)) {
            Write-FacilityCacheState @{
                installed_version = $local
                latest_version    = $remote
                last_result       = 'up-to-date'
            }
            Write-FcOk 'already up to date'
            Write-FcStep 'gh' 'GitHub CLI'
            if (Sync-FacilityCacheGitHubCli) {
                Write-FcStepOk 'gh'
            } else {
                Write-FcWarn 'gh install skipped — the next update cannot verify build provenance'
            }
            Write-FcFinish -Ok $true -Message "v$local"
            return
        }

        $name = $manifest.assets.windows.name
        $expect = ([string]$manifest.assets.windows.sha256).ToLowerInvariant()
        if (-not $name -or -not $expect) { throw 'manifest.json missing windows asset name/sha256' }
        if (-not $assets.ContainsKey($name)) { throw "release is missing asset $name" }

        $zip = Join-Path $tmp ([IO.Path]::GetFileName($name))
        Write-FcStep 'download' $name
        & $save $assets[$name].url $zip
        Write-FcStepOk $name
        Write-FcStep 'verify' 'sha256'
        $got = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($got -ne $expect) { throw "sha256 mismatch: $got != $expect" }
        Write-FcStepOk ($got.Substring(0, 12) + '...')

        Write-FcStep 'gh' 'GitHub CLI'
        $haveGh = Sync-FacilityCacheGitHubCli
        if ($haveGh) { Write-FcStepOk 'gh' }

        # Nothing from the zip is extracted or run before this passes. With gh
        # present a missing or failing attestation is fatal; only a machine where
        # gh could not be installed falls back to sha256, and says so loudly.
        Write-FcStep 'attest' 'build provenance'
        if ($haveGh) {
            $why = Test-FacilityCacheAttestation -Path $zip -RepoId $repoId -Owner ([string]$meta.owner.login) `
                -OwnerId ([string]$meta.owner.id) -Version $remote -Token $token
            if ($why) { throw "build-provenance attestation for $name v${remote} not accepted: $why; refusing to install" }
            $attest = 'verified'
            Write-FcStepOk $attest
        } else {
            $attest = 'NOT VERIFIED: gh unavailable, sha256 only'
            Write-FcFail "gh could not be installed — installing v$remote WITHOUT build-provenance verification (sha256 only)"
        }

        Write-FcStep 'install' "v$remote"
        $src = Join-Path $tmp 'src'
        Expand-Archive -LiteralPath $zip -DestinationPath $src -Force
        $installer = Get-ChildItem -Path $src -Recurse -Filter 'Install-FacilityCache.ps1' | Select-Object -First 1
        if (-not $installer) { throw 'zip missing windows/Install-FacilityCache.ps1' }
        & (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -NoProfile -ExecutionPolicy Bypass -File $installer.FullName -NoRestartDocker
        # & powershell.exe never throws; without this a failed installer was logged as "updated".
        if ($LASTEXITCODE -ne 0) { throw "Install-FacilityCache.ps1 exited $LASTEXITCODE" }
        Write-FcStepOk "v$remote"
        Write-FacilityCacheState @{
            installed_version = $remote
            latest_version    = $remote
            last_result       = 'updated'
            from_tag          = $release.tag_name
            attestation       = $attest
        }
        Write-FcFinish -Ok $true -Message "now running v$remote"
    } catch {
        Write-FacilityCacheState @{ installed_version = $local; latest_version = $remote; last_result = "update failed: $($_.Exception.Message)" }
        Write-FcFail $_
        Write-FcFinish -Ok $false -Message 'update failed'
        throw
    } finally {
        if ($tmp) { try { [IO.Directory]::Delete($tmp, $true) } catch { } }
    }
}

Export-ModuleMember -Function @(
    'Get-FacilityCacheConfig',
    'Get-FacilityCacheInstalledVersion',
    'Get-FacilityCacheLogPath',
    'Test-FacilityCache',
    'Get-FacilityCacheStatus',
    'Show-FacilityCacheDashboard',
    'Show-FacilityCacheLog',
    'Merge-DockerDaemonJson',
    'Remove-DockerMirrors',
    'Set-DeliveryOptimizationDhcpDiscovery',
    'Remove-DeliveryOptimizationDhcpDiscovery',
    'Invoke-FacilityCacheApply',
    'Update-FacilityCacheClient',
    'Sync-FacilityCacheGitHubCli',
    'Test-FacilityCacheAttestation',
    'Protect-FacilityCacheInstallDir', 'Get-FcTrustedCommand',
    'Reset-TreehouseGitSession', 'Start-TreehouseGitSession', 'Show-TreehouseGitSession',
    'Get-TreehouseGitHint', 'Show-TreehouseGitWelcome',
    'Disable-TreehouseGitSharedMachine',
    'Write-FcHeader', 'Write-FcKv', 'Write-FcOk', 'Write-FcFail', 'Write-FcWarn',
    'Write-FcNote', 'Write-FcStep', 'Write-FcStepOk', 'Write-FcBar', 'Write-FcFinish'
)
