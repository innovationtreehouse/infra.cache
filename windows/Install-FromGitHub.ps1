#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Download the latest GitHub Release and install the Windows client.
#>
[CmdletBinding()]
param(
    # Display only: the release is located by the numeric id below.
    [string]$GitHubRepo = $(if ($env:GITHUB_REPO) { $env:GITHUB_REPO } else { 'innovationtreehouse/infra.cache' }),
    # Immutable numeric repo id — a renamed repo's re-registered name cannot fake it.
    [string]$GitHubRepoId = $(if ($env:GITHUB_REPO_ID) { $env:GITHUB_REPO_ID } else { '1343160243' }),
    [string]$GitHubToken = $(if ($env:GITHUB_TOKEN) { $env:GITHUB_TOKEN } else { '' })
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Write-Boot([string]$Msg, [string]$Color = 'Cyan') {
    Write-Host "  $Msg" -ForegroundColor $Color
}

# Nothing below may come from the zip until it has passed sha256 AND (when gh
# exists) attestation, so these helpers duplicate a few module functions.

function Get-BootHeaders([string]$Uri, [string]$Accept = 'application/vnd.github+json') {
    # Token only to https://api.github.com. Windows PowerShell drops Authorization
    # on every redirect, so it never follows a 302 to objects.githubusercontent.com.
    $h = @{ 'User-Agent' = 'facility-cache-client-bootstrap'; Accept = $Accept }
    $u = [Uri]$Uri
    if ($GitHubToken -and $u.Scheme -eq 'https' -and $u.Host -eq 'api.github.com') { $h['Authorization'] = "Bearer $GitHubToken" }
    return $h
}

function Find-BootTool([string]$Name) {
    # Only binaries under Program Files / Windows / this admin's own profile, never
    # one from a PATH folder a non-admin can write.
    $roots = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:SystemRoot, $env:LOCALAPPDATA) |
        Where-Object { $_ } | ForEach-Object { $_.TrimEnd('\') + '\' }
    foreach ($c in @(Get-Command $Name -CommandType Application -All -ErrorAction SilentlyContinue)) {
        $full = [IO.Path]::GetFullPath($c.Path)
        foreach ($r in $roots) { if ($full.StartsWith($r, [StringComparison]::OrdinalIgnoreCase)) { return $full } }
    }
    return $null
}

function Install-BootGitHubCli([string]$Dir) {
    # winget, else the cli/cli MSI — installed only if Authenticode is Valid and the
    # signer subject is exactly CN=GitHub, Inc. / O=GitHub, Inc. / C=US.
    try {
        $winget = Find-BootTool winget
        if ($winget) {
            & $winget install --id GitHub.cli -e --source winget --accept-package-agreements --accept-source-agreements 2>$null | Out-Null
        }
        $env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine') + ";$env:ProgramFiles\GitHub CLI;$env:Path"
        if (Find-BootTool gh) { return }
        $h = @{ 'User-Agent' = 'facility-cache-client-bootstrap'; Accept = 'application/vnd.github+json' }
        $rel = Invoke-RestMethod -Uri 'https://api.github.com/repos/cli/cli/releases/latest' -Headers $h
        $asset = $rel.assets | Where-Object { $_.name -like '*windows_amd64.msi' } | Select-Object -First 1
        if (-not $asset) { return }
        $msi = Join-Path $Dir 'gh.msi'
        Invoke-WebRequest -Uri $asset.browser_download_url -Headers $h -OutFile $msi -UseBasicParsing
        $sig = Get-AuthenticodeSignature -FilePath $msi
        $rdn = @{}
        if ($sig.SignerCertificate) {
            foreach ($line in ($sig.SignerCertificate.SubjectName.Format($true) -split "`r?`n")) {
                if ($line -match '^\s*([A-Za-z]+)=(.*)$') { $rdn[$Matches[1]] = $Matches[2].Trim().Trim('"') }
            }
        }
        if ($sig.Status -ne 'Valid' -or $rdn['CN'] -cne 'GitHub, Inc.' -or $rdn['O'] -cne 'GitHub, Inc.' -or $rdn['C'] -cne 'US') {
            Write-Host "  X  gh MSI signature rejected (status $($sig.Status))" -ForegroundColor Red
            return
        }
        Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\msiexec.exe') -ArgumentList @('/i', "`"$msi`"", '/qn', '/norestart') -Wait | Out-Null
    } catch {
        Write-Host "  !  gh install failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

function Test-BootAttestationIdentity {
    # Same rule as Test-FcAttestationIdentity in FacilityCache.psm1 (copied: see below).
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

function Test-BootstrapAttestation {
    # Never-throws build-provenance check on $Path — deliberately
    # duplicated here (rather than calling the same-named function the zip's
    # own FacilityCache.psm1 exports) because THIS script is verifying that
    # very zip: sourcing the checker from the archive under test would let a
    # malicious release ship a module whose Test-FacilityCacheAttestation just
    # returns $true, or omit the module entirely to skip the check. This copy
    # must run on $Path before it is ever Expand-Archive'd or Import-Module'd.
    #
    # Fetches every attestation bundle for $Path's sha256 from the PUBLIC
    # GitHub attestations API (no credentials required — a token, if
    # supplied, only lifts the 60/hr/IP unauthenticated rate limit), filters
    # to $RepoId, verifies them offline as JSON Lines with
    # `gh attestation verify --bundle` (no `gh auth login`), then checks the
    # certified identity by immutable ids. Returns '' when verified, else why.
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$RepoId,
        [Parameter(Mandatory = $true)][string]$Owner,
        [Parameter(Mandatory = $true)][string]$OwnerId,
        [Parameter(Mandatory = $true)][string]$Version,
        [string]$Token
    )
    try {
        $ghPath = Find-BootTool gh
        if (-not $ghPath) { return 'gh not available' }
        if ($Owner -notmatch '^[A-Za-z0-9-]+$') { return "bad owner name $Owner" }

        $hash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
        $uri = "https://api.github.com/repositories/$RepoId/attestations/sha256:$hash"
        $headers = @{ 'User-Agent' = 'facility-cache-client-bootstrap'; Accept = 'application/vnd.github+json' }
        $resp = $null
        if ($Token) {
            try {
                $resp = Invoke-WebRequest -Uri $uri -Headers (Get-BootHeaders $uri) -UseBasicParsing -TimeoutSec 30
            } catch {
                $status = 0
                if ($_.Exception.Response) { $status = [int]$_.Exception.Response.StatusCode }
                if ($status -eq 401 -or $status -eq 403) {
                    # A stale/bad token — this endpoint is public, so retry
                    # once without it rather than silently disabling this.
                    $resp = Invoke-WebRequest -Uri $uri -Headers $headers -UseBasicParsing -TimeoutSec 30
                } else {
                    throw
                }
            }
        } else {
            $resp = Invoke-WebRequest -Uri $uri -Headers $headers -UseBasicParsing -TimeoutSec 30
        }

        # Do NOT round-trip through ConvertFrom-Json/ConvertTo-Json here — it
        # corrupts the bundle (a literal U+2014 in the Rekor checkpoint gets
        # mangled). JavaScriptSerializer preserves it losslessly as long as
        # we only serialize the object graph straight out of DeserializeObject.
        Add-Type -AssemblyName System.Web.Extensions -ErrorAction Stop
        $ser = New-Object System.Web.Script.Serialization.JavaScriptSerializer
        $ser.MaxJsonLength = [int]::MaxValue
        $obj = $ser.DeserializeObject($resp.Content)
        if (-not $obj.ContainsKey('attestations') -or $obj['attestations'].Count -lt 1) { return "no attestation published for repo id $RepoId" }

        $lines = New-Object 'System.Collections.Generic.List[string]'
        foreach ($att in $obj['attestations']) {
            if ($RepoId -and $att.ContainsKey('repository_id') -and ([string]$att['repository_id']) -ne ([string]$RepoId)) {
                continue
            }
            if (-not $att.ContainsKey('bundle') -or $null -eq $att['bundle']) { continue }
            [void]$lines.Add($ser.Serialize($att['bundle']))
        }
        if ($lines.Count -lt 1) { return "no attestation published for repo id $RepoId" }
        $bundleJsonl = [string]::Join("`n", $lines.ToArray())

        # Next to $Path, in the SYSTEM+Administrators-only temp dir.
        $bundleFile = "$Path.bundle.jsonl"
        try {
            # A UTF-8 BOM would break Go's JSON parser, so write UTF-8
            # without one via .NET directly rather than Set-Content, whose
            # -Encoding UTF8 always adds a BOM in PS 5.1.
            $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
            [System.IO.File]::WriteAllText($bundleFile, $bundleJsonl, $utf8NoBom)
            # Process.Start + WaitForExit(timeout), not `&`, so a wedged gh
            # can't hang this install forever.
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
            return (Test-BootAttestationIdentity -Json $out.Result -RepoId $RepoId -OwnerId $OwnerId -Version $Version)
        } finally {
            Remove-Item -LiteralPath $bundleFile -Force -ErrorAction SilentlyContinue
        }
    } catch {
        return "attestation check error: $($_.Exception.Message)"
    }
}

Write-Host ''
Write-Host '  facility-cache-client' -ForegroundColor Cyan -NoNewline
Write-Host '  bootstrap from GitHub' -ForegroundColor DarkGray
Write-Host ('  ' + ('-' * 48)) -ForegroundColor DarkGray

# Located by id, never by name: an old name can be re-registered, and the
# redirect GitHub sends for it would arrive here without the token.
if ($GitHubRepoId -notmatch '^\d+$') { throw 'GitHubRepoId must be the numeric GitHub repository id' }
$metaUri = "https://api.github.com/repositories/$GitHubRepoId"
$meta = Invoke-RestMethod -Uri $metaUri -Headers (Get-BootHeaders $metaUri)
$repo = [string]$meta.full_name
if ([string]$meta.id -ne $GitHubRepoId -or $repo -notmatch '^[A-Za-z0-9-]+/[A-Za-z0-9._-]+$') {
    Write-Host "  X  GitHub answered repo id $($meta.id) for pinned $GitHubRepoId — refusing to install" -ForegroundColor Red
    throw 'Repository id mismatch'
}
Write-Boot "github  $repo  (id $GitHubRepoId)" 'Green'
if ($repo -ne $GitHubRepo) { Write-Boot "(repo is now named $repo, not $GitHubRepo)" 'DarkGray' }

$relUri = "https://api.github.com/repos/$repo/releases/latest"
$release = Invoke-RestMethod -Uri $relUri -Headers (Get-BootHeaders $relUri)
$assets = @{}
foreach ($a in $release.assets) { $assets[$a.name] = $a }
if (-not $assets.ContainsKey('manifest.json')) {
    Write-Host '  X  release has no manifest.json' -ForegroundColor Red
    throw 'Release has no manifest.json'
}

# Random name + SYSTEM/Administrators-only ACL. Under SYSTEM's %TEMP%
# (C:\Windows\Temp) non-admins can create entries but cannot list it (so cannot
# learn this name) and cannot delete or enter a dir they do not own.
$tmp = Join-Path $env:TEMP ('facility-cache-' + [guid]::NewGuid().ToString('N'))
if (Test-Path -LiteralPath $tmp) { throw "temp dir $tmp already exists" }
$tmpItem = New-Item -ItemType Directory -Path $tmp
$acl = $tmpItem.GetAccessControl()
$acl.SetAccessRuleProtection($true, $false)
foreach ($r in @($acl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]))) { $acl.RemoveAccessRuleSpecific($r) }
foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
        (New-Object Security.Principal.SecurityIdentifier $sid), 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow')))
}
$tmpItem.SetAccessControl($acl)
try {
    $manPath = Join-Path $tmp 'manifest.json'
    $u = $assets['manifest.json'].url
    Invoke-WebRequest -Uri $u -Headers (Get-BootHeaders $u 'application/octet-stream') -OutFile $manPath -UseBasicParsing
    $manifest = Get-Content -LiteralPath $manPath -Raw | ConvertFrom-Json
    $name = $manifest.assets.windows.name
    $expect = ([string]$manifest.assets.windows.sha256).ToLowerInvariant()
    if (-not $name -or -not $expect -or -not $assets.ContainsKey($name)) { throw 'manifest.json / release missing the windows asset' }
    Write-Boot "download  $name"
    $zip = Join-Path $tmp ([IO.Path]::GetFileName($name))
    $u = $assets[$name].url
    Invoke-WebRequest -Uri $u -Headers (Get-BootHeaders $u 'application/octet-stream') -OutFile $zip -UseBasicParsing
    $got = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($got -ne $expect) { throw "sha256 mismatch: $got != $expect" }
    Write-Host "  +  sha256  v$($manifest.version)" -ForegroundColor Green

    # Attest BEFORE the zip is extracted: the verdict on this archive must never
    # come from code inside it. With gh present, failure is fatal.
    if (-not (Find-BootTool gh)) {
        Write-Boot 'gh  GitHub CLI'
        Install-BootGitHubCli $tmp
    }
    if (Find-BootTool gh) {
        Write-Boot 'attest  build provenance'
        $why = Test-BootstrapAttestation -Path $zip -RepoId $GitHubRepoId -Owner ([string]$meta.owner.login) `
            -OwnerId ([string]$meta.owner.id) -Version ([string]$manifest.version) -Token $GitHubToken
        if ($why) {
            Write-Host "  X  attestation not accepted for $name ($why) — refusing to install" -ForegroundColor Red
            throw "build-provenance attestation not accepted: $why"
        }
        Write-Host "  +  attested  $name" -ForegroundColor Green
    } else {
        Write-Host '  X  gh could not be installed — installing WITHOUT build-provenance verification (sha256 only)' -ForegroundColor Red
    }

    $src = Join-Path $tmp 'src'
    Expand-Archive -LiteralPath $zip -DestinationPath $src -Force
    $installer = Get-ChildItem -Path $src -Recurse -Filter 'Install-FacilityCache.ps1' | Select-Object -First 1
    if (-not $installer) { throw 'zip missing windows/Install-FacilityCache.ps1' }
    & (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -NoProfile -ExecutionPolicy Bypass -File $installer.FullName
    if ($LASTEXITCODE -ne 0) { throw "Install-FacilityCache.ps1 exited $LASTEXITCODE" }
} finally {
    try { [IO.Directory]::Delete($tmp, $true) } catch { }
}
