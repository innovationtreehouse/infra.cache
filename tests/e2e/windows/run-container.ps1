# Drives the Windows-container E2E on a windows-2022 runner (Windows containers,
# process isolation). The fake cache runs on the runner host; the client runs
# inside servercore:ltsc2022 (real Windows PowerShell 5.1, ContainerAdministrator).
param([string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path)
$ErrorActionPreference = 'Stop'

Write-Host '--- fake cache on runner host ---'
New-NetFirewallRule -DisplayName 'fc-e2e-cache' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 3141, 3142, 4873, 5000, 5001 | Out-Null
$cache = Start-Process python -ArgumentList (Join-Path $RepoRoot 'tests\e2e\cache\fakecache.py') -PassThru -NoNewWindow -RedirectStandardOutput cache.log -RedirectStandardError cache.err
Start-Sleep -Seconds 3
if ($cache.HasExited) { Get-Content cache.err; throw 'fake cache failed to start' }

Write-Host '--- client container (servercore ltsc2022, PS 5.1) ---'
# The runner image sometimes hands over the job before the Docker engine is up
# (seen as "failed to connect to the docker API at npipe:////./pipe/docker_engine").
# Start it if needed and wait; cmd swallows stderr so PS 5.1 + Stop does not throw.
$dockerReady = $false
foreach ($i in 1..40) {
    cmd /c 'docker version >nul 2>&1'
    if ($LASTEXITCODE -eq 0) { $dockerReady = $true; break }
    if ($i -eq 1) { Start-Service docker -ErrorAction SilentlyContinue }
    Start-Sleep -Seconds 3
}
if (-not $dockerReady) { throw 'docker engine did not come up within 2 minutes' }
docker pull -q mcr.microsoft.com/windows/servercore:ltsc2022
if ($LASTEXITCODE -ne 0) { throw 'docker pull failed' }
docker run -d --name fc-win-client mcr.microsoft.com/windows/servercore:ltsc2022 cmd /c ping -t localhost | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'docker run failed' }
docker cp $RepoRoot fc-win-client:C:\src
if ($LASTEXITCODE -ne 0) { throw 'docker cp failed' }

# The container reaches the runner host via its NAT default gateway.
$gw = (docker exec fc-win-client powershell -NoProfile -Command "(Get-NetRoute -DestinationPrefix 0.0.0.0/0 | Select-Object -First 1).NextHop").Trim()
Write-Host "container->host gateway: $gw"
docker exec fc-win-client powershell -NoProfile -Command "Add-Content -Path C:\Windows\System32\drivers\etc\hosts -Value '$gw cache.facility.test'"

Write-Host '--- harness inside the container ---'
docker exec -e GITHUB_TOKEN fc-win-client powershell -NoProfile -ExecutionPolicy Bypass -File C:\src\tests\e2e\windows\harness.ps1 -CacheHost cache.facility.test -ExpectedIp $gw -RepoRoot C:\src
$rc = $LASTEXITCODE
Write-Host '--- cache request log (tail) ---'
Get-Content cache.log -Tail 30 -ErrorAction SilentlyContinue
exit $rc
