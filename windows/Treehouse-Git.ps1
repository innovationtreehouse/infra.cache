# Member entrypoint for shared-machine GitHub sign-in: treehouse-git signin|signout|status
# Runs as the (non-admin) member via %SystemRoot%\treehouse-git.cmd.
param(
    [Parameter(Position = 0)][ValidateSet('signin', 'signout', 'status')][string]$Command = 'status'
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'FacilityCache.psm1') -Force
switch ($Command) {
    'signin' { if (-not (Start-TreehouseGitSession)) { exit 1 } }
    'signout' { if (Reset-TreehouseGitSession) { Write-FcOk 'signed out of GitHub' } else { exit 1 } }
    'status' { Show-TreehouseGitSession }
}
