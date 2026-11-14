# Facility cache client

Points Ubuntu and Windows machines at `cache.facility.innovationtreehouse.org` **only while they are on the facility LAN**. Off-site, the hostname does not resolve in public DNS, so clients go direct to Ubuntu/PyPI/npm/Docker Hub/Microsoft. That detection trusts the local resolver: a hostile network (rogue DHCP/DNS) can fake being the facility and receive pip/npm/Docker traffic over plain HTTP — see [`docs/SECURITY.md`](docs/SECURITY.md#lan-trust-not-transport-security).

Never uses `10.41.1.50` or the short name `cache` in client config (those collide on other networks). The probe requires the FQDN to resolve to **exactly** `10.41.1.50`.

Installed clients **update themselves from GitHub Releases**, as root/SYSTEM. A new tag publishes new scripts *and* new package defaults (host, ports, repo). Local override files are not overwritten.

Default repo: `innovationtreehouse/infra.cache` (formerly `innovationtreehouse/cache`; clients pin the numeric repo id `1343160243`).

The repo is **public**: release downloads and attestation lookups need no token.

The cache host itself (`10.41.1.50`, apt-cacher-ng/devpi/verdaccio/Docker mirrors on ports 3141-5001) is an **external dependency**: this repo only configures clients to find it, it does not provision or run that box. See the org's infra repo for how the cache host is built and kept up.

## What gets applied

| Client | On facility | Off-site |
|---|---|---|
| apt (Ubuntu) | HTTP proxy `…:3142` via APT auto-detect | `DIRECT` |
| pip / uv | index-url `…:3141/root/pypi/+simple/` | files/env removed; public PyPI |
| npm | registry `…:4873` | default registry.npmjs.org |
| Docker Hub | `registry-mirrors` (always listed) | engine falls back to docker.io |
| GHCR | not rewritten | pull `ghcr.io/...` as usual |
| Windows Update / Store | DHCP option **235** → MCC, if you deploy one | option absent → Microsoft CDN |
| Microsoft 365 Apps / Defender updates | *partly* Delivery-Optimization-backed at best | expect some direct-to-Microsoft traffic regardless |

> Delivery Optimization only honors the DHCP option 235 cache host on Windows Pro/Enterprise/Education. **Windows Home ignores that policy entirely** and always goes straight to Microsoft's CDN — there is no workaround for that edition here.

## GitHub CLI on client machines

First install and the daily updater install `gh` if it is missing, and
upgrade it when GitHub's apt repo / winget has a newer version. On the
facility LAN the Ubuntu package is fetched through apt-cacher-ng
(`http://cache…:3142/cli.github.com/packages`) so later machines reuse the
cached `.deb`; the apt signing key is always fetched directly from
`https://cli.github.com` and checked against pinned fingerprints. Off-site,
and on Windows (winget or the GitHub Releases MSI), it is a direct GitHub
download.

`gh` is what verifies release attestations, and no `gh auth login` is
needed for it: the client fetches the Sigstore bundle from the GitHub
attestations API (with the token file's token while the repo is private)
and verifies it with `gh attestation verify --bundle`. With `gh` present, a
missing or invalid attestation means the update is refused. Only if `gh`
cannot be installed does the client install on SHA-256 alone, with a loud
warning — SHA-256 only proves the archive matches the release's own
manifest, not who built it. See `docs/SECURITY.md`.

## Shared machines: GitHub sign-in

On opted-in shared-login computers, each member signs in to GitHub as
themself with `treehouse-git signin`, so commits are attributed to them. At
desktop login a terminal window opens and offers the sign-in, and new bash /
Git Bash terminals show a one-line "signed in as …" or "not signed in" hint. The sign-in ends at logout, on `treehouse-git signout`, or
after 36 hours. Each of those deletes the token from the computer but does not
revoke it on GitHub, because revoking was seen to sign the member out of `gh`
on their other devices too. See [docs/SHARED-MACHINES.md](docs/SHARED-MACHINES.md).

## Install and enable

There are three ways to install the client:

- **Verify first** (recommended): download the bootstrap script, check its GitHub
  attestation, then run it.
- **Quick**: run the bootstrap script without checking it first.
- **From a checkout** of this repo.

All three end in the same place. The client then updates itself from GitHub
Releases (daily, as root/SYSTEM). The repo is public, so no token is needed.

> Commands marked **(v1.1.0+)** use bootstrap assets that change in v1.1.0.
> They are re-verified on the facility test machines after that release.
> `v1.0.3` and earlier were signed before the repo rename: to verify those,
> use `--repo innovationtreehouse/cache` and
> `--signer-workflow innovationtreehouse/cache/.github/workflows/release.yml`.
> The `infra.cache` names fail on them with a certificate mismatch.

### Ubuntu

Prerequisites: Ubuntu 22.04 or 24.04, an account with `sudo`, `curl`, and
`python3`. Being on the facility LAN is not required: off-site the client
stays idle and switches on when you arrive.

**Verify first (v1.1.0+).** This needs `gh` 2.49 or newer. The `gh` in
Ubuntu's own archive is too old, so get it from <https://cli.github.com>
first. The bootstrap keeps `gh` updated after that.

```bash
mkdir -p ~/fc-install && cd ~/fc-install
curl -fsSL -o install-linux.sh \
  https://github.com/innovationtreehouse/infra.cache/releases/latest/download/install-linux.sh
DIGEST="$(sha256sum install-linux.sh | cut -d' ' -f1)"
curl -fsSL -H "Accept: application/vnd.github+json" \
  "https://api.github.com/repos/innovationtreehouse/infra.cache/attestations/sha256:${DIGEST}" \
  -o attestation.json
python3 <<'PY'
import json
d = json.load(open("attestation.json", encoding="utf-8"))
with open("bundle.jsonl", "w", encoding="utf-8") as f:
    for att in d.get("attestations", []):
        bundle = att.get("bundle")
        if isinstance(bundle, dict):
            f.write(json.dumps(bundle) + "\n")
PY
gh attestation verify install-linux.sh --repo innovationtreehouse/infra.cache \
  --bundle bundle.jsonl \
  --signer-workflow innovationtreehouse/infra.cache/.github/workflows/release.yml \
  --deny-self-hosted-runners
sudo bash install-linux.sh
cd ~ && rm -rf ~/fc-install
```

The plain `gh attestation verify FILE --repo ...` form, without `--bundle`,
needs `gh auth login`. That is why the attestation is fetched first.
`gh attestation verify --bundle` reads one bundle per line, so every
attestation for the file is written out.

**Quick:**

```bash
curl -fsSL https://github.com/innovationtreehouse/infra.cache/releases/latest/download/install-linux.sh | sudo bash
```

This skips checking the bootstrap script itself: root runs whatever
github.com served, trusting only HTTPS. The script still installs `gh`
directly from GitHub, and it refuses a tarball whose SHA-256 or attestation
does not verify. If `gh` cannot be installed, it installs on SHA-256 alone
and says so.

**From a checkout:** `sudo ./linux/install.sh`. Options: `--no-docker`,
`--no-restart-docker`.

**Check that it is enabled:**

```bash
facility-cache status
```

On the facility LAN, the important lines are:

```
  ▸ network      on-site ●
  ▸ resolved     10.41.1.50 ✓
  ▸ apt          on       :3142   apt-cacher-ng · auto-detect ●
  ▸ pypi         on       :3141   devpi / pip / uv ●
  ▸ npm          on       :4873   verdaccio ●
  ▸ pip          present  /etc/pip.conf ●
```

Off-site, `network` shows `off-site · public registries` and the pip, npm
and uv files are removed. Re-checks happen every 5 minutes, on network
change, or on demand with `sudo facility-cache apply`.

**Shared machine (one login for everyone):** run
`echo SHARED_MACHINE=1 | sudo tee -a /etc/facility-cache/config && sudo facility-cache apply`,
then have the shared account log out and back in once. See
[docs/SHARED-MACHINES.md](docs/SHARED-MACHINES.md).

**Update / uninstall:**

```bash
sudo facility-cache update --check   # installed vs latest
sudo facility-cache update           # install if newer (the daily timer does this)
sudo facility-cache uninstall        # --keep-docker to leave daemon.json alone
facility-cache log                   # recent events; -f to follow, --json
```

Uninstall removes the client files, timers, drop-ins and the shared-machine
setup. It keeps `/etc/facility-cache/config` and `/var/log/facility-cache/`.
If install backed up `daemon.json`, uninstall restores that backup, and
first saves the live file as `daemon.json.facility-cache.uninstalled`.

### Windows 10/11

Prerequisites:

- Windows Pro, Enterprise or Education. Home ignores the Delivery
  Optimization policy; everything else still works.
- An **elevated** Windows PowerShell 5.1 (Run as administrator).
- `gh` 2.49 or newer for the verify-first form. The bootstrap installs `gh`
  itself if it is missing.
- Shared machines also need **Git for Windows installed machine-wide**:
  `treehouse-git` refuses to sign in without it.

**Verify first (v1.1.0+):**

```powershell
Set-ExecutionPolicy -Scope Process Bypass
New-Item -ItemType Directory -Force $env:TEMP\fc-install | Out-Null; Set-Location $env:TEMP\fc-install
Invoke-WebRequest -UseBasicParsing `
  https://github.com/innovationtreehouse/infra.cache/releases/latest/download/install-windows.ps1 `
  -OutFile install-windows.ps1
$hash = (Get-FileHash install-windows.ps1 -Algorithm SHA256).Hash.ToLowerInvariant()
$resp = Invoke-WebRequest -UseBasicParsing -Headers @{ Accept = 'application/vnd.github+json' } `
  -Uri "https://api.github.com/repos/innovationtreehouse/infra.cache/attestations/sha256:$hash"
Add-Type -AssemblyName System.Web.Extensions
$ser = New-Object System.Web.Script.Serialization.JavaScriptSerializer
$ser.MaxJsonLength = [int]::MaxValue
$atts = $ser.DeserializeObject($resp.Content)['attestations']
# Do NOT use ConvertFrom-Json/ConvertTo-Json here -- it corrupts the bundle.
$lines = $atts | ForEach-Object { $ser.Serialize($_['bundle']) }
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText("$PWD\bundle.jsonl", ($lines -join "`n"), $utf8NoBom)
gh attestation verify .\install-windows.ps1 --repo innovationtreehouse/infra.cache `
  --bundle bundle.jsonl `
  --signer-workflow innovationtreehouse/infra.cache/.github/workflows/release.yml `
  --deny-self-hosted-runners
.\install-windows.ps1
```

**Quick:** run the first three lines (download), skip the verification, and
run `.\install-windows.ps1`. The same caveat applies as on Linux: the
bootstrap script itself is unchecked. It still verifies the release zip's
SHA-256 and attestation before running anything from it. It installs `gh`
through winget, or from the Authenticode-checked GitHub MSI when winget is
not usable.

**From a checkout (or a copy of the repo):**
`.\windows\Install-FacilityCache.ps1`. Option: `-NoRestartDocker`.

**Check that it is enabled:**
`& "$env:ProgramData\FacilityCache\Status-FacilityCache.ps1"`. On the LAN it
shows the cache resolving to `10.41.1.50` and pip, npm and uv on.
Off-site they are off. Scheduled tasks, all running as SYSTEM:

- `FacilityCache-Apply`: every 5 minutes, at boot, and on network change.
- `FacilityCache-Update`: daily, and at boot.
- `FacilityCache-SessionReset`: logon, logoff and boot.

**Shared machine:** set `C:\ProgramData\FacilityCache\config.json` to
`{"SharedMachine": true}`, keeping any other keys, and run
`& "$env:ProgramData\FacilityCache\FacilityCache-Apply.ps1"`. Install Git for
Windows machine-wide first. Each account picks up the sign-in settings at its
next logon.

**Update / uninstall:**

```powershell
& "$env:ProgramData\FacilityCache\FacilityCache-Update.ps1" -Check
& "$env:ProgramData\FacilityCache\FacilityCache-Update.ps1"          # install if newer
& "$env:ProgramData\FacilityCache\Uninstall-FacilityCache.ps1"
Import-Module "$env:ProgramData\FacilityCache\FacilityCache.psm1"; Show-FacilityCacheLog
```

Uninstall removes the tasks, drop-ins, machine environment variables, the
Delivery Optimization policy and the shared-machine setup. It keeps
`config.json` and `logs\`.

### Settings that survive updates

| | Ubuntu `/etc/facility-cache/config` | Windows `C:\ProgramData\FacilityCache\config.json` |
|---|---|---|
| Turn off self-update | `AUTO_UPDATE=0` | `"AutoUpdate": false` |
| Shared machine | `SHARED_MACHINE=1` | `"SharedMachine": true` |
| Sign-in length | `GH_SESSION_HOURS=36` | `"GhSessionHours": 36` |
| Sign-in prompt at login | `SIGNIN_PROMPT_AT_LOGIN=0` turns it off | `"SignInPromptAtLogin": false` turns it off |
| LAN probe timeout | `PROBE_TIMEOUT_SEC=5` | `"ProbeTimeoutMs": 5000` |

Package defaults ship in each release: `/usr/local/lib/facility-cache/defaults`
and `C:\ProgramData\FacilityCache\defaults.json`. They are replaced on update;
don't edit them. A read token is not needed now that the repo is public. If
you ever add one, put it in `/etc/facility-cache/github-token` (mode 600) or
`C:\ProgramData\FacilityCache\github-token`, never in the config file. A
stale token breaks updates, so delete it when done.

### Troubleshooting

These problems were seen while validating on the facility machines:

- **pip/uv sometimes go direct while npm uses the cache.** The cache host was
  on Wi-Fi, with LAN round trips of 0.3 to 3 s. The TCP probe gave up after
  1 s, so pip/uv were switched off for that 5-minute cycle. The default
  timeout is now 5 s. Check the probe with `facility-cache-probe` (Linux)
  or `Test-FacilityCache -Port 3141` after importing the module (Windows).
  The real fix is a wired cache host.
- **devpi returns 404 for every package right after the cache host
  restarts.** Warm it once with
  `curl http://cache.facility.innovationtreehouse.org:3141/root/pypi/+simple/`.
- **`apt` or the installer waits on "Could not get lock
  /var/lib/dpkg/lock-frontend".** Ubuntu's own `unattended-upgrade` is
  running. After a long time off the network it can download a big backlog,
  through the cache, for half an hour or more. Let it finish; don't kill it.
- **`winget` fails over SSH or as SYSTEM** with "Failed when opening
  source(s)". winget is a per-user app. Install Git for Windows (and Python
  or Node, if needed) from the official signed installers instead:
  `Git-*-64-bit.exe /VERYSILENT /NORESTART /SP- /SUPPRESSMSGBOXES /ALLUSERS`.
  The client falls back to the signed `gh` MSI by itself.
- **Git Bash says `treehouse-git: command not found`.** That Git Bash was
  started before shared mode was on, or Git for Windows was installed after
  the client (the next 5-minute apply adds the hook). Open a new Git Bash,
  or type `treehouse-git.cmd signin`: Git Bash does not run `.cmd` files
  without the extension.
- **No sign-in hint in Windows PowerShell or cmd.** This is on purpose. A
  machine-wide PowerShell profile lives under System32 and errors under the
  default Restricted execution policy. cmd's AutoRun runs for every cmd,
  scripts included. The window at logon covers those users.
- **`git commit` says "Please tell me who you are" on a shared machine.**
  Nobody is signed in: run `treehouse-git signin`. When a GitHub credential
  is needed, git also prints `Not signed in to GitHub. Run: treehouse-git signin`.
- **The update refuses with "attestation not verified" or "repo id
  mismatch".** That is the client doing its job. Don't work around it;
  check `facility-cache log` and the release on GitHub.

## Publishing a release

The tag is the version — there is no `VERSION` file in the repo; the
release workflow derives it from the pushed tag and generates the `VERSION`
file that ships inside the archives.

1. Change `defaults.env` / `defaults.json` if host, ports, or repo should move.
2. Merge to `main`, then tag a commit **on `main`** and push the tag:

```bash
git tag v1.1.0 origin/main
git push origin v1.1.0
```

The workflow refuses a tag whose commit is not on `main`, runs lint and the
unit tests first, runs in the `release` environment (where reviewers can be
required), and never modifies an already-published release: a broken
release is fixed with a new patch version. If a run fails half-way, re-run
it (or dispatch the workflow against the tag); the leftover draft is
replaced.

GitHub Actions packs:

- `facility-cache-client-linux.tar.gz`
- `facility-cache-client-windows.zip`
- `manifest.json` (version + SHA-256)
- `SHA256SUMS`
- `install-linux.sh` / `install-windows.ps1`

Each of those files is attested (build provenance from `release.yml`) before
the Release is published; this only works while the repo is public (or on
GitHub Enterprise Cloud). The packer is reproducible: the same commit gives
byte-identical archives.
See `docs/SECURITY.md`. Clients pick a new release up on the next daily check
(or immediately with `facility-cache update`).

Pack locally without tagging: `python3 scripts/pack-release.py` — the
version comes from `git describe --tags` (e.g. `1.0.1-3-gabc1234`), or from
`FC_RELEASE_VERSION` if set; timestamps come from `SOURCE_DATE_EPOCH` or the
commit time.

## UniFi (once, on the facility DHCP)

1. Local DNS: `cache.facility.innovationtreehouse.org` → `10.41.1.50`
2. DHCP DNS = the gateway (`10.41.1.1`), not 8.8.8.8
3. Custom DHCP option **235** (text) = `cache.facility.innovationtreehouse.org`
4. Do **not** publish a public A record for that name

## Notes

- Do not set a machine-wide `http_proxy`.
- Do not put a static `Acquire::http::Proxy` in apt; auto-detect is the fallback.
- Auto-update talks to GitHub, not the facility cache, so it still works off-site.
- Auto-update does **not** restart Docker; restart it yourself if `daemon.json` changed.
- Disable auto-update: `AUTO_UPDATE=0` in `/etc/facility-cache/config`, or `"AutoUpdate": false` in the Windows `config.json`.
- Existing `/etc/pip.conf` or `/etc/npmrc` without a `facility-cache-managed` marker is left alone.
- Docker's `registry-mirrors` / `insecure-registries` are written once at install/update time and **stay in `daemon.json` off-site too** — unlike pip/npm/uv they are not toggled on network change. dockerd only reads `daemon.json` at start (or a `docker restart docker`), so gating them on the LAN probe would mean restarting the daemon every time the network changes. Entries are always exact `host:port` strings (never a bare hostname or wildcard), so this only affects pulls explicitly addressed to that host:port — accepted trade-off for the trusted-LAN model. A network that fakes the facility DNS answer re-activates them (see `docs/SECURITY.md`).
- Changing `CACHE_HOST` between releases only *adds* the new host's entries to `daemon.json` — it does not remove the old host's. Old-host entries accumulate until something explicitly restores/edits `daemon.json` (uninstall's backup-restore does this; a plain update does not).
- Trust model, integrity checks, and release-publishing controls: see [`docs/SECURITY.md`](docs/SECURITY.md).
- Planned HTTPS on the cache host (public cert, keep the `10.41.1.50` IP pin, drop `trusted-host` / `insecure-registries`): [`docs/HTTPS.md`](docs/HTTPS.md).
