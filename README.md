# Facility cache client

Points Ubuntu and Windows machines at `cache.facility.innovationtreehouse.org` **only while they are on the facility LAN**. Off-site, the hostname does not resolve in public DNS, so clients go direct to Ubuntu/PyPI/npm/Docker Hub/Microsoft. That detection trusts the local resolver: a hostile network (rogue DHCP/DNS) can fake being the facility and receive pip/npm/Docker traffic over plain HTTP — see [`docs/SECURITY.md`](docs/SECURITY.md#lan-trust-not-transport-security).

Never uses `10.41.1.50` or the short name `cache` in client config (those collide on other networks). The probe requires the FQDN to resolve to **exactly** `10.41.1.50`.

Installed clients **update themselves from GitHub Releases**, as root/SYSTEM. A new tag publishes new scripts *and* new package defaults (host, ports, repo). Local override files are not overwritten.

Default repo: `innovationtreehouse/infra.cache` (formerly `innovationtreehouse/cache`; clients pin the numeric repo id `1343160243`).

The repo is currently **private**: while it is, release downloads and attestation lookups return 404 without a token, so every client needs a read token in its token file (see below). If it is public, no token is needed.

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
themself with `treehouse-git signin`, so commits are attributed to them.
The sign-in ends at logout, on `treehouse-git signout`, or after 36 hours.
See [docs/SHARED-MACHINES.md](docs/SHARED-MACHINES.md).

## Ubuntu — first install from a Release

Download, verify the bootstrap script, then run it. These commands need
`gh` on PATH and work without a token **while the repo is public**. The
**two-step** form is used because the plain `gh attestation verify FILE
--repo ... --signer-workflow ...` command (no `--bundle`) requires `gh auth
login`/`GH_TOKEN` even against a public repo:

```bash
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
facility-cache status
facility-cache version
```

(`gh attestation verify --bundle` accepts one bundle object per line — JSON
Lines — which is why every attestation for this file's SHA-256 is written
out, not just the first.)

These use the post-rename names. `v1.0.3` and earlier were signed before the
rename: verify those with `--repo innovationtreehouse/cache` and
`--signer-workflow innovationtreehouse/cache/.github/workflows/release.yml`.

**While the repo is private**, with a read token (fine-grained: Contents
read, Attestations read) in `GH_TOKEN`:

```bash
gh release download --repo innovationtreehouse/infra.cache --pattern install-linux.sh
gh attestation verify install-linux.sh --repo innovationtreehouse/infra.cache \
  --signer-workflow innovationtreehouse/infra.cache/.github/workflows/release.yml \
  --deny-self-hosted-runners
sudo install -d -m 755 /etc/facility-cache
sudo install -m 600 /dev/stdin /etc/facility-cache/github-token <<<"$GH_TOKEN"
sudo bash install-linux.sh
```

`curl -fsSL …/install-linux.sh | sudo bash` works only while the repo is
public. It skips verifying the bootstrap script itself: you run, as root,
whatever `github.com` served, trusting only HTTPS. The script then installs
`gh` (directly from GitHub, not from the download) and refuses to install a
tarball whose SHA-256 or attestation does not verify; if `gh` cannot be
installed it proceeds on SHA-256 alone and says so.

From a git checkout instead:

```bash
sudo ./linux/install.sh
```

Options: `--no-docker`, `--no-restart-docker`.

Uninstall (installed clients don't need the checkout — `uninstall.sh` ships to `/usr/local/sbin/facility-cache-uninstall`):

```bash
sudo facility-cache uninstall
sudo facility-cache uninstall --keep-docker
```

Client files, timers, and drop-ins are removed. `/etc/facility-cache/config` and the event log under `/var/log/facility-cache/` are left in place.

If install found a `daemon.json.facility-cache.bak`, uninstall restores it exactly — whatever was live in `daemon.json` right before that restore (our entries, plus any manual edits made since install) is saved first to `daemon.json.facility-cache.uninstalled`, so nothing is silently lost.

Local overrides (kept across updates): `/etc/facility-cache/config`

`/etc/facility-cache/github-token` (mode 600, root) holds the read token, which is **required while the repo is private**. If the file exists its contents are sent as a bearer token on every GitHub API call, so delete it if it's stale; a bad token breaks updates even on a public repo. Never put the token in `/etc/facility-cache/config` — that file is world-readable.

A 5-minute timer re-applies LAN detection. A **daily** timer (with jitter) checks GitHub for a newer release, verifies it (SHA-256 against `manifest.json`, then the GitHub Artifact Attestation — refused if that fails while `gh` is available) before running anything from it, and re-runs `install.sh` without restarting Docker. See `docs/SECURITY.md` for the self-update integrity/authenticity model in full.

Commands draw a live terminal dashboard (steps, bars, on/off glyphs). The same events are appended as JSON lines you can fetch later:

```bash
sudo facility-cache update          # install if newer
sudo facility-cache update --check  # print versions only
sudo facility-cache update --force  # reinstall current latest
facility-cache log                  # last 40 events, pretty
facility-cache log -n 100 -f        # follow
facility-cache log --json           # machine-readable
facility-cache log --path           # where the file lives
```

## Windows — first install from a Release

Elevated PowerShell, `gh` on PATH. As on Linux, these commands work without
a token only **while the repo is public**; verify the bootstrap script
before executing it. The **two-step** form is used because `gh attestation
verify FILE --repo ... --signer-workflow ...` with no `--bundle` requires
`gh auth login`/`GH_TOKEN` even against a public repo (for `v1.0.3` and
earlier, use the pre-rename `innovationtreehouse/cache` names — see the
Linux section):

```powershell
Set-ExecutionPolicy -Scope Process Bypass
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
# gh attestation verify --bundle accepts one bundle object per line (JSON
# Lines), which is why every attestation is written out, not just the first.
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText("$PWD\bundle.jsonl", ($lines -join "`n"), $utf8NoBom)
gh attestation verify .\install-windows.ps1 --repo innovationtreehouse/infra.cache `
  --bundle bundle.jsonl `
  --signer-workflow innovationtreehouse/infra.cache/.github/workflows/release.yml `
  --deny-self-hosted-runners
.\install-windows.ps1
```

While the repo is private: with `$env:GH_TOKEN` set to a read token, use
`gh release download --repo innovationtreehouse/infra.cache --pattern install-windows.ps1`
and the plain `gh attestation verify` form (as in the Linux section), write
the token to `C:\ProgramData\FacilityCache\github-token`, then run
`.\install-windows.ps1 -GitHubToken $env:GH_TOKEN`.

From a checkout:

```powershell
.\windows\Install-FacilityCache.ps1
.\windows\Status-FacilityCache.ps1
```

Uninstall:

```powershell
.\windows\Uninstall-FacilityCache.ps1
```

Scheduled tasks and drop-ins are removed; `config.json` and the event log under `logs\` are preserved.

Local overrides: `C:\ProgramData\FacilityCache\config.json` (start from `{}`).
Package defaults: `C:\ProgramData\FacilityCache\defaults.json` (replaced on each release).
`C:\ProgramData\FacilityCache\github-token` holds the read token, **required while the repo is private**; restrict its ACL to SYSTEM and Administrators. If it exists it is sent as a bearer token on every call, so delete it if it's stale; a bad token breaks updates even on a public repo. Never put the token in `config.json` (`GitHubToken`) — that file is readable by every user.

Scheduled tasks: `FacilityCache-Apply` (LAN, every 5 minutes) and `FacilityCache-Update` (GitHub, daily + at boot).

```powershell
& "$env:ProgramData\FacilityCache\FacilityCache-Update.ps1" -Check
& "$env:ProgramData\FacilityCache\FacilityCache-Update.ps1" -Force
Import-Module "$env:ProgramData\FacilityCache\FacilityCache.psm1"
Show-FacilityCacheDashboard
Show-FacilityCacheLog
Show-FacilityCacheLog -PathOnly
```

## Publishing a release

The tag is the version — there is no `VERSION` file in the repo; the
release workflow derives it from the pushed tag and generates the `VERSION`
file that ships inside the archives.

1. Change `defaults.env` / `defaults.json` if host, ports, or repo should move.
2. Merge to `main`, then tag a commit **on `main`** and push the tag:

```bash
git tag v1.0.1 origin/main
git push origin v1.0.1
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
