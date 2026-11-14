# Trust model

## What this proxies, and what it doesn't

Every cache/mirror this client points at — apt-cacher-ng, devpi/pip, verdaccio,
the Docker Hub pull-through — serves **public package content only**: the same
bytes anyone gets from Ubuntu/PyPI/npm/Docker Hub directly. No private
package feeds, no credentials, no build artifacts flow through the facility
cache. That does not make a compromised cache harmless: it can serve
malicious packages to every tool on this list that does not verify
signatures itself (pip, npm, Docker — see below). apt is the exception.

## LAN trust, not transport security

Traffic to the cache host (`cache.facility.innovationtreehouse.org`) is plain
HTTP, on the facility LAN, by design — not HTTPS. That's a deliberate
LAN-trust boundary: the facility network is treated as trusted transport, the
same way a corporate office trusts its own switches. Do not extend reachability
to that host beyond the facility LAN (no site-to-site VPN routing, no NAT
forwarding it in) without revisiting this assumption.

**On-site detection can be spoofed.** The client decides it is on the facility
LAN when `cache.facility.innovationtreehouse.org` resolves to `EXPECTED_IP`
(`10.41.1.50`) and, for pip/npm/apt, a TCP connect to that IP's service port
succeeds (`on_facility` / `dns_matches_expected` / `port_open` in
`linux/lib/common.sh`, `Test-FacilityCache` in `windows/FacilityCache.psm1`).
That is only true of honest resolvers. On a network whose DHCP/DNS an attacker
controls (café Wi-Fi, a rogue access point) the attacker can answer that name
with `10.41.1.50` and listen on those ports. The client then treats the
network as the facility and points tools at the attacker over plain HTTP:

- pip / uv get the attacker's index **and** the `trusted-host` /
  `allow-insecure-host` bypass;
- npm gets the attacker's registry;
- Docker's `registry-mirrors` / `insecure-registries` entries are never
  removed off-site (see below), so the same DNS answer re-activates them
  without the client doing anything.

The next `pip install` / `npm install` can then run attacker code as that
user, and the next `docker pull` of a mirrored image can return an image of
the attacker's choosing. "Off-site the name does not
resolve" protects against honest networks, not hostile ones. No code in this
client mitigates this today. The remedy is the TLS plan in
[`HTTPS.md`](HTTPS.md) — a public certificate on the cache host and the HTTP
bypasses removed, so a spoofed host fails the TLS check — and it is **not
shipped**. apt is not affected in the same way (signatures, below).

## Integrity, package by package

- **apt** — `Acquire::http::Proxy-Auto-Detect` only changes *where*
  packages are fetched from; APT verifies `InRelease` against the keyring a
  source is `signed-by`, and every `.deb` against the hashes that file
  covers, whoever serves the bytes. That holds only while the keyring itself
  did not come from the party being distrusted. The Ubuntu archive keys ship
  with the OS. The GitHub CLI keyring
  (`/etc/apt/keyrings/facility-cache-githubcli.gpg`) is fetched **only** from
  `https://cli.github.com` (HTTPS, never through the cache) and installed only
  if every primary key in it matches GitHub's published fingerprints, which
  are pinned in `linux/lib/ensure_gh.sh`; a keyring that fails the pin is
  removed. With the trust anchor fetched out-of-band and pinned, the `gh`
  packages themselves may transit the cache. (Earlier releases fetched that
  keyring through the cache over HTTP, so a hostile or spoofed cache could
  have supplied its own key.)
- **pip / uv** — the `trusted-host` / `allow-insecure-host` bypass (needed
  because the cache serves plain HTTP) is written by `facility-cache-apply`
  *only* while the probe says we're on-site (DNS answers `10.41.1.50`
  **and** the pypi port answers), and removed otherwise. pip does not verify
  package signatures; only lockfile hashes (`--require-hashes`) protect a
  project against a malicious index. The probe is spoofable (above).
- **npm** — same gating and the same caveat as pip.
- **Docker** — `registry-mirrors` and `insecure-registries` in `daemon.json`
  are **not** probe-gated: they're written at install/update time and stay
  in place on every network, because toggling them would mean restarting
  dockerd on every network change. On an honest network off-site the name
  does not resolve and Docker falls back to Docker Hub. On a network that
  answers the name (spoofed, above) the mirror is used over plain HTTP.
  Pin images by digest where it matters.

## Self-update: what is verified, and in what order

Clients download releases from this repo's GitHub Releases
(`innovationtreehouse/infra.cache`, numeric id `1343160243`; formerly
`innovationtreehouse/cache`). Each client pins the numeric repo id and refuses
to update if the name now points at a different repository.

Two checks, which do different jobs:

1. **sha256 against `manifest.json`** — integrity only. It proves the archive
   is the one the *same release's* manifest names. Anyone able to publish the
   release can publish a matching manifest, so it says nothing about who
   built it.
2. **GitHub Artifact Attestation** — authenticity. It proves the bytes were
   produced by this repo's `.github/workflows/release.yml` on a GitHub-hosted
   runner, not hand-uploaded onto a Release.

Both updaters (`linux/sbin/facility-cache-update`, `windows/FacilityCache.psm1`)
and both bootstraps (`linux/bootstrap.sh`, `windows/Install-FromGitHub.ps1`)
run both checks **before anything from the download is executed or
extracted**. When `gh` is available (it is installed from GitHub directly if
missing — never from the archive under test), a missing or failing
attestation is **fatal**: nothing is installed. Only when `gh` cannot be
installed does the client fall back to sha256 alone, and it logs that loudly
as a warning on every run. A fleet machine stuck in that state is trusting
whoever can publish a release.

`release.yml` attests **every file it publishes**:

- `facility-cache-client-linux.tar.gz`
- `facility-cache-client-windows.zip`
- `manifest.json`
- `SHA256SUMS`
- `install-linux.sh`
- `install-windows.ps1`

The client verifies in two steps, so no `gh auth login` is needed:

1. Fetch every attestation for the file's SHA-256:

   ```
   GET https://api.github.com/repos/innovationtreehouse/infra.cache/attestations/sha256:<sha256 of FILE>
   ```

   Write each returned `attestations[i].bundle` as its own line of a JSON
   Lines file (`gh attestation verify --bundle` accepts one bundle per line).
   Attestations whose `repository_id` doesn't match the pinned repo id are
   dropped first.
2. Verify that bundle file locally (`gh` still fetches Sigstore's TUF root
   when its cache is cold, so this needs network, but no GitHub login):

   ```
   gh attestation verify FILE --repo innovationtreehouse/infra.cache \
     --bundle bundle.jsonl \
     --signer-workflow innovationtreehouse/infra.cache/.github/workflows/release.yml \
     --deny-self-hosted-runners
   ```

**Repo rename and manual verification.** A signing certificate records the
repository name at build time. `v1.0.3` (and earlier) was built before the
rename, so verifying it by hand needs the **old** names —
`--repo innovationtreehouse/cache` and
`--signer-workflow innovationtreehouse/cache/.github/workflows/release.yml`
(GitHub redirects API calls made under the old name). Releases built after the rename
need the new names, as shown everywhere else in these docs.

The bare `gh attestation verify FILE --repo ... --signer-workflow ...` form
(no `--bundle`) always needs an authenticated `gh`, even for a public repo.
The unattended updater is never logged in, which is why the client uses the
two-step form.

`--signer-workflow` so a different workflow in the repo with
`attestations: write` cannot satisfy the check.
`--deny-self-hosted-runners` so only GitHub-hosted runners count.

`windows/Install-FromGitHub.ps1` carries its own copy of the verifier rather
than importing it from the release zip it is verifying: sourcing the checker
from the archive under test would let a malicious release ship a check that
always passes. That duplication is intentional. `linux/bootstrap.sh` has the
check inline for the same reason.

## Public vs private repo

The repo is **private** at the time of writing; whether it goes public again
is an open decision. The client works in both states, but not the same way:

| | Public | Private |
|---|---|---|
| Release list / asset download | no credentials | read token required (404 without one) |
| Attestations API | no credentials | read token required (404 without one) |
| `release.yml` can create attestations | yes | **no** on the GitHub Team plan (needs Enterprise Cloud) — the attest step fails, so no release can be published |
| `release` environment required reviewers | available | not available on Team |

While the repo is private each client needs a token with read access to this
repo's contents and attestations (a fine-grained token: Contents read,
Attestations read). Put it only in the root-only token file:

- Linux: `/etc/facility-cache/github-token`, mode `600`, owner root
- Windows: `C:\ProgramData\FacilityCache\github-token`, with its ACL
  restricted to SYSTEM and Administrators

**Never put a token in `/etc/facility-cache/config` or Windows
`config.json`** — those are world-readable. When the repo is public no token
is needed; a token file that exists is still sent on every GitHub call, so
delete a stale one.

## GitHub CLI on client machines

Bootstrap, `install.sh`, and the daily updater **install `gh` if it is
missing** and **upgrade it** when a newer version is in GitHub's apt repo
(Ubuntu) or winget / GitHub Releases (Windows), because `gh` is what makes
attestation verification possible (and therefore mandatory).

Ubuntu uses GitHub's apt repository with the pinned keyring described under
*apt* above, not Ubuntu universe (too old for `--signer-workflow`) and not
`curl | bash`. On the facility LAN the source line is rewritten through
apt-cacher-ng:

```
http://cache.facility.innovationtreehouse.org:3142/cli.github.com/packages
```

`facility-apt-proxy` returns `DIRECT` for URLs already aimed at the cache
host so that rewrite is not double-proxied. Off-site the source is
`https://cli.github.com/packages`. Apply (every 5 minutes) only rewrites
the URL; install/update/bootstrap run `apt-get install gh`.

Windows: `winget install`/`upgrade GitHub.cli`, falling back to the
`windows_amd64.msi` from `cli/cli` releases.

Uninstall removes the apt source and keyring this client wrote; it does
not remove `gh` itself.

The recommended first install verifies `install-linux.sh` /
`install-windows.ps1` **before** executing them, which needs a `gh` already
on PATH. `curl | sudo bash` cannot do that; see `README.md`.

## Release-publishing controls

Anyone who can get a release published here gets root/SYSTEM on every client
at its next daily update. `release.yml` publishes only when all of these hold:

- the run is for a tag ref `vMAJOR.MINOR.PATCH` (a tag push, or a
  `workflow_dispatch` run against that tag to retry a failed run) — the tag is
  the version, there is no `VERSION` file in the repo;
- the tagged commit is already on `main`;
- the `lint` and `test` jobs pass on that commit;
- the job is allowed to run in the `release` environment (gates nothing until
  the environment is configured — see the checklist);
- no **published** release exists for that tag: assets are never overwritten.
  The workflow uploads to a draft, checks the draft holds exactly the attested
  files (by SHA-256), checks the tag still points at the built commit, and only
  then publishes. A leftover draft from a failed run is deleted and rebuilt;
  builds are reproducible, so a retry yields the same hashes.

Those gates control *what* gets published. *Who* can trigger them is GitHub
configuration, not files in this repo, and is the stronger control.

### Operator checklist — NOT yet applied

State observed via read-only `gh api` on 2026-11-14:

1. **Tag ruleset** — a ruleset named `v*` exists (id 21301233) with rules
   creation/update/deletion/non-fast-forward, but enforcement is **disabled**,
   its target list is **empty** (it matches no refs; the name is only a label)
   and it has no bypass actors. Set *include* to `refs/tags/v*`, add the
   release managers (a team) as bypass actors, and set enforcement to
   **active**. Until then any collaborator with write access can push a `v*`
   tag, and move or delete one.
2. **`main` protection** — required status checks `format`, `lint`, `test`
   (strict) are on, but required approving reviews is **0** and
   "include administrators" is **off**, so anyone with write (via admin) can
   land on `main` unreviewed, and the main-ancestry gate then means nothing.
   Require ≥1 approving review, dismiss stale approvals, and include admins.
3. **Org 2FA** — `two_factor_requirement_enabled` is **false** for the
   `innovationtreehouse` org. Require it.
4. **Collaborators** — five direct collaborators, all **admin**. Reduce to the
   people who need it; admins can bypass every control above.
5. **`release` environment** — does not exist yet (GitHub creates it,
   unprotected, on the first run). Create it, restrict deployment tags to
   `v*`, and add required reviewers. Required reviewers are only available to
   private repos on GitHub Enterprise; on the Team plan they work only while
   the repo is public.

## Shared machines (treehouse-git)

- The per-login GitHub token lives only in that login's session:
  `$XDG_RUNTIME_DIR/treehouse-gh` (tmpfs) on Linux, and
  `%LOCALAPPDATA%\FacilityCache\gh-session` in each account's own profile
  on Windows.
- Root/SYSTEM sweeps sessions at logout/logon and at expiry, and revokes the
  token through GitHub's credential-revocation API. They never follow a link
  a member planted inside a session.
- Git takes GitHub credentials only from that session (`shared.gitconfig`).
  The helper does not call `gh` when there is no session, because `gh` would
  fall back to a token in the OS keyring left by an earlier plain
  `gh auth login`.
- Everything that runs at a member's login is root/admin-owned and
  regenerated by apply:
  - the XDG autostart entry and the bash-completion drop-in (Linux);
  - the HKLM `Run` value and Git for Windows' `etc\profile.d` hook (Windows).
