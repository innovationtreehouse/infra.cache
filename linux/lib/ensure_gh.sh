# shellcheck shell=bash
# GitHub CLI (gh) via GitHub's apt repo. Sourced, not executed.
# On the facility LAN the source URL is rewritten through apt-cacher-ng
# (http://CACHE_HOST:APT_PORT/cli.github.com/packages) so the .deb
# is cached; off-site it is vanilla HTTPS. That is safe only because the
# signed-by keyring below is fetched directly over HTTPS and fingerprint-pinned:
# apt then verifies InRelease against that keyring alone, and the .deb against
# the hashes InRelease covers, whoever serves the bytes.

GH_CLI_KEYRING="${GH_CLI_KEYRING:-/etc/apt/keyrings/facility-cache-githubcli.gpg}"
GH_CLI_LIST="${GH_CLI_LIST:-/etc/apt/sources.list.d/facility-cache-github-cli.list}"
GH_CLI_UPSTREAM="${GH_CLI_UPSTREAM:-https://cli.github.com/packages}"
# The keyring is the trust anchor for every gh .deb, so it never comes through
# the cache (plain HTTP, and anyone controlling DNS can pose as it): HTTPS to
# cli.github.com only, and installed only if every primary key in it is one of
# GitHub's published fingerprints (docs/install_linux.md in cli/cli). Not
# overridable from the environment. A GitHub key rotation needs a release here.
GH_CLI_KEY_URL="https://cli.github.com/packages/githubcli-archive-keyring.gpg"
GH_CLI_KEY_FPRS="2C6106201985B60E6C7AC87323F3D4EA75716059 7F38BBB59D064DBCB3D84D725612B36462313325"

github_cli_rewrite() {
  # $1 = https://host/path → http://CACHE_HOST:APT_PORT/host/path
  # apt-cacher-ng maps the path to an implicit backend; a literal https://
  # in the path returns 406, so strip the scheme.
  printf 'http://%s:%s/%s' "$CACHE_HOST" "$APT_PORT" "${1#*://}"
}

github_cli_packages_url() {
  if [[ "${GH_CLI_FORCE_UPSTREAM:-}" == 1 ]]; then
    printf '%s' "$GH_CLI_UPSTREAM"
    return
  fi
  if on_facility "$APT_PORT"; then
    github_cli_rewrite "$GH_CLI_UPSTREAM"
  else
    printf '%s' "$GH_CLI_UPSTREAM"
  fi
}

github_cli_https_get() {
  # github_cli_https_get <url> <dest> — HTTPS only, redirects included.
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --proto '=https' --proto-redir '=https' --max-time 30 "$1" -o "$2"
  elif command -v wget >/dev/null 2>&1; then
    wget -q --https-only -T 30 -O "$2" "$1"
  else
    return 1
  fi
}

github_cli_keyring_ok() {
  # github_cli_keyring_ok <file> — 0 if it is a binary OpenPGP keyring whose
  # primary keys are all pinned (signed-by trusts every key in the file, so a
  # single extra key is a fail). Parsed in python3 (needed by the updater
  # anyway): gpg is not on minimal installs, and gpgv/sqv cannot list keys.
  command -v python3 >/dev/null 2>&1 || return 1
  python3 -I - "$1" "$GH_CLI_KEY_FPRS" <<'PY'
import hashlib, sys
data = open(sys.argv[1], "rb").read()
pinned = set(sys.argv[2].upper().split())
i, prim = 0, []
while i < len(data):
    b = data[i]
    if not b & 0x80:
        sys.exit(1)  # not a packet (e.g. ASCII armor)
    if b & 0x40:  # new-format header
        tag, o = b & 0x3F, data[i + 1]
        if o < 192:
            n, i = o, i + 2
        elif o < 224:
            n, i = ((o - 192) << 8) + data[i + 2] + 192, i + 3
        elif o == 255:
            n, i = int.from_bytes(data[i + 2 : i + 6], "big"), i + 6
        else:
            sys.exit(1)  # partial lengths never appear in a keyring
    else:  # old-format header
        tag, lt = (b >> 2) & 0xF, b & 3
        if lt == 3:
            sys.exit(1)
        w = 1 << lt
        n, i = int.from_bytes(data[i + 1 : i + 1 + w], "big"), i + 1 + w
    body = data[i : i + n]
    if len(body) != n or tag in (5, 7):  # truncated, or secret key material
        sys.exit(1)
    if tag == 6:  # primary public key: v4 fingerprint = SHA-1(0x99 len body)
        if body[:1] != b"\x04":
            sys.exit(1)
        prim.append(hashlib.sha1(b"\x99" + n.to_bytes(2, "big") + body).hexdigest().upper())
    i += n
sys.exit(0 if prim and set(prim) <= pinned else 1)
PY
}

github_cli_install_keyring() {
  # Keep a keyring that passes the pin; anything else (possibly planted by a
  # hostile cache before this check existed) is removed, then re-fetched.
  local tmp
  if [[ -s "$GH_CLI_KEYRING" ]] && github_cli_keyring_ok "$GH_CLI_KEYRING"; then
    return 0
  fi
  if [[ -e "$GH_CLI_KEYRING" ]]; then
    echo "facility-cache: $GH_CLI_KEYRING does not match the pinned GitHub CLI key fingerprints — removing it" >&2
    rm -f "$GH_CLI_KEYRING"
  fi
  tmp="$(mktemp)"
  if ! github_cli_https_get "$GH_CLI_KEY_URL" "$tmp"; then
    echo "facility-cache: could not fetch $GH_CLI_KEY_URL — gh not installed/upgraded" >&2
  elif ! github_cli_keyring_ok "$tmp"; then
    echo "facility-cache: REFUSING GitHub CLI keyring from $GH_CLI_KEY_URL: its keys do not match the pinned fingerprints ($GH_CLI_KEY_FPRS) — GitHub may have rotated its key (needs a facility-cache-client release) or the download was tampered with; python3 is required for this check" >&2
  else
    install -d -m 0755 "$(dirname "$GH_CLI_KEYRING")"
    install -m 0644 "$tmp" "$GH_CLI_KEYRING"
    rm -f "$tmp"
    return 0
  fi
  rm -f "$tmp"
  return 1
}

github_cli_write_source() {
  local arch url
  if ! github_cli_install_keyring; then
    # No trusted keyring: drop the source so apt-get update does not fail on it.
    remove_managed "$GH_CLI_LIST"
    return 1
  fi
  arch="$(dpkg --print-architecture 2>/dev/null || echo amd64)"
  url="$(github_cli_packages_url)"
  write_managed "$GH_CLI_LIST" <<EOF
# ${MANAGED_MARKER} — do not edit; facility-cache-apply rewrites the URL.
deb [arch=${arch} signed-by=${GH_CLI_KEYRING}] ${url} stable main
EOF
}

github_cli_apt_install_pkg() {
  apt-get install -y \
    -o Dpkg::Options::=--force-confdef \
    -o Dpkg::Options::=--force-confold \
    gh >/dev/null 2>&1 || return 1
  hash -r 2>/dev/null || true
  command -v gh >/dev/null 2>&1
}

github_cli_apt_install() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update \
    -o Dir::Etc::sourcelist="$GH_CLI_LIST" \
    -o Dir::Etc::sourceparts=- \
    -o APT::Get::List-Cleanup=0 >/dev/null 2>&1 || return 1
  if github_cli_apt_install_pkg; then
    return 0
  fi
  # gh Depends: git. The restricted update above only refreshes the gh source
  # list, so on a machine whose Ubuntu package lists are missing or stale (a
  # fresh minimal install, a cleaned image) git is unresolvable and the
  # install fails with unmet dependencies. Refresh everything once, retry.
  apt-get update >/dev/null 2>&1 || true
  github_cli_apt_install_pkg
}

github_cli_ensure() {
  # Install gh if missing; upgrade if GitHub's apt repo has a newer version.
  # Never throws the caller off a cliff: return 1 on failure, 0 if gh is on PATH.
  if ! command -v apt-get >/dev/null 2>&1; then
    return 1
  fi
  if [[ "$(id -u)" -ne 0 ]]; then
    return 1
  fi
  github_cli_write_source || return 1
  if github_cli_apt_install; then
    return 0
  fi
  # apt-cacher-ng may not map /https://… — fall back to vanilla GitHub HTTPS.
  if on_facility "$APT_PORT"; then
    GH_CLI_FORCE_UPSTREAM=1 github_cli_write_source || true
    github_cli_apt_install && return 0
    github_cli_write_source || true
  fi
  return 1
}
