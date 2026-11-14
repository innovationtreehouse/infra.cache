#!/bin/bash
# Self-check for linux/bin/treehouse-git. No root, no network: gh and curl are
# stubs first in PATH, and the session lives under a temp XDG_RUNTIME_DIR.
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
TG="$ROOT/linux/bin/treehouse-git"

mkdir -p "$TMP/bin" "$TMP/run/1000"
cat >"$TMP/bin/gh" <<'EOF2'
#!/bin/bash
case "$1 $2" in
"auth login") mkdir -p "$GH_CONFIG_DIR" && printf 'github.com:\n  oauth_token: gho_faketoken123\n' >"$GH_CONFIG_DIR/hosts.yml" ;;
"api user") printf 'octo\t42\tOcto Cat\n' ;;
esac
EOF2
cat >"$TMP/bin/curl" <<'EOF2'
#!/bin/bash
cat >>"$CURL_LOG"
EOF2
chmod +x "$TMP/bin/gh" "$TMP/bin/curl"

export PATH="$TMP/bin:$PATH"
export FACILITY_CACHE_CONFIG="$TMP/config"
export XDG_RUNTIME_DIR="$TMP/run/1000"
export TREEHOUSE_RUN_BASE="$TMP/run"
export CURL_LOG="$TMP/curl.log"
export GIT_CONFIG_GLOBAL=/dev/null
S="$XDG_RUNTIME_DIR/treehouse-gh"

pass=0 fail=0
check() { # check <name> <expected> <actual>
  if [[ "$2" == "$3" ]]; then
    pass=$((pass + 1))
  else
    fail=$((fail + 1))
    echo "FAIL $1: expected [$2] got [$3]" >&2
  fi
}
fake_session() { # fake_session <expires-or-empty> <token-line>
  mkdir -p "$S/gh"
  [[ -n "$1" ]] && echo "$1" >"$S/expires"
  printf 'github.com:\n  %s\n' "$2" >"$S/gh/hosts.yml"
  : >"$CURL_LOG"
}

echo "SHARED_MACHINE=0" >"$TMP/config"
"$TG" signin >/dev/null 2>&1
check signin-refused-when-off 1 $?
check no-session-when-refused 0 "$([[ ! -e "$S" ]] && echo 0 || echo 1)"

echo "SHARED_MACHINE=1" >"$TMP/config"
"$TG" signin >/dev/null 2>&1
check signin 0 $?
check hosts-yml 0 "$([[ -f "$S/gh/hosts.yml" ]] && echo 0 || echo 1)"
check user.name "Octo Cat" "$(GIT_CONFIG_GLOBAL="$S/gitconfig" git config --global user.name)"
check user.email "42+octo@users.noreply.github.com" "$(GIT_CONFIG_GLOBAL="$S/gitconfig" git config --global user.email)"
check login octo "$(cat "$S/login")"
want=$(($(date +%s) + 36 * 3600))
got="$(cat "$S/expires")"
check expires-about-36h 1 "$((got > want - 60 && got < want + 5 ? 1 : 0))"
"$TG" status >/dev/null 2>&1
check status 0 $?

: >"$CURL_LOG"
"$TG" sweep
check sweep-exit 0 $?
check sweep-keeps-live-session 0 "$([[ -d "$S" ]] && echo 0 || echo 1)"

echo $(($(date +%s) - 10)) >"$S/expires"
"$TG" sweep
check sweep-removes-expired 0 "$([[ ! -e "$S" ]] && echo 0 || echo 1)"
grep -q gho_faketoken123 "$CURL_LOG"
check sweep-revokes-token 0 $?
"$TG" status >/dev/null 2>&1
check status-signed-out 1 $?

fake_session "" "oauth_token: gho_faketoken123"
"$TG" sweep
check sweep-missing-expires 0 "$([[ ! -e "$S" ]] && echo 0 || echo 1)"

fake_session "$(($(date +%s) + 3600))" "oauth_token: not-a-token"
"$TG" signout >/dev/null 2>&1
check signout-garbage 0 $?
check non-token-never-sent 0 "$([[ ! -s "$CURL_LOG" ]] && echo 0 || echo 1)"

fake_session "$(($(date +%s) + 3600))" "oauth_token: gho_faketoken123"
"$TG" signout >/dev/null 2>&1
check signout-removes 0 "$([[ ! -e "$S" ]] && echo 0 || echo 1)"
grep -q gho_faketoken123 "$CURL_LOG"
check signout-revokes 0 $?

echo "treehouse-git: $pass passed, $fail failed"
[[ "$fail" -eq 0 ]]
