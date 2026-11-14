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
check sweep-never-revokes 0 "$([[ ! -s "$CURL_LOG" ]] && echo 0 || echo 1)"
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
check signout-never-revokes 0 "$([[ ! -s "$CURL_LOG" ]] && echo 0 || echo 1)"

# Links inside the session are user-controlled: never followed, session still wiped.
printf 'github.com:\n  oauth_token: gho_elsewhere456\n' >"$TMP/elsewhere.yml"
fake_session "" "x"
ln -sf "$TMP/elsewhere.yml" "$S/gh/hosts.yml"
"$TG" sweep
check symlinked-hosts-not-sent 0 "$([[ ! -s "$CURL_LOG" ]] && echo 0 || echo 1)"
check symlinked-hosts-session-removed 0 "$([[ ! -e "$S" ]] && echo 0 || echo 1)"
check symlink-target-untouched 0 "$([[ -f "$TMP/elsewhere.yml" ]] && echo 0 || echo 1)"
mkdir -p "$TMP/elsedir" "$S" && cp "$TMP/elsewhere.yml" "$TMP/elsedir/hosts.yml" && : >"$CURL_LOG"
ln -s "$TMP/elsedir" "$S/gh"
"$TG" sweep
check symlinked-gh-dir-not-sent 0 "$([[ ! -s "$CURL_LOG" ]] && echo 0 || echo 1)"
check symlinked-gh-dir-session-removed 0 "$([[ ! -e "$S" ]] && echo 0 || echo 1)"

# Login prompt and shell hint: quiet unless shared, never run gh (stub logs calls).
cat >"$TMP/bin/gh" <<'EOF2'
#!/bin/bash
echo "gh $*" >>"$GH_LOG"
EOF2
export GH_LOG="$TMP/gh.log"
: >"$GH_LOG"
rm -rf "$S"
echo "SHARED_MACHINE=0" >"$TMP/config"
check hint-silent-when-not-shared "" "$("$TG" hint)"
check welcome-silent-when-not-shared "" "$("$TG" welcome </dev/null)"
echo "SHARED_MACHINE=1" >"$TMP/config"
check hint-no-session "Not signed in to GitHub. Run: treehouse-git signin" "$("$TG" hint)"
fake_session "$(($(date +%s) + 2 * 3600 + 5 * 60 + 30))" "oauth_token: gho_faketoken123"
echo octo >"$S/login"
check hint-signed-in "Signed in to GitHub as octo (2h 5m left)" "$("$TG" hint)"
check welcome-quiet-when-signed-in "" "$("$TG" welcome </dev/null)"
check welcome-launch-quiet-when-signed-in "" "$(PATH="$TMP/bin:/usr/bin:/bin" "$TG" welcome --launch)"
echo $(($(date +%s) - 10)) >"$S/expires"
check hint-expired "Not signed in to GitHub. Run: treehouse-git signin" "$("$TG" hint)"
out="$("$TG" welcome </dev/null)"
check welcome-offers-signin 1 "$([[ "$out" == *"not signed in to GitHub"* ]] && echo 1 || echo 0)"
check welcome-skip-on-eof-no-gh "" "$(cat "$GH_LOG")"

echo "treehouse-git: $pass passed, $fail failed"
[[ "$fail" -eq 0 ]]
