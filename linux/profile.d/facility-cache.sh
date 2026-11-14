# shellcheck shell=sh
# Sourced by login shells. Vars are written by facility-cache-apply when on-site.
# shellcheck disable=SC1091
if [ -r /run/facility-cache/env ]; then
  . /run/facility-cache/env
fi

# Shared machine: GitHub identity lives in the login session's tmpfs, so
# logout/reboot forgets it. Credentials saved elsewhere are dropped.
if [ "${TREEHOUSE_SHARED_MACHINE:-}" = 1 ] && [ "$(id -u)" -ne 0 ]; then
  _th_s="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/treehouse-gh"
  export GH_CONFIG_DIR="$_th_s/gh"
  export GIT_CONFIG_GLOBAL="$_th_s/gitconfig"
  rm -f "$HOME/.git-credentials" "$HOME/.config/gh/hosts.yml"
  unset _th_s
fi
unset TREEHOUSE_SHARED_MACHINE
