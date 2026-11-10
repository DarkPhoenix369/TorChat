#!/usr/bin/env sh
# Launcher created by setup.sh
PY='/root/.torchat-venv/bin/python'
cd "$(dirname "$0")" || exit 1
CONF="torchat.conf"
opt() { [ -f "$CONF" ] && grep -E "^$1=" "$CONF" | tail -n 1 | cut -d= -f2- | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'; }
[ "$(opt TOR_CACHE)" = 0 ] && set -- "$@" --no-cache
[ "$(opt FIREWALL_80_443)" = 1 ] && set -- "$@" --firewall
case "$(opt INTERFACE)" in gui) set -- "$@" --gui ;; text) set -- "$@" --tui ;; esac
b="$(opt BRIDGES_FILE)"
if [ -n "$b" ]; then
  if printf '%s' "$b" | grep -Eq '^[A-Za-z0-9_./~ -]+$'; then
    case "$b" in "~/"*) b="$HOME/${b#\~/}" ;; esac
    set -- "$@" --bridges "$b"
  else echo "BRIDGES_FILE has unsupported characters - ignored" >&2; fi
fi
exec "$PY" torchat.py "$@"
