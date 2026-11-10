#!/usr/bin/env sh
# setup.sh - installs everything torchat needs, checks it works, creates a launcher.
#
#   sh setup.sh            install + verify + create start.sh and torchat.conf
#   sh setup.sh --check    only verify (installs nothing)
#
# Supports: Termux (Android), Debian/Ubuntu/Mint/Kali, Fedora/RHEL, Arch/Manjaro,
#           Alpine, openSUSE, macOS (Homebrew). Anything else: see the message at the end.
# Installs only: tor, python3, the 'cryptography' library (and tkinter for the window, if available) - from your OS's own
# package manager (or pip as a fallback). Nothing is downloaded from anywhere else.

set -eu
FILES="torchat.py"
HERE=$(cd "$(dirname "$0")" && pwd)
CHECK_ONLY=0; [ "${1:-}" = "--check" ] && CHECK_ONLY=1

say()  { printf '\033[1m==> %s\033[0m\n' "$*"; }
ok()   { printf '  \033[32m[ok]\033[0m %s\n' "$*"; }
warn() { printf '  \033[33m[!]\033[0m %s\n' "$*"; }
bad()  { printf '  \033[31m[x]\033[0m %s\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

SUDO=""
if [ "$(id -u)" -ne 0 ]; then have sudo && SUDO="sudo"; fi

# ---------------------------------------------------------------- detect OS
OS="unknown"
if [ -d /data/data/com.termux ] || [ -n "${TERMUX_VERSION:-}" ]; then OS="termux"
elif [ "$(uname -s)" = "Darwin" ]; then OS="macos"
elif [ -r /etc/os-release ]; then
  . /etc/os-release
  case " ${ID:-} ${ID_LIKE:-} " in
    *" debian "*|*" ubuntu "*) OS="debian" ;;
    *" fedora "*|*" rhel "*|*" centos "*) OS="fedora" ;;
    *" arch "*) OS="arch" ;;
    *" alpine "*) OS="alpine" ;;
    *" suse "*|*" opensuse "*) OS="suse" ;;
  esac
fi
say "Detected system: $OS"

# ---------------------------------------------------------------- install
install_pkgs() {
  case "$OS" in
    termux) pkg update -y && pkg install -y python tor python-cryptography ;;
    debian) $SUDO apt-get update && DEBIAN_FRONTEND=noninteractive $SUDO apt-get install -y tor python3 python3-cryptography python3-venv ;;
    fedora) $SUDO dnf install -y tor python3 python3-cryptography ;;
    arch)   $SUDO pacman -S --needed --noconfirm tor python python-cryptography ;;
    alpine) $SUDO apk add tor python3 py3-cryptography ;;
    suse)   $SUDO zypper --non-interactive install tor python3 python3-cryptography ;;
    macos)
      have brew || { bad "Homebrew not found. Install it from https://brew.sh then re-run this script."; return 1; }
      brew install tor python ;;
    *) return 1 ;;
  esac
}

install_window_support() {          # optional: only needed for the desktop window; failure is fine
  case "$OS" in
    debian) $SUDO apt-get install -y python3-tk ;;
    fedora) $SUDO dnf install -y python3-tkinter ;;
    arch)   $SUDO pacman -S --needed --noconfirm tk ;;
    alpine) $SUDO apk add py3-tkinter ;;
    suse)   $SUDO zypper --non-interactive install python3-tk ;;
    macos)  brew install python-tk ;;
    *) return 1 ;;
  esac
}

if [ "$CHECK_ONLY" -eq 0 ]; then
  say "Installing packages (you may be asked for your password)"
  if ! install_pkgs; then
    warn "Automatic install not available for this system."
    warn "Please install manually: tor, python3 (3.8+), and the python 'cryptography' library."
  fi
  install_window_support >/dev/null 2>&1 || true
fi

# ---------------------------------------------------------------- verify
say "Checking requirements"
FAIL=0

PY=""
for c in python3 python; do if have "$c"; then PY="$c"; break; fi; done
if [ -z "$PY" ]; then bad "Python 3 not found"; FAIL=1
else
  if "$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3,8) else 1)'; then ok "Python $("$PY" -c 'import platform;print(platform.python_version())')"
  else bad "Python is too old (need 3.8+)"; FAIL=1; fi
fi

if have tor; then
  TV=$(tor --version 2>/dev/null | head -n1 | sed -n 's/.*version \([0-9][0-9.]*\).*/\1/p' | sed 's/\.$//')
  if [ -n "$TV" ] && "${PY:-python3}" -c "import sys; v=tuple(map(int,'$TV'.split('.')[:3])); sys.exit(0 if v>=(0,4,6) else 1)" 2>/dev/null; then
    ok "Tor $TV"
  else warn "Tor found (version '${TV:-unknown}') - 0.4.6 or newer is recommended"; fi
else bad "Tor not found"; FAIL=1; fi

CRYPTO_TEST='
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes
import os
a, b = X25519PrivateKey.generate(), X25519PrivateKey.generate()
assert a.exchange(b.public_key()) == b.exchange(a.public_key())
k = HKDF(hashes.SHA256(), 32, None, b"t").derive(b"x" * 32)
n = os.urandom(12); assert ChaCha20Poly1305(k).decrypt(n, ChaCha20Poly1305(k).encrypt(n, b"hi", b"a"), b"a") == b"hi"
Scrypt(salt=b"s", length=32, n=2**15, r=8, p=1).derive(b"pw")
'
VENV_PY="$HOME/.torchat-venv/bin/python"
crypto_ok() { "$1" -c "$CRYPTO_TEST" >/dev/null 2>&1; }

USE_PY="$PY"
if [ -n "$PY" ]; then
  if crypto_ok "$PY"; then ok "'cryptography' library works (X25519, ChaCha20-Poly1305, HKDF, scrypt)"
  elif [ "$CHECK_ONLY" -eq 0 ]; then
    warn "'cryptography' missing or broken - trying a private virtual environment"
    if "$PY" -m venv "$HOME/.torchat-venv" 2>/dev/null && "$VENV_PY" -m pip install --quiet --only-binary=:all: --upgrade pip cryptography 2>/dev/null && crypto_ok "$VENV_PY"; then
      ok "Installed 'cryptography' in $HOME/.torchat-venv"; USE_PY="$VENV_PY"
    else bad "Could not install 'cryptography'. Try: $PY -m pip install --user cryptography"; FAIL=1; fi
  else bad "'cryptography' library missing or broken"; FAIL=1; fi
fi
[ -x "$VENV_PY" ] && crypto_ok "$VENV_PY" && ! crypto_ok "${PY:-false}" && USE_PY="$VENV_PY"

if [ -n "$PY" ]; then
  if "$PY" -c 'import tkinter' >/dev/null 2>&1; then ok "Window support (tkinter) available"
  else warn "No window support here - the simple text screen will be used (Debian/Ubuntu: sudo apt install python3-tk)"; fi
fi
for f in $FILES; do
  if [ -f "$HERE/$f" ]; then ok "Found $f"; else bad "$f is not in $HERE - put it in the same folder as this script"; FAIL=1; fi
done

# ---------------------------------------------------------------- location + config + launcher
sum256() { if have sha256sum; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }

if [ "$FAIL" -eq 0 ] && [ "$CHECK_ONLY" -eq 0 ]; then
  DEST="$HERE"
  case "$HERE" in
    */storage/*|/sdcard/*|*/Download*|*/download*)
      DEST="$HOME/torchat"
      warn "This folder is shared storage (other apps could modify the scripts). Copying to $DEST"
      mkdir -p "$DEST" && chmod 700 "$DEST"
      for f in $FILES; do cp "$HERE/$f" "$DEST/$f"; done
      if [ -f "$HERE/torchat.conf" ] && [ ! -f "$DEST/torchat.conf" ]; then cp "$HERE/torchat.conf" "$DEST/torchat.conf"; fi ;;
  esac
  for f in $FILES; do chmod 600 "$DEST/$f" 2>/dev/null || true; done
  [ -f "$DEST/torchat.conf" ] && chmod 600 "$DEST/torchat.conf"

  # settings file (never overwritten if it already exists)
  if [ ! -f "$DEST/torchat.conf" ]; then
    cat > "$DEST/torchat.conf" <<'CONF'
# torchat settings - read by start.sh. One KEY=VALUE per line. The file is never executed;
# anything that is not exactly one of the options below is ignored.

# Which screen to use: auto (a window if your device can show one, otherwise the text screen),
# gui (force the window) or text (force the simple text screen).
INTERFACE=auto

# Keep Tor's PUBLIC network cache in ~/.cache/torchat so later starts connect faster.
# It holds no keys, codes or chats. 0 = keep nothing on disk (slower start).
TOR_CACHE=1

# 1 = for networks that only allow web traffic (ports 80 and 443), like some schools and offices.
FIREWALL_80_443=0

# For networks that block Tor: a text file with bridge lines from https://bridges.torproject.org
# (you may also need obfs4proxy or lyrebird installed - see the README).
# Remove the # at the start of the next line to use it.
# BRIDGES_FILE=~/bridges.txt
CONF
    chmod 600 "$DEST/torchat.conf"
  fi

  # launcher: reads torchat.conf safely (only the exact values 0 or 1 are accepted)
  {
    case "$USE_PY" in *\'*) bad "unsafe characters in Python path"; exit 1 ;; esac
    printf "#!/usr/bin/env sh\n# Launcher created by setup.sh\nPY='%s'\n" "$USE_PY"
    cat <<'LAUNCH'
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
LAUNCH
  } > "$DEST/start.sh"
  chmod 700 "$DEST/start.sh"

  say "All set!"
  echo "  Start the app with:   sh $DEST/start.sh"
  echo "  Settings file:        $DEST/torchat.conf"
  echo "  It opens a window (or a simple text screen on phones). No browser is used."
  echo "  File fingerprints (SHA-256, first 16 characters) - compare with the values you were given:"
  for f in $FILES; do echo "    $f  $(sum256 "$DEST/$f" | cut -c1-16)"; done
elif [ "$FAIL" -ne 0 ]; then
  say "Some requirements are missing - see the [x] lines above."
  [ "$OS" = "unknown" ] && echo "  Unsupported system: install tor + python3 (3.8+) + 'pip install cryptography', then run: sh setup.sh --check"
  exit 1
else
  say "Everything is ready."
fi
