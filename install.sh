#!/bin/bash
# Install (or update) the tattle daemon, CLI and monitor.
#
# Run from a checkout, or let the Omarchy plugin run it for you:
#   bash install.sh            # pinned release binary, else build from source
#   bash install.sh --source   # always build from source (needs cargo)
#
# The release binary is tied to this checkout: the version comes from
# Cargo.toml, and its SHA-256 must match packaging/checksums/v<version>.sha256,
# which is committed here (not fetched from the release, which is editable).
# If this checkout has no pinned hash for your architecture, it builds from
# source instead.
#
# Installs /usr/bin/tattle and tattle.service, then enables the service.

set -euo pipefail

REPO="jonaylor89/tattle"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FROM_SOURCE=0
[[ ${1:-} == "--source" ]] && FROM_SOURCE=1

say() { printf '\033[1;33m ᘛ⁐ᕐᐷ \033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m ✗ \033[0m %s\n' "$*" >&2; exit 1; }

for tool in nft curl sha256sum; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    case $tool in nft) pkg=nftables ;; sha256sum) pkg=coreutils ;; *) pkg=$tool ;; esac
    fail "$tool is required (sudo pacman -S $pkg)"
  fi
done

case "$(uname -m)" in
  x86_64) ARCH=x86_64 ;;
  aarch64 | arm64) ARCH=aarch64 ;;
  *) ARCH="" ;;
esac

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
BIN=""

if pacman -Qq tattle >/dev/null 2>&1; then
  fail "tattle is installed as a pacman package; update it with pacman (or remove it first: sudo pacman -R tattle)"
fi

VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' "$HERE/Cargo.toml" | head -n1)"
PINS="$HERE/packaging/checksums/v$VERSION.sha256"
ASSET="tattle-$ARCH-linux"
WANT=""
if [[ -n $ARCH && -f $PINS ]]; then
  WANT="$(awk -v f="$ASSET" '$2 == f { print $1 }' "$PINS")"
fi

if (( ! FROM_SOURCE )) && [[ -n $WANT ]]; then
  URL="https://github.com/$REPO/releases/download/v$VERSION/$ASSET"
  say "Fetching release v$VERSION for $ARCH…"
  if curl -fsSL --proto '=https' --max-time 120 -o "$TMP/tattle" "$URL"; then
    GOT="$(sha256sum "$TMP/tattle" | cut -d' ' -f1)"
    [[ $GOT == "$WANT" ]] \
      || fail "checksum mismatch: v$VERSION $ASSET is $GOT, this checkout pins $WANT"
    chmod +x "$TMP/tattle"
    BIN="$TMP/tattle"
  else
    say "Could not download release v$VERSION; building from source instead."
  fi
elif (( ! FROM_SOURCE )); then
  say "No pinned release binary for v$VERSION on $(uname -m); building from source."
fi

if [[ -z $BIN ]]; then
  [[ -f $HERE/Cargo.toml ]] || fail "no source checkout next to this script"
  if ! command -v cargo >/dev/null 2>&1; then
    fail "building needs Rust: sudo pacman -S rust (or rustup)"
  fi
  say "Building tattle (release)…"
  # --locked: exactly the dependency versions in Cargo.lock.
  (cd "$HERE" && cargo build --release --locked)
  BIN="$HERE/target/release/tattle"
fi

say "Installing — sudo will ask for your password."
sudo install -Dm755 "$BIN" /usr/bin/tattle
sudo install -Dm644 "$HERE/packaging/tattle.service" /usr/lib/systemd/system/tattle.service
sudo systemctl daemon-reload
if systemctl is-active --quiet tattle; then
  sudo systemctl restart tattle
else
  sudo systemctl enable --now tattle
fi

for _ in $(seq 1 20); do
  [[ -S /run/tattle/tattle.sock ]] && break
  sleep 0.25
done
[[ -S /run/tattle/tattle.sock ]] || fail "the daemon did not start: journalctl -u tattle -b"

if ! id -nG | tr ' ' '\n' | grep -qx wheel; then
  say "Note: your user is not in 'wheel', so it cannot control tattle. Fix: sudo usermod -aG wheel $USER (then log in again)"
fi

say "Tattle is watching. Open the monitor with: tattle"
