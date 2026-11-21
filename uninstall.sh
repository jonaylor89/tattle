#!/bin/bash
# Remove the tattle daemon. Your rules stay in /var/lib/tattle unless you
# pass --purge.
set -euo pipefail

sudo systemctl disable --now tattle 2>/dev/null || true
if pacman -Qq tattle >/dev/null 2>&1; then
  # Installed from packaging/arch: let pacman remove its own files and record.
  sudo pacman -R --noconfirm tattle
else
  # Installed by install.sh: these are not owned by any package.
  for f in /usr/bin/tattle /usr/lib/systemd/system/tattle.service; do
    if owner="$(pacman -Qqo "$f" 2>/dev/null)"; then
      echo "Leaving $f: it belongs to the '$owner' package." >&2
    else
      sudo rm -f "$f"
    fi
  done
fi
sudo systemctl daemon-reload
# The daemon removes its table on shutdown; make sure even after a crash.
sudo nft delete table inet tattle 2>/dev/null || true

if [[ ${1:-} == "--purge" ]]; then
  sudo rm -rf /var/lib/tattle
  echo "Removed tattle and its rules."
else
  echo "Removed tattle. Rules kept in /var/lib/tattle (use --purge to delete them)."
fi
echo "Remove the shell plugin with: omarchy plugin remove jonaylor89.tattle"
