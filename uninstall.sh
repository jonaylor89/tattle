#!/bin/bash
# Remove the tattle daemon. Your rules stay in /var/lib/tattle unless you
# pass --purge.
set -euo pipefail

sudo systemctl disable --now tattle 2>/dev/null || true
sudo rm -f /usr/lib/systemd/system/tattle.service /usr/bin/tattle
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
