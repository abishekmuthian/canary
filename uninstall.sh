#!/usr/bin/env bash
set -euo pipefail

# Remove the canary systemd service and binary installed by install.sh.

UNIT_NAME=canary.service
UNIT_DEST=/etc/systemd/system/${UNIT_NAME}

if [[ ${EUID} -ne 0 ]]; then
	echo "uninstall.sh must run as root; re-run with sudo" >&2
	exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

systemctl stop "${UNIT_NAME}" 2>/dev/null || true
systemctl disable "${UNIT_NAME}" 2>/dev/null || true

rm -f "${UNIT_DEST}"
systemctl daemon-reload

if [[ -f Makefile ]]; then
	make uninstall
else
	rm -f /usr/local/bin/canary
fi

echo "canary service and binary removed."
echo "Note: /var/log/canary.log and any mount-point directory are left in place."
echo "Remove them manually if you no longer need them."
