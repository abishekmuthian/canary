#!/usr/bin/env bash
set -euo pipefail

# Install canary as a systemd service (Linux, NFS mode).

UNIT_NAME=canary.service
UNIT_DEST=/etc/systemd/system/${UNIT_NAME}
LOG_DEFAULT=/var/log/canary.log
NO_START=0

usage() {
	cat <<EOF
Usage: sudo ./install.sh [options]

Options:
  --mount-point PATH   Absolute path to plant canary files
                       (default: <invoking-user-home>/.secrets.d)
  --log PATH           Log file path (default: ${LOG_DEFAULT})
  --no-start           Install and enable but do not start the service
  -h, --help           Show this help

The default mount point is the home directory of the user who ran sudo,
not /root, because that is where credential-scanning attackers look.
EOF
}

MOUNT=""
LOG="${LOG_DEFAULT}"
while [[ $# -gt 0 ]]; do
	case "$1" in
		--mount-point) MOUNT="${2:-}"; shift 2 ;;
		--log)         LOG="${2:-}"; shift 2 ;;
		--no-start)    NO_START=1; shift ;;
		-h|--help)     usage; exit 0 ;;
		*)             echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
	esac
done

if [[ ${EUID} -ne 0 ]]; then
	echo "install.sh must run as root; re-run with sudo" >&2
	exit 1
fi

# Resolve default mount point from the invoking user's home.
if [[ -z "${MOUNT}" ]]; then
	if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
		USER_HOME="$(getent passwd "${SUDO_USER}" | cut -d: -f6)"
		if [[ -z "${USER_HOME}" ]]; then
			echo "could not resolve home directory for SUDO_USER=${SUDO_USER}" >&2
			exit 1
		fi
		MOUNT="${USER_HOME}/.secrets.d"
	else
		MOUNT="${HOME}/.secrets.d"
	fi
fi

if [[ "${MOUNT}" != /* ]]; then
	echo "--mount-point must be an absolute path (got: ${MOUNT})" >&2
	echo "systemd does not expand ~; pass the full path." >&2
	exit 1
fi
if [[ "${LOG}" != /* ]]; then
	echo "--log must be an absolute path (got: ${LOG})" >&2
	exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

if [[ ! -f "${UNIT_NAME}" ]]; then
	echo "${UNIT_NAME} not found in ${SCRIPT_DIR}" >&2
	exit 1
fi

# Build if Go is available; otherwise require a prebuilt binary.
if command -v go >/dev/null 2>&1 && [[ -f main.go ]]; then
	echo "building canary..."
	make
elif [[ ! -x ./canary ]]; then
	echo "no Go toolchain and no prebuilt ./canary binary; install Go or place a binary next to this script" >&2
	exit 1
fi

echo "installing binary to /usr/local/bin/canary..."
make install

# Runtime dependency checks (warn-only).
if ! command -v mount.nfs >/dev/null 2>&1; then
	echo "warning: mount.nfs not found — install nfs-common (Debian/Ubuntu) or nfs-utils (Fedora/RHEL)" >&2
fi
if ! command -v notify-send >/dev/null 2>&1; then
	echo "warning: notify-send not found — desktop notifications will be skipped (install libnotify-bin / libnotify to enable)" >&2
fi

echo "rendering ${UNIT_DEST} (mount=${MOUNT}, log=${LOG})..."
sed -e "s|@MOUNT_POINT@|${MOUNT}|g" \
    -e "s|@LOG_PATH@|${LOG}|g" \
    "${UNIT_NAME}" > "${UNIT_DEST}"
chmod 644 "${UNIT_DEST}"

mkdir -p "${MOUNT}"
chmod 0755 "${MOUNT}"
mkdir -p "$(dirname "${LOG}")"

systemctl daemon-reload
systemctl enable "${UNIT_NAME}"

if [[ ${NO_START} -eq 0 ]]; then
	systemctl restart "${UNIT_NAME}"
	systemctl --no-pager status "${UNIT_NAME}" || true
	echo
	echo "canary is running. Test it:"
	echo "  cat ${MOUNT}/.env"
	echo "  journalctl -u canary -f"
else
	echo "service installed and enabled (not started). Start with: systemctl start ${UNIT_NAME}"
fi
