#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
DRIVER_ROOT=$(CDPATH= cd -- "${SCRIPT_DIR}/.." && pwd)
: "${HOME:?HOME must be set}"

AGENTENV_HOME="${AGENTENV_HOME:-$HOME/.agentenv}"
DRIVERS_ROOT="${AGENTENV_HOME}/drivers"
INSTALL_ROOT="${DRIVERS_ROOT}/context-nexus"
mkdir -p "${DRIVERS_ROOT}"

release=$(mktemp -d "${DRIVERS_ROOT}/.context-nexus.XXXXXX")
tmp_link=""
backup=""
installed=0

cleanup() {
    if [ "${installed}" -ne 1 ]; then
        if [ -n "${tmp_link}" ]; then
            rm -f "${tmp_link}"
        fi
        rm -rf "${release}"
        if [ -n "${backup}" ] && [ -e "${backup}" ] \
            && [ ! -e "${INSTALL_ROOT}" ] && [ ! -L "${INSTALL_ROOT}" ]; then
            mv "${backup}" "${INSTALL_ROOT}"
        fi
    fi
}
trap cleanup EXIT INT TERM

python_bin="${PYTHON:-python3}"
replace_link() {
    "${python_bin}" - "$1" "$2" <<'PY'
import os
import sys

os.replace(sys.argv[1], sys.argv[2])
PY
}

staged="${release}"
mkdir -p "${staged}/bin" "${staged}/wheels"

"${python_bin}" -m venv "${staged}/venv"
"${staged}/venv/bin/python" -m pip install --upgrade pip >/dev/null
"${staged}/venv/bin/python" -m pip install "${DRIVER_ROOT}" >/dev/null

cat > "${staged}/bin/agentenv-driver-nexus" <<'EOF'
#!/bin/sh
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
exec "${SCRIPT_DIR}/../venv/bin/python" -m agentenv_context_nexus "$@"
EOF
chmod +x "${staged}/bin/agentenv-driver-nexus"

cp "${DRIVER_ROOT}/manifest.json.in" "${staged}/manifest.json"
tmp_link=$(mktemp "${DRIVERS_ROOT}/.context-nexus.link.XXXXXX")
rm -f "${tmp_link}"
ln -s "$(basename "${release}")" "${tmp_link}"

old_release=""
if [ -L "${INSTALL_ROOT}" ]; then
    old_target=$(readlink "${INSTALL_ROOT}")
    case "${old_target}" in
        /*) old_release="${old_target}" ;;
        *) old_release="${DRIVERS_ROOT}/${old_target}" ;;
    esac
    replace_link "${tmp_link}" "${INSTALL_ROOT}"
    tmp_link=""
    installed=1
    case "${old_release}" in
        "${DRIVERS_ROOT}/.context-nexus."*) rm -rf "${old_release}" ;;
    esac
else
    backup="${DRIVERS_ROOT}/.context-nexus.backup.$$"
    rm -rf "${backup}"
    if [ -e "${INSTALL_ROOT}" ]; then
        # Legacy installs were real directories. POSIX cannot atomically replace a
        # non-empty directory with a symlink, so keep rollback for this migration.
        mv "${INSTALL_ROOT}" "${backup}"
    fi
    if replace_link "${tmp_link}" "${INSTALL_ROOT}"; then
        tmp_link=""
        installed=1
        rm -rf "${backup}"
    else
        rm -f "${INSTALL_ROOT}"
        if [ -e "${backup}" ]; then
            mv "${backup}" "${INSTALL_ROOT}"
        fi
        exit 1
    fi
fi
printf '%s\n' "${INSTALL_ROOT}"
