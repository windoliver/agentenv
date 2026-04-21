#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
DRIVER_ROOT=$(CDPATH= cd -- "${SCRIPT_DIR}/.." && pwd)
: "${HOME:?HOME must be set}"

AGENTENV_HOME="${AGENTENV_HOME:-$HOME/.agentenv}"
INSTALL_ROOT="${AGENTENV_HOME}/drivers/context-nexus"
TMP_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/agentenv-context-nexus.XXXXXX")

cleanup() {
    rm -rf "${TMP_ROOT}"
}
trap cleanup EXIT INT TERM

python_bin="${PYTHON:-python3}"
staged="${TMP_ROOT}/context-nexus"
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
mkdir -p "$(dirname "${INSTALL_ROOT}")"
backup="${INSTALL_ROOT}.backup.$$"
rm -rf "${backup}"
if [ -e "${INSTALL_ROOT}" ]; then
    mv "${INSTALL_ROOT}" "${backup}"
fi
if mv "${staged}" "${INSTALL_ROOT}"; then
    rm -rf "${backup}"
else
    rm -rf "${INSTALL_ROOT}"
    if [ -e "${backup}" ]; then
        mv "${backup}" "${INSTALL_ROOT}"
    fi
    exit 1
fi
printf '%s\n' "${INSTALL_ROOT}"
