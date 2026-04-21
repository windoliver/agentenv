#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
if [ -f "${SCRIPT_DIR}/manifest.json" ] || [ -f "${SCRIPT_DIR}/pyproject.toml" ]; then
    DRIVER_ROOT=${SCRIPT_DIR}
else
    DRIVER_ROOT=$(CDPATH= cd -- "${SCRIPT_DIR}/.." && pwd)
fi
AGENTENV_HOME=${AGENTENV_HOME:-"$HOME/.agentenv"}
INSTALL_ROOT=${AGENTENV_DRIVER_INSTALL_ROOT:-"${AGENTENV_HOME}/drivers/agent-hermes"}
STAGED=${AGENTENV_DRIVER_STAGED_DIR:-}
PYTHON=${PYTHON:-python3}
TMP_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/agentenv-hermes-driver.XXXXXX")
EXTERNAL_STAGED=0

cleanup() {
    rm -rf "${TMP_ROOT}"
}

trap cleanup EXIT INT TERM

if [ -z "${STAGED}" ]; then
    STAGED="${TMP_ROOT}/agent-hermes"
    mkdir -p "${STAGED}/bin" "${STAGED}/wheels"
    "${PYTHON}" -m pip wheel --wheel-dir "${STAGED}/wheels" "${DRIVER_ROOT}" "hermes-agent[mcp]"
    cp "${DRIVER_ROOT}/manifest.json.in" "${STAGED}/manifest.json"
else
    EXTERNAL_STAGED=1
fi

"${PYTHON}" -m venv "${STAGED}/venv"
"${STAGED}/venv/bin/python" -m pip install --no-index --find-links "${STAGED}/wheels" agentenv-agent-hermes "hermes-agent[mcp]"

cat > "${STAGED}/bin/agentenv-driver-hermes" <<'LAUNCHER'
#!/bin/sh
set -eu
DIR=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
exec "$DIR/venv/bin/python" -m agentenv_agent_hermes "$@"
LAUNCHER
chmod 0755 "${STAGED}/bin/agentenv-driver-hermes"

if [ "${EXTERNAL_STAGED}" -eq 1 ]; then
    printf '%s\n' "${STAGED}"
    exit 0
fi

mkdir -p "$(dirname "${INSTALL_ROOT}")"
BACKUP="${INSTALL_ROOT}.backup.$$"
rm -rf "${BACKUP}"
if [ -e "${INSTALL_ROOT}" ]; then
    mv "${INSTALL_ROOT}" "${BACKUP}"
fi
if mv "${STAGED}" "${INSTALL_ROOT}"; then
    rm -rf "${BACKUP}"
else
    rm -rf "${INSTALL_ROOT}"
    if [ -e "${BACKUP}" ]; then
        mv "${BACKUP}" "${INSTALL_ROOT}"
    fi
    exit 1
fi

printf '%s\n' "${INSTALL_ROOT}"
