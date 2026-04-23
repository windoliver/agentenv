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
HERMES_AGENT_PACKAGE=${HERMES_AGENT_PACKAGE:-"hermes-agent[mcp] @ git+https://github.com/NousResearch/hermes-agent.git"}
HERMES_AGENT_INSTALL_REQUIREMENT=${HERMES_AGENT_INSTALL_REQUIREMENT:-"hermes-agent[mcp]"}
TMP_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/agentenv-hermes-driver.XXXXXX")
EXTERNAL_STAGED=0

cleanup() {
    rm -rf "${TMP_ROOT}"
}

trap cleanup EXIT INT TERM

rewrite_venv_shebangs() {
    old_python=$1
    new_python=$2
    "${PYTHON}" - "${old_python}" "${new_python}" <<'PY'
from pathlib import Path
import sys

old_bin = Path(sys.argv[1]).parent
new_bin = Path(sys.argv[2]).parent
old_bins = {str(old_bin), str(old_bin.resolve(strict=False))}

for path in new_bin.iterdir():
    if not path.is_file():
        continue
    try:
        data = path.read_bytes()
    except OSError:
        continue
    first_line_end = data.find(b"\n")
    if first_line_end == -1:
        first_line_end = len(data)
    first_line = data[:first_line_end]
    if not first_line.startswith(b"#!"):
        continue
    interpreter = Path(first_line[2:].decode())
    interpreter_bins = {
        str(interpreter.parent),
        str(interpreter.parent.resolve(strict=False)),
    }
    if old_bins.isdisjoint(interpreter_bins):
        continue
    replacement = b"#!" + str(new_bin / interpreter.name).encode()
    path.write_bytes(replacement + data[first_line_end:])
PY
}

if [ -z "${STAGED}" ]; then
    STAGED="${TMP_ROOT}/agent-hermes"
    mkdir -p "${STAGED}/bin" "${STAGED}/wheels"
    "${PYTHON}" -m pip wheel --wheel-dir "${STAGED}/wheels" "${DRIVER_ROOT}" "${HERMES_AGENT_PACKAGE}"
    cp "${DRIVER_ROOT}/manifest.json.in" "${STAGED}/manifest.json"
else
    EXTERNAL_STAGED=1
fi

"${PYTHON}" -m venv "${STAGED}/venv"
"${STAGED}/venv/bin/python" -m pip install --no-index --find-links "${STAGED}/wheels" agentenv-agent-hermes "${HERMES_AGENT_INSTALL_REQUIREMENT}"

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

OLD_VENV_PYTHON="${STAGED}/venv/bin/python"
mkdir -p "$(dirname "${INSTALL_ROOT}")"
BACKUP="${INSTALL_ROOT}.backup.$$"
rm -rf "${BACKUP}"
if [ -e "${INSTALL_ROOT}" ]; then
    mv "${INSTALL_ROOT}" "${BACKUP}"
fi
if mv "${STAGED}" "${INSTALL_ROOT}"; then
    rewrite_venv_shebangs "${OLD_VENV_PYTHON}" "${INSTALL_ROOT}/venv/bin/python"
    rm -rf "${BACKUP}"
else
    rm -rf "${INSTALL_ROOT}"
    if [ -e "${BACKUP}" ]; then
        mv "${BACKUP}" "${INSTALL_ROOT}"
    fi
    exit 1
fi

printf '%s\n' "${INSTALL_ROOT}"
