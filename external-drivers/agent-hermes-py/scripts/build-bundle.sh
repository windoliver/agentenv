#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
DRIVER_ROOT=$(CDPATH= cd -- "${SCRIPT_DIR}/.." && pwd)
PYTHON=${PYTHON:-python3}
DIST_DIR=${DIST_DIR:-"${DRIVER_ROOT}/dist"}
TMP_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/agentenv-hermes-bundle.XXXXXX")

cleanup() {
    rm -rf "${TMP_ROOT}"
}

trap cleanup EXIT INT TERM

mkdir -p "${DIST_DIR}" "${TMP_ROOT}/agent-hermes/bin" "${TMP_ROOT}/agent-hermes/wheels"
"${PYTHON}" -m pip wheel --wheel-dir "${TMP_ROOT}/agent-hermes/wheels" "${DRIVER_ROOT}"
cp "${DRIVER_ROOT}/manifest.json.in" "${TMP_ROOT}/agent-hermes/manifest.json"
cp "${DRIVER_ROOT}/scripts/install-driver.sh" "${TMP_ROOT}/agent-hermes/install-driver.sh"
chmod 0755 "${TMP_ROOT}/agent-hermes/install-driver.sh"
cat > "${TMP_ROOT}/agent-hermes/bin/agentenv-driver-hermes" <<'LAUNCHER'
#!/bin/sh
set -eu
DIR=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
exec "$DIR/venv/bin/python" -m agentenv_agent_hermes "$@"
LAUNCHER
chmod 0755 "${TMP_ROOT}/agent-hermes/bin/agentenv-driver-hermes"

tar -C "${TMP_ROOT}/agent-hermes" -czf "${DIST_DIR}/agent-hermes-py.tar.gz" .
printf '%s\n' "${DIST_DIR}/agent-hermes-py.tar.gz"
