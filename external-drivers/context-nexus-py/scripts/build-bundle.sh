#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
DRIVER_ROOT=$(CDPATH= cd -- "${SCRIPT_DIR}/.." && pwd)
OUT_DIR="${1:-${DRIVER_ROOT}/dist}"
TMP_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/agentenv-context-nexus-bundle.XXXXXX")

cleanup() {
    rm -rf "${TMP_ROOT}"
}
trap cleanup EXIT INT TERM

mkdir -p "${OUT_DIR}" "${TMP_ROOT}/context-nexus"
cp -R "${DRIVER_ROOT}/pyproject.toml" "${DRIVER_ROOT}/README.md" "${DRIVER_ROOT}/manifest.json.in" "${DRIVER_ROOT}/src" "${DRIVER_ROOT}/scripts" "${TMP_ROOT}/context-nexus/"
(cd "${TMP_ROOT}" && tar -czf "${OUT_DIR}/context-nexus.tar.gz" context-nexus)
printf '%s\n' "${OUT_DIR}/context-nexus.tar.gz"
