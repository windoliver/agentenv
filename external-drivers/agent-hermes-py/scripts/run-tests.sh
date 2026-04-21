#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
DRIVER_ROOT=$(CDPATH= cd -- "${SCRIPT_DIR}/.." && pwd)
PYTHON=${PYTHON:-python3}
VENV=${VENV:-"${DRIVER_ROOT}/.venv"}

if [ ! -x "${VENV}/bin/python" ]; then
    "${PYTHON}" -m venv "${VENV}"
fi

"${VENV}/bin/python" -m pip install -e "${DRIVER_ROOT}[test]"
"${VENV}/bin/python" -m pytest "${DRIVER_ROOT}/tests" "$@"
