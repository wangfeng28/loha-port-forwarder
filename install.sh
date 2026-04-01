#!/bin/sh
set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
export PYTHONPATH="$SCRIPT_DIR/src${PYTHONPATH:+:$PYTHONPATH}"
exec "${PYTHON:-python3}" -m loha.install "$@"
