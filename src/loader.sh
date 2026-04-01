#!/bin/sh
set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
if [ -d "$SCRIPT_DIR/../src" ]; then
  export PYTHONPATH="$SCRIPT_DIR/../src${PYTHONPATH:+:$PYTHONPATH}"
fi
exec "${PYTHON:-python3}" -m loha.loader "$@"
