#!/bin/sh
set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
ROOT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
export PYTHONPATH="$ROOT_DIR/src${PYTHONPATH:+:$PYTHONPATH}"
python3 -m unittest discover -s "$ROOT_DIR/tests" -p "test_*.py"
