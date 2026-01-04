#!/usr/bin/env bash

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
export PYTHONPATH="$PYTHONPATH:$ROOT_DIR"
uv run python3 "$(dirname "$0")/app.py"