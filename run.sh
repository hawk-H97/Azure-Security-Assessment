#!/bin/bash
# 🛡  Azure Audit Pro v1 — Quick Launcher
# Developer: 🦅 Singaram

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$SCRIPT_DIR/.venv"

if [ -d "$VENV" ]; then
    source "$VENV/bin/activate"
    python "$SCRIPT_DIR/main.py" "$@"
else
    echo "Virtual environment not found. Run: bash docker/setup.sh"
    exit 1
fi
