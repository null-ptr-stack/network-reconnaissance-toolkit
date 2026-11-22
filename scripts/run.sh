
#!/bin/bash

# Network Reconnaissance Toolkit
# Bash execution wrapper

set -e

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

PYTHON_SCRIPT="$PROJECT_DIR/src/nrt.py"

echo "========================================"
echo "     NETWORK RECONNAISSANCE TOOLKIT"
echo "========================================"

# Check Python installation

if ! command -v python3 >/dev/null 2>&1; then
    echo "[ERROR] Python3 is not installed."
    exit 1
fi

# Check Nmap installation

if ! command -v nmap >/dev/null 2>&1; then
    echo "[ERROR] Nmap is not installed."
    exit 1
fi

# Check Python script

if [[ ! -f "$PYTHON_SCRIPT" ]]; then
    echo "[ERROR] Python scanner not found."
    exit 1
fi

# Execute scanner

python3 "$PYTHON_SCRIPT" "$@"

