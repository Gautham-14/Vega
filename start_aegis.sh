#!/bin/bash
# Aegis Sovereign AI Runtime - 1-Click Linux/macOS Launcher
set -e
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"

echo "========================================================================"
echo " AEGIS - SOVEREIGN INDUSTRIAL AI RUNTIME"
echo " Local Simulation - CPU-Only Portable Environment"
echo "========================================================================"
echo ""

if ! command -v python3 &> /dev/null; then
    echo "[ERROR] python3 could not be found. Please install Python 3.10+."
    exit 1
fi

echo "Starting Aegis Sovereign AI Runtime on http://127.0.0.1:8000..."
python3 run_aegis.py --host 127.0.0.1 --port 8000
