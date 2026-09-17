#!/bin/bash
# Vega Sovereign AI Runtime - 1-Click Linux/macOS Launcher
set -e
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"

echo "========================================================================"
echo " VEGA - SOVEREIGN INDUSTRIAL AI RUNTIME"
echo " Local Simulation - CPU-Only Portable Environment"
echo "========================================================================"
echo ""

if ! command -v python3 &> /dev/null; then
    echo "[ERROR] python3 could not be found. Please install Python 3.10+."
    exit 1
fi

echo "Starting Vega Sovereign AI Runtime on http://127.0.0.1:8000..."
python3 run_vega.py --host 127.0.0.1 --port 8000
