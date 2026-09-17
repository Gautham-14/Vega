@echo off
cd /d "%~dp0"
REM Vega Sovereign AI Runtime - 1-Click Windows Launcher
echo ========================================================================
echo  VEGA - SOVEREIGN INDUSTRIAL AI RUNTIME
echo  Local Simulation - CPU-Only Portable Environment
echo ========================================================================
echo.

REM Verify Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python 3 not detected in PATH.
    echo Please install Python 3.10+ to run Vega locally.
    pause
    exit /b 1
)

echo Starting Vega Sovereign AI Runtime on http://127.0.0.1:8000...
python run_vega.py --host 127.0.0.1 --port 8000
pause
