@echo off
setlocal
cd /d "%~dp0"
if exist ".venv\Scripts\python.exe" goto venv
if exist ".runtime\python\python.exe" goto bundled
rem Never invoke Store execution aliases or a launcher that may install Python.
for /f "delims=" %%P in ('where python.exe 2^>nul ^| findstr /v /i "WindowsApps"') do (
  set "AEGIS_FOUND_PYTHON=%%P"
  goto installed
)
echo Install a reviewed local Python 3.11+ runtime first. See QUICKSTART.md.
exit /b 1
:venv
".venv\Scripts\python.exe" aegis.py %*
exit /b %errorlevel%
:bundled
".runtime\python\python.exe" aegis.py %*
exit /b %errorlevel%
:installed
"%AEGIS_FOUND_PYTHON%" aegis.py %*
exit /b %errorlevel%
