@echo off
cd /d "%~dp0"
call Aegis.bat %*
exit /b %errorlevel%
