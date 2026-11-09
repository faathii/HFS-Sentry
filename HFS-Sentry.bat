@echo off
cd /d "%~dp0"
if exist "dist\HFS-Sentry.exe" (
    start "" "dist\HFS-Sentry.exe" %*
) else (
    start "" pythonw sentry.py %*
)

