@echo off
cd /d "%~dp0"

if not exist config.json (
  echo config.json was not found.
  echo Copy config.example.json to config.json and enter the real source, backup, and report paths.
  pause
  exit /b 1
)

where py >nul 2>&1
if errorlevel 1 (
  python pe_backup_web.py --config config.json
) else (
  py pe_backup_web.py --config config.json
)
if errorlevel 1 pause
