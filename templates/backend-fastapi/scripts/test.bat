@echo off
rem Backend (FastAPI) security tests
setlocal
cd /d "%~dp0.."
if not exist ".venv\Scripts\python.exe" (
  echo [backend] run scripts\setup.bat first
  exit /b 1
)
".venv\Scripts\python.exe" -m pytest -q
endlocal
