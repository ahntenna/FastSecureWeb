@echo off
rem Backend (FastAPI) local setup: virtualenv + dependencies + dev .env
setlocal
cd /d "%~dp0.."

if not exist ".venv\Scripts\python.exe" (
  echo [backend] creating virtualenv .venv
  python -m venv .venv || exit /b 1
)
echo [backend] installing dependencies
".venv\Scripts\python.exe" -m pip install -q --disable-pip-version-check -r requirements-dev.txt || exit /b 1

if not exist ".env" (
  copy /y ".env.dev.example" ".env" >nul
  echo [backend] created backend\.env from .env.dev.example
)
echo [backend] setup done
endlocal
