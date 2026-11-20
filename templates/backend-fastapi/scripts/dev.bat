@echo off
rem Backend (FastAPI) dev server. Port comes from ports.env (DEV_API_PORT).
setlocal
cd /d "%~dp0.."
for /f "usebackq eol=# tokens=1,* delims==" %%A in ("..\ports.env") do set "%%A=%%B"
if not defined DEV_API_PORT set "DEV_API_PORT=8000"

if not exist ".venv\Scripts\python.exe" (
  echo [backend] run scripts\setup.bat first
  exit /b 1
)
".venv\Scripts\python.exe" -m uvicorn app.main:app --host 127.0.0.1 --port %DEV_API_PORT% --reload --no-server-header
endlocal
