@echo off
rem Backend (Rust) dev server. Port comes from ports.env (DEV_API_PORT).
setlocal
cd /d "%~dp0.."
for /f "usebackq eol=# tokens=1,* delims==" %%A in ("..\ports.env") do set "%%A=%%B"
if not defined DEV_API_PORT set "DEV_API_PORT=8000"

if not exist ".env" (
  echo [backend] run scripts\setup.bat first
  exit /b 1
)
rem The server reads API_PORT; here it is the local dev port, not the container port.
set "API_PORT=%DEV_API_PORT%"
cargo run
endlocal
