@echo off
rem One-time local setup: signing keys, backend deps, frontend deps.
setlocal
cd /d "%~dp0.."

where node >nul 2>&1
if errorlevel 1 (
  echo [setup] Node.js 22 or newer is required.
  exit /b 1
)

if not exist "secrets\server_sign_key.pem" (
  node scripts\gen-keys.mjs
  if errorlevel 1 exit /b 1
)

call backend\scripts\setup.bat
if errorlevel 1 exit /b 1

pushd frontend
echo [frontend] installing dependencies
call npm install
if errorlevel 1 (
  popd
  exit /b 1
)
popd

echo.
echo [setup] done. Start the dev servers with: scripts\dev.bat
endlocal
