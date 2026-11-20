@echo off
rem Backend security tests + frontend type check.
setlocal
cd /d "%~dp0.."

call backend\scripts\test.bat
if errorlevel 1 (
  echo [test] backend tests FAILED
  exit /b 1
)

pushd frontend
call npm run typecheck
if errorlevel 1 (
  popd
  echo [test] frontend type check FAILED
  exit /b 1
)
popd

echo [test] all passed
endlocal
