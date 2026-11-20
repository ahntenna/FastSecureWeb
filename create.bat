@echo off
rem Interactive project generator. Installs the generator's own dependency on first run.
rem Every exit path goes through ":finish", which waits for a key press when the script
rem was started without arguments (e.g. double-click) so the output stays readable.
setlocal
cd /d "%~dp0"
set "RC=0"

where node >nul 2>&1
if errorlevel 1 (
  echo Node.js 22 or newer is required.
  set "RC=1"
  goto finish
)

if not exist "node_modules\@clack\prompts" (
  call npm install --no-fund --no-audit
  if errorlevel 1 (
    echo Failed to install the generator dependency.
    set "RC=1"
    goto finish
  )
)

node create.mjs %*
set "RC=%ERRORLEVEL%"

:finish
rem Interactive run (no arguments): wait so the user can read the output above.
rem With arguments (--name ..., --help) it does not wait, so scripted runs are not blocked.
if "%~1"=="" (
  echo.
  pause
)
endlocal & exit /b %RC%
