@echo off
rem Local development without Docker: backend + Vite dev server, each in its own window.
rem Ports come from ports.env (DEV_API_PORT, DEV_WEB_PORT).
setlocal
set "ROOT=%~dp0.."
for /f "usebackq eol=# tokens=1,* delims==" %%A in ("%ROOT%\ports.env") do set "%%A=%%B"

start "__PROJECT_NAME__ api" /d "%ROOT%\backend" cmd /k scripts\dev.bat
start "__PROJECT_NAME__ web" /d "%ROOT%\frontend" cmd /k npm run dev

echo [dev] api : http://127.0.0.1:%DEV_API_PORT%/api/health
echo [dev] web : http://localhost:%DEV_WEB_PORT%
endlocal
