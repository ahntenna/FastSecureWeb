@echo off
rem Try the obfuscated release bundle locally without Docker.
rem Builds the release bundle, then serves it with "vite preview" (same CSP as nginx)
rem next to the local backend. Check here that the obfuscated code runs under the CSP.
setlocal
set "ROOT=%~dp0.."
for /f "usebackq eol=# tokens=1,* delims==" %%A in ("%ROOT%\ports.env") do set "%%A=%%B"

call "%~dp0build-release.bat"
if errorlevel 1 exit /b 1

start "__PROJECT_NAME__ api" /d "%ROOT%\backend" cmd /k scripts\dev.bat
start "__PROJECT_NAME__ web (release preview)" /d "%ROOT%\frontend" cmd /k npm run preview

echo [preview] web : http://localhost:%DEV_WEB_PORT%
endlocal
