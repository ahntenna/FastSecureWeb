@echo off
rem Release build of the frontend: type check, bundle, obfuscate, verify.
rem Output: frontend\dist  (the Docker web image runs the same steps on its own)
setlocal
cd /d "%~dp0..\frontend"
call npm run build:release
if errorlevel 1 exit /b 1
echo [build] release bundle is in frontend\dist
endlocal
