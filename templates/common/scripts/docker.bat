@echo off
rem Docker helper (Windows).
rem   scripts\docker.bat local up      build + start, published on 127.0.0.1:WEB_HOST_PORT
rem   scripts\docker.bat local down
rem   scripts\docker.bat local logs
rem   scripts\docker.bat npm up        behind Nginx Proxy Manager (see docs\DEPLOY.md)
rem Ports: ports.env    Settings: .env (copied from .env.example on first run)
setlocal
cd /d "%~dp0.."

set "MODE=%~1"
set "ACTION=%~2"
if "%MODE%"=="" goto usage
if "%ACTION%"=="" goto usage
if /i not "%MODE%"=="local" if /i not "%MODE%"=="npm" goto usage

where docker >nul 2>&1
if errorlevel 1 (
  echo [docker] Docker is not installed or not on PATH.
  exit /b 1
)
if not exist "secrets\server_sign_key.pem" (
  node scripts\gen-keys.mjs
  if errorlevel 1 exit /b 1
)
if not exist ".env" (
  if /i "%MODE%"=="npm" (
    echo [docker] .env is missing. Copy .env.example to .env and set ALLOWED_HOSTS first.
    exit /b 1
  )
  copy /y ".env.example" ".env" >nul
  echo [docker] created .env from .env.example
)

set "COMPOSE=docker compose --env-file ports.env --env-file .env -f docker-compose.yml -f docker-compose.%MODE%.yml"

if /i "%ACTION%"=="up"    %COMPOSE% up -d --build & goto done
if /i "%ACTION%"=="down"  %COMPOSE% down & goto done
if /i "%ACTION%"=="logs"  %COMPOSE% logs -f --tail 100 & goto done
if /i "%ACTION%"=="ps"    %COMPOSE% ps & goto done
if /i "%ACTION%"=="build" %COMPOSE% build & goto done
goto usage

:done
if errorlevel 1 exit /b 1
if /i "%MODE%"=="local" if /i "%ACTION%"=="up" (
  for /f "usebackq eol=# tokens=1,* delims==" %%A in ("ports.env") do set "%%A=%%B"
  call echo [docker] open http://127.0.0.1:%%WEB_HOST_PORT%%
)
exit /b 0

:usage
echo usage: scripts\docker.bat ^<local^|npm^> ^<up^|down^|logs^|ps^|build^>
exit /b 1
