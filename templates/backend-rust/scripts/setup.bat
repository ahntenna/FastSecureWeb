@echo off
rem Backend (Rust) local setup: dev .env + first build
setlocal
cd /d "%~dp0.."

where cargo >nul 2>&1
if errorlevel 1 (
  echo [backend] Rust toolchain is required. Install it from https://rustup.rs
  exit /b 1
)
if not exist ".env" (
  copy /y ".env.dev.example" ".env" >nul
  echo [backend] created backend\.env from .env.dev.example
)
echo [backend] building (the first build takes a few minutes)
cargo build
if errorlevel 1 exit /b 1
echo [backend] setup done
endlocal
