@echo off
rem Backend (Rust) security tests
setlocal
cd /d "%~dp0.."
cargo test
endlocal
