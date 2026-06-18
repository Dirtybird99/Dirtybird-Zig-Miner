@echo off
REM Dirtybird Zig Miner -- launcher (Windows).
REM Your settings live in config.json next to this file. You can edit config.json
REM directly, OR answer "y" below to set pool/wallet/threads interactively -- either way
REM persists to the same config.json that the miner reads. Double-click to run.
setlocal
cd /d "%~dp0"

set "BIN=zig-miner.exe"
if not exist "%BIN%" if exist "zig-out\bin\zig-miner.exe" set "BIN=zig-out\bin\zig-miner.exe"
if not exist "%BIN%" (
    echo error: zig-miner.exe not found. Run this from a release folder ^(next to zig-miner.exe^).
    pause
    exit /b 1
)

set /p EDIT=Change pool/wallet/threads? (y/N):
if /i "%EDIT%"=="y" "%BIN%" --setup

echo.
echo Starting miner (Ctrl-C to stop)...
echo.
"%BIN%"
