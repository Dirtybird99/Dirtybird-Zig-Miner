@echo off
REM Dirtybird Zig Miner -- launcher (Windows).
REM Presets (pool + wallet + threads) live in config.json next to zig-miner.exe.
REM Edit config.json once with YOUR wallet, then double-click this. At each prompt,
REM press Enter to keep the config.json value, or type a value to override it.
setlocal EnableDelayedExpansion
cd /d "%~dp0"

set "BIN=zig-miner.exe"
if not exist "%BIN%" if exist "zig-out\bin\zig-miner.exe" set "BIN=zig-out\bin\zig-miner.exe"
if not exist "%BIN%" (
    echo error: zig-miner.exe not found. Run this from a release folder ^(next to zig-miner.exe^).
    pause
    exit /b 1
)

echo Presets come from config.json (edit it to set your own wallet). Press Enter to use them.
set /p DAEMON=Daemon/pool host:port [Enter=config.json]:
set /p WALLET=DERO wallet           [Enter=config.json]:
set /p THREADS=Threads              [Enter=config.json]:

set "ARGS="
if not "%DAEMON%"==""  set "ARGS=!ARGS! -d %DAEMON%"
if not "%WALLET%"==""  set "ARGS=!ARGS! -w %WALLET%"
if not "%THREADS%"=="" set "ARGS=!ARGS! -t %THREADS%"

echo.
echo Starting: %BIN% !ARGS!
echo (Ctrl-C to stop)
echo.
"%BIN%" !ARGS!
