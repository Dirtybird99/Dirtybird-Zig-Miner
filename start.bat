@echo off
REM Dirtybird Zig Miner -- interactive launcher (Windows).
REM Prompts for your daemon/pool address and DERO wallet, then starts mining.
REM Double-click it, or run it from a release folder next to zig-miner.exe.
setlocal EnableDelayedExpansion
cd /d "%~dp0"

set "BIN=zig-miner.exe"
if not exist "%BIN%" if exist "zig-out\bin\zig-miner.exe" set "BIN=zig-out\bin\zig-miner.exe"
if not exist "%BIN%" (
    echo error: zig-miner.exe not found. Build it first ^(build.bat^) or run this from a release folder.
    pause
    exit /b 1
)

set /p DAEMON=Daemon/pool address (host:port):
set /p WALLET=DERO wallet address:
set /p THREADS=Threads [10]:
if "%THREADS%"=="" set "THREADS=10"

if "%DAEMON%"=="" ( echo error: a daemon address is required. & pause & exit /b 1 )
if "%WALLET%"=="" ( echo error: a wallet is required. & pause & exit /b 1 )

echo.
echo Starting: %BIN% -d %DAEMON% -w %WALLET% -t %THREADS%
echo (Ctrl-C to stop)
echo.
"%BIN%" -d "%DAEMON%" -w "%WALLET%" -t "%THREADS%"
