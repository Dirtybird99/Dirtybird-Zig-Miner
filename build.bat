@echo off
REM Dirtybird Zig Miner -- native build script (Windows cmd).
REM Run from the source root (the directory containing this script).
REM
REM Usage:
REM   build.bat                 Standard ReleaseFast + native-CPU build
REM   build.bat -Dpgo=use       PGO optimized build (after profiling)
REM
REM Any extra arguments are passed straight through to "zig build", so the whole
REM PGO workflow (-Dpgo=gen|use, -Dprofile_rt=...) rides in as pass-through args.

setlocal
cd /d "%~dp0"

where zig >nul 2>nul
if %errorlevel% neq 0 (
    echo error: 'zig' is not on your PATH. Install Zig 0.14.1 and retry.
    exit /b 1
)

echo === Building: ReleaseFast + native CPU (SHA-NI + AVX2) ===
zig build -Doptimize=ReleaseFast -Dcpu=native %*
if %errorlevel% neq 0 (
    echo BUILD FAILED
    exit /b 1
)

echo.
if exist "zig-out\bin\zig-miner.exe" (
    echo === Binary ready: %cd%\zig-out\bin\zig-miner.exe ===
) else (
    echo warning: build finished but zig-out\bin\zig-miner.exe was not found.
)

echo.
echo Test run:
echo   zig-out\bin\zig-miner.exe -d pool.example:10100 -w dero1q...your_wallet... -t 20
