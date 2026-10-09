@echo off
rem ---------------------------------------------------------------------------
rem Keep this file PURE ASCII. cmd.exe parses .bat byte-by-byte using the
rem console code page; a UTF-8 Chinese string gets read as GBK, the byte
rem alignment shifts, and the parser breaks in the middle of a token.
rem All Chinese guidance is printed by pool.py instead (Python reconfigures
rem its stdout to UTF-8, so it renders correctly under chcp 65001).
rem ---------------------------------------------------------------------------
chcp 65001 >nul
cd /d "%~dp0"
title freeVPN

where python >nul 2>nul
if errorlevel 1 (
    echo [x] Python not found. Install Python 3.10+ and add it to PATH.
    pause
    exit /b 1
)

if not exist "bin\mihomo.exe" (
    echo [!] bin\mihomo.exe missing - L2 kernel probing will be skipped
    echo     and the pool quality will drop a lot.
    echo     Download: https://github.com/MetaCubeX/mihomo/releases
    echo.
)

python pool.py daemon --port 8787 --interval 30
pause
