@echo off
rem PURE ASCII only - see the note in start.bat for why.
chcp 65001 >nul
cd /d "%~dp0"
title freeVPN - Console

where python >nul 2>nul
if errorlevel 1 (
    echo [x] Python not found. Install Python 3.10+ and add it to PATH.
    pause
    exit /b 1
)

rem pythonw = no console window behind the GUI
set PYW=pythonw
where pythonw >nul 2>nul || set PYW=python

start "" %PYW% pool.py gui
exit /b 0
