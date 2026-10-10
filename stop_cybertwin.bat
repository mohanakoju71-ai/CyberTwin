@echo off
setlocal EnableDelayedExpansion
cd /d "%~dp0"
if "%PORT%"=="" set "PORT=8000"
set "FOUND=0"
if exist "data\server.pid" (
  set /p SPID=<"data\server.pid"
  taskkill /PID !SPID! /T /F >nul 2>nul && (echo Stopped CyberTwin ^(PID !SPID!^) & set "FOUND=1")
  del "data\server.pid" >nul 2>nul
)
for /f "tokens=5" %%p in ('netstat -ano ^| findstr /R /C:":%PORT% .*LISTENING"') do (
  taskkill /PID %%p /T /F >nul 2>nul && (echo Stopped process %%p listening on port %PORT% & set "FOUND=1")
)
if "!FOUND!"=="0" echo CyberTwin does not appear to be running on port %PORT%.
pause
endlocal
