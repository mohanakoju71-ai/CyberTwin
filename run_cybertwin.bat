@echo off
setlocal EnableDelayedExpansion
cd /d "%~dp0"
title CyberTwin
if "%PORT%"=="" set "PORT=8000"
set "LAUNCH_ARGS="
if /i "%~1"=="dev" set "LAUNCH_ARGS=--reload"

rem ---- 1. Find a compatible Python (3.10 - 3.13, 3.12 preferred) ----
set "PY="
py -3.12 -c "import sys" >nul 2>nul && set "PY=py -3.12"
if not defined PY python -c "import sys; sys.exit(0 if (3,10)<=sys.version_info[:2]<=(3,13) else 1)" >nul 2>nul && set "PY=python"
if not defined PY (
  echo [ERROR] No compatible Python found. CyberTwin needs Python 3.10 to 3.13 ^(3.12 recommended^).
  echo         Install it from https://www.python.org/downloads/ and tick "Add python.exe to PATH".
  goto :fail
)
for /f "delims=" %%v in ('%PY% -c "import sys; print(sys.version.split()[0])"') do set "PYV=%%v"
echo Using Python !PYV!  ^(%PY%^)

rem ---- 2. Virtual environment (recreated if it uses an unsupported Python) ----
if exist ".venv\Scripts\python.exe" (
  ".venv\Scripts\python.exe" -c "import sys; sys.exit(0 if (3,10)<=sys.version_info[:2]<=(3,13) else 1)" >nul 2>nul
  if errorlevel 1 (
    echo The existing .venv uses an unsupported Python. Recreating it...
    rmdir /s /q ".venv"
  )
)
if not exist ".venv\Scripts\python.exe" (
  echo Creating virtual environment .venv ...
  %PY% -m venv ".venv"
  if errorlevel 1 goto :fail
)
set "VPY=.venv\Scripts\python.exe"

rem ---- 3. Dependencies: install only when requirements.txt changed or imports fail ----
set "NEED=0"
fc /b "requirements.txt" ".venv\requirements.installed" >nul 2>nul
if errorlevel 1 set "NEED=1"
if "!NEED!"=="0" (
  "%VPY%" -c "import fastapi, uvicorn, sqlalchemy, sklearn, numpy, joblib, httpx" >nul 2>nul
  if errorlevel 1 set "NEED=1"
)
if "!NEED!"=="1" (
  echo Installing dependencies ^(this can take a few minutes the first time^)...
  "%VPY%" -m pip install --disable-pip-version-check -r "requirements.txt"
  if errorlevel 1 (
    echo [ERROR] Dependency installation failed. Check your internet connection and the messages above.
    goto :fail
  )
  "%VPY%" -c "import fastapi, uvicorn, sqlalchemy, sklearn, numpy, joblib, httpx"
  if errorlevel 1 (
    echo [ERROR] Packages installed but could not be imported. Delete the .venv folder and run this file again.
    goto :fail
  )
  copy /y "requirements.txt" ".venv\requirements.installed" >nul
)

if not exist ".env" if exist ".env.example" copy /y ".env.example" ".env" >nul

rem ---- 4. Start: the launcher waits for /api/health, then opens the browser ----
echo.
"%VPY%" scripts\launch.py %LAUNCH_ARGS%
set "RC=%ERRORLEVEL%"
if not "%RC%"=="0" (
  echo.
  echo [CyberTwin] The server exited with code %RC%.
  goto :fail
)
goto :end

:fail
echo.
echo [CyberTwin] Startup failed. Read the message above, fix it, and run this file again.
echo             Port problem?  See "Troubleshooting" in README.md.
pause
exit /b 1
:end
endlocal
