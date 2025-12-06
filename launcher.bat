@echo off
setlocal enabledelayedexpansion

where python >nul 2>&1
if %errorlevel% neq 0 (
  echo Python is not installed. Please install Python and try again.
  pause
  exit /b 1
)

pushd "%~dp0"

python -m pip install --upgrade pip

set "REQ_FILE="
if exist "requirements.txt" set "REQ_FILE=requirements.txt"
if not defined REQ_FILE if exist "..\requirements.txt" set "REQ_FILE=..\requirements.txt"

if defined REQ_FILE (
  python -m pip install -r "%REQ_FILE%"
) else (
  python -c "import mitmproxy" >nul 2>&1
  if errorlevel 1 (
    python -m pip install mitmproxy
  )
)

echo Launching SWF Files Downloader...
python "app.py"

popd
endlocal
