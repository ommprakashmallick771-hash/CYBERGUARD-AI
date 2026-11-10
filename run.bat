@echo off
setlocal EnableExtensions
cd /d "%~dp0"
title CyberGuard AI - Local Server
echo ================================================================
echo   CyberGuard AI - starting up, please wait a moment...
echo ================================================================
set "PY="
if exist "runtime\python\python.exe" set "PY=runtime\python\python.exe"
if not defined PY ( python --version >nul 2>&1 && set "PY=python" )
if not defined PY ( py -3 --version >nul 2>&1 && set "PY=py -3" )
if defined PY goto :run

echo Python was not found. Downloading a portable copy (about 11 MB, one time only)...
if not exist runtime mkdir runtime
powershell -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Stop'; [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; $ProgressPreference='SilentlyContinue'; Invoke-WebRequest -UseBasicParsing 'https://www.python.org/ftp/python/3.12.8/python-3.12.8-embed-amd64.zip' -OutFile 'runtime\py.zip'; Expand-Archive -Force 'runtime\py.zip' 'runtime\python'; Remove-Item 'runtime\py.zip'"
if not exist "runtime\python\python.exe" (
  echo.
  echo Could not download Python. Please check your internet connection and run this file again.
  pause
  exit /b 1
)
set "PY=runtime\python\python.exe"

:run
echo Using Python: %PY%
%PY% server.py
echo.
echo Server stopped.
pause
