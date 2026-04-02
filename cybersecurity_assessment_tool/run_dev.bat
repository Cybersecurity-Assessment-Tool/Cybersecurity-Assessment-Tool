@echo off
setlocal EnableDelayedExpansion

REM Run Django development server and Django Q cluster simultaneously.
REM Usage: run_dev.bat [port]  (default port: 8000)

set PORT=%1
if "%PORT%"=="" set PORT=8000

cd /d "%~dp0"

echo Starting Django development server on port %PORT%...
start "Django-Server" cmd /k python manage.py runserver %PORT%

echo Starting Django Q cluster...
start "Django-QCluster" cmd /k python manage.py qcluster

echo.
echo Both processes are running in separate windows.
echo Press any key here to shut down both and exit.
echo.
pause >nul

echo Shutting down server and qcluster...
taskkill /fi "WindowTitle eq Django-Server*" /f >nul 2>&1
taskkill /fi "WindowTitle eq Django-QCluster*" /f >nul 2>&1
echo Done.
endlocal
