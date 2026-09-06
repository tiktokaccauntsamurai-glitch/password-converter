@echo off
REM pwvault launcher for Windows - double-click this file.
setlocal
cd /d "%~dp0"
set "PY="
where py >NUL 2>&1
if not errorlevel 1 set "PY=py -3"
if defined PY goto run
where python >NUL 2>&1
if not errorlevel 1 set "PY=python"
if defined PY goto run
echo Python 3.9 or newer was not found.
echo Install it from https://www.python.org/downloads/windows/
echo and tick "Add python.exe to PATH" during setup, then run this again.
pause
exit /b 1
:run
%PY% -m pwvault %*
if errorlevel 1 pause
endlocal
