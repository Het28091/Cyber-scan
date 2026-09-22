@echo off
setlocal
powershell.exe -NoProfile -File "%~dp0scripts\setup-windows.ps1" %*
exit /b %ERRORLEVEL%
