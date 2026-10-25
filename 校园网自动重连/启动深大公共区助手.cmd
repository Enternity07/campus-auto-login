@echo off
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0SzuPublicAutoLogin.ps1" -Action Menu
if errorlevel 1 pause
