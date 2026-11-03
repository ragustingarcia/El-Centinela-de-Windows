@echo off
setlocal DisableDelayedExpansion
title El Centinela de Windows
rem No elevation, temporary executable, PATH lookup or shell-built script.
set "PSModulePath=%SystemRoot%\System32\WindowsPowerShell\v1.0\Modules"
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0src\Centinela.ps1"
exit /b %errorlevel%
