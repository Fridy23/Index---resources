echo off
color 03

echo Are you sure you want to continue?
set /p b=
if "%b%" == "yes" goto :disable
if "%b%" == "no" goto :question
cls

:disable
REG ADD HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Diagnostics\Performance\ /v DisableDiagnosticTracing /t REG_DWORD /d 1 /f 
echo Would you like to exit?
set /p c=
if "%c%" == "yes" goto :exit
if "%c%" == "no" goto :question

:exit 
cls
exit
cls

