@echo off
REM Lemonade Nexus Flutter test runner (Windows).
REM Thin wrapper around `flutter test` in the apps\LemonadeNexus directory.

setlocal
set "SCRIPT_DIR=%~dp0"
set "APP_DIR=%SCRIPT_DIR%..\apps\LemonadeNexus"

if not exist "%APP_DIR%" (
    echo Flutter app directory not found at %APP_DIR%
    exit /b 1
)

pushd "%APP_DIR%"
call flutter pub get
if errorlevel 1 (
    popd
    exit /b %ERRORLEVEL%
)
call flutter test
set "RC=%ERRORLEVEL%"
popd
exit /b %RC%
