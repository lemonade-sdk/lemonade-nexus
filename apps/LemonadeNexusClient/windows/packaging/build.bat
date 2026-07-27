@echo off
REM Build script for Lemonade Nexus VPN Windows packages
REM Usage: build.bat [msix|msi|exe|all|clean] [debug|release]

setlocal enabledelayedexpansion

REM Default values
set BUILD_TYPE=%1
set CONFIGURATION=%2

if "%BUILD_TYPE%"=="" set BUILD_TYPE=all
if "%CONFIGURATION%"=="" set CONFIGURATION=release

echo ============================================
echo Lemonade Nexus VPN - Windows Package Builder
echo ============================================
echo Build Type: %BUILD_TYPE%
echo Configuration: %CONFIGURATION%
echo ============================================
echo.

REM Check if running in correct directory
if not exist "pubspec.yaml" (
    echo ERROR: Please run this script from the LemonadeNexus directory
    exit /b 1
)

REM Clean build
if "%BUILD_TYPE%"=="clean" (
    echo Cleaning build artifacts...
    if exist "build" rmdir /s /q build
    if exist ".dart_tool" rmdir /s /q .dart_tool
    if exist ".flutter-plugins" del /q .flutter-plugins
    if exist ".flutter-plugins-dependencies" del /q .flutter-plugins-dependencies
    echo Clean complete.
    goto :eof
)

REM Get Flutter dependencies
echo Getting Flutter dependencies...
call flutter pub get
if errorlevel 1 (
    echo ERROR: Flutter pub get failed
    exit /b 1
)

REM Build Flutter Windows app
echo Building Flutter Windows app...
call flutter build windows --%CONFIGURATION%
if errorlevel 1 (
    echo ERROR: Flutter build failed
    exit /b 1
)

echo Flutter build completed successfully.
echo.

REM Build MSIX
if "%BUILD_TYPE%"=="msix" (
    echo Creating MSIX package...
    call dart run msix:create
    if errorlevel 1 (
        echo ERROR: MSIX creation failed
        exit /b 1
    )
    echo MSIX package created successfully.
)

REM Build MSI
if "%BUILD_TYPE%"=="msi" (
    echo Creating MSI installer...
    REM Requires WiX Toolset to be installed
    where candle >nul 2>nul
    if errorlevel 1 (
        echo ERROR: WiX Toolset not found. Please install from https://wixtoolset.org
        exit /b 1
    )

    REM Delayed expansion (!VAR!) is required: %VAR% inside this block would
    REM expand before the set lines run.
    set BUILD_DIR=%cd%\build\windows\x64\runner\Release
    set MSI_DIR=%cd%\windows\packaging\MSI

    mkdir "!MSI_DIR!\obj" 2>nul

    echo Harvesting Flutter bundle with heat...
    heat dir "!BUILD_DIR!" -cg ApplicationFiles -dr INSTALLFOLDER -srd -sreg -scom -gg -var var.BuildDir -out "!MSI_DIR!\HarvestedFiles.wxs"
    if errorlevel 1 (
        echo ERROR: Heat harvesting failed
        exit /b 1
    )

    echo Compiling WiX source files...
    candle -arch x64 -dBuildDir="!BUILD_DIR!" -out "!MSI_DIR!\obj\" "!MSI_DIR!\Product.wxs" "!MSI_DIR!\HarvestedFiles.wxs"
    if errorlevel 1 (
        echo ERROR: Candle compilation failed
        exit /b 1
    )

    echo Linking WiX object files...
    light -cultures:en-us -ext WixUIExtension -out "!MSI_DIR!\nexus-client-setup.msi" -sval "!MSI_DIR!\obj\Product.wixobj" "!MSI_DIR!\obj\HarvestedFiles.wixobj"
    if errorlevel 1 (
        echo ERROR: Light linking failed
        exit /b 1
    )

    echo MSI installer created successfully.
)

REM Build standalone EXE
if "%BUILD_TYPE%"=="exe" (
    echo Creating standalone package...
    set BUILD_DIR=%cd%\build\windows\x64\runner\Release
    set EXE_DIR=%cd%\build\windows\packagesexe
exus-client

    if exist "!EXE_DIR!" rmdir /s /q "!EXE_DIR!"
    mkdir "!EXE_DIR!" 2>nul

    REM The whole Release bundle is the portable app (exe, engine, SDK DLL,
    REM plugin DLLs, data\).
    xcopy /E /I /Y "!BUILD_DIR!\*" "!EXE_DIR!"

    echo Creating ZIP archive...
    powershell -Command "Compress-Archive -Path '!EXE_DIR!' -DestinationPath '%cd%\build\windows\packages\nexus-client-portable.zip' -Force"

    echo Standalone package created successfully.
)

REM Build all
if "%BUILD_TYPE%"=="all" (
    echo Creating all package types...

    REM MSIX
    echo Creating MSIX package...
    call dart run msix:create
    if errorlevel 1 (
        echo WARNING: MSIX creation failed, continuing...
    )

    REM MSI
    echo Creating MSI installer...
    where candle >nul 2>nul
    if not errorlevel 1 (
        set BUILD_DIR=%cd%\build\windows\x64\runner\Release
        set MSI_DIR=%cd%\windows\packaging\MSI

        mkdir "!MSI_DIR!\obj" 2>nul

        heat dir "!BUILD_DIR!" -cg ApplicationFiles -dr INSTALLFOLDER -srd -sreg -scom -gg -var var.BuildDir -out "!MSI_DIR!\HarvestedFiles.wxs"
        if not errorlevel 1 (
            candle -arch x64 -dBuildDir="!BUILD_DIR!" -out "!MSI_DIR!\obj\" "!MSI_DIR!\Product.wxs" "!MSI_DIR!\HarvestedFiles.wxs"
            if not errorlevel 1 (
                light -cultures:en-us -ext WixUIExtension -out "!MSI_DIR!\nexus-client-setup.msi" -sval "!MSI_DIR!\obj\Product.wixobj" "!MSI_DIR!\obj\HarvestedFiles.wixobj"
            )
        )
    ) else (
        echo WARNING: WiX Toolset not found, skipping MSI build
    )

    REM Standalone
    echo Creating standalone package...
    set BUILD_DIR=%cd%\build\windows\x64\runner\Release
    set EXE_DIR=%cd%\build\windows\packagesexe
exus-client

    if exist "!EXE_DIR!" rmdir /s /q "!EXE_DIR!"
    mkdir "!EXE_DIR!" 2>nul

    xcopy /E /I /Y "!BUILD_DIR!\*" "!EXE_DIR!" >nul

    powershell -Command "Compress-Archive -Path '!EXE_DIR!' -DestinationPath '%cd%\build\windows\packages\nexus-client-portable.zip' -Force"

    echo All packages created.
)

echo.
echo ============================================
echo Build Complete!
echo Output directory: %cd%\build\windows
echo ============================================
