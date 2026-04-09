# Build Scripts for Lemonade Nexus VPN Windows Packages
# PowerShell scripts for building MSIX, MSI, and standalone packages

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet('msix', 'msi', 'exe', 'all', 'clean')]
    [string]$BuildType = 'all',

    [Parameter(Mandatory=$false)]
    [ValidateSet('debug', 'release')]
    [string]$Configuration = 'release',

    [Parameter(Mandatory=$false)]
    [switch]$SignPackages,

    [Parameter(Mandatory=$false)]
    [switch]$SkipFlutterBuild,

    [Parameter(Mandatory=$false)]
    [string]$CertificatePath,

    [Parameter(Mandatory=$false)]
    [SecureString]$CertificatePassword
)

$ErrorActionPreference = 'Stop'
$VerbosePreference = 'Continue'

# =============================================================================
# Configuration
# =============================================================================

$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptRoot
$FlutterRoot = if ($env:FLUTTER_ROOT) { $env:FLUTTER_ROOT } else { 'C:\src\flutter' }
$BuildDir = Join-Path $ProjectRoot 'build\windows'
$OutputDir = Join-Path $BuildDir 'packages'

# Package names
$PackageName = 'lemonade_nexus'
$PackageDisplayName = 'Lemonade Nexus VPN'
$PackageVersion = '1.0.0.0'
$PublisherName = 'Lemonade Nexus'
$PublisherCN = 'CN=Lemonade Nexus, O=Lemonade Nexus, C=US'

# SignTool configuration
$SignToolPath = 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.19041.0\x64\signtool.exe'
$TimestampUrl = 'http://timestamp.digicert.com'
$TimestampUrlBackup = 'http://timestamp.sectigo.com'

# =============================================================================
# Helper Functions
# =============================================================================

function Write-Status {
    param([string]$Message, [string]$Level = 'INFO')
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $(if ($Level -eq 'ERROR') { 'Red' } elseif ($Level -eq 'SUCCESS') { 'Green' } else { 'Cyan' })
}

function Test-Prerequisite {
    param(
        [string]$Name,
        [scriptblock]$Check,
        [string]$InstallUrl
    )

    Write-Status "Checking: $Name"
    try {
        if (& $Check) {
            Write-Status "$Name - OK" 'SUCCESS'
            return $true
        } else {
            Write-Status "$Name - NOT FOUND" 'ERROR'
            if ($InstallUrl) {
                Write-Host "  Install from: $InstallUrl" -ForegroundColor Yellow
            }
            return $false
        }
    } catch {
        Write-Status "$Name - ERROR: $_" 'ERROR'
        return $false
    }
}

function Invoke-WithRetry {
    param(
        [scriptblock]$Command,
        [int]$MaxRetries = 3,
        [int]$RetryDelay = 5
    )

    $attempt = 0
    while ($attempt -lt $MaxRetries) {
        try {
            return & $Command
        } catch {
            $attempt++
            if ($attempt -ge $MaxRetries) {
                throw
            }
            Write-Status "Retry $attempt/$MaxRetries after error: $_" 'WARNING'
            Start-Sleep -Seconds $RetryDelay
        }
    }
}

function New-Directory {
    param([string]$Path)
    if (-not (Test-Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Remove-Directory {
    param([string]$Path)
    if (Test-Path $Path) {
        Remove-Item -Path $Path -Recurse -Force
    }
}

# =============================================================================
# Check Prerequisites
# =============================================================================

function Test-Prerequisites {
    Write-Status '=== Checking Prerequisites ==='

    $allPassed = $true

    # Flutter SDK
    $allPassed = $allPassed -and (Test-Prerequisite -Name 'Flutter SDK' -Check {
        $flutterExe = Join-Path $FlutterRoot 'bin\flutter.bat'
        Test-Path $flutterExe
    } -InstallUrl 'https://docs.flutter.dev/get-started/install/windows')

    # Git
    $allPassed = $allPassed -and (Test-Prerequisite -Name 'Git' -Check {
        $null -ne (Get-Command 'git' -ErrorAction SilentlyContinue)
    } -InstallUrl 'https://git-scm.com/download/win')

    # Visual Studio Build Tools
    $allPassed = $allPassed -and (Test-Prerequisite -Name 'Visual Studio Build Tools' -Check {
        $vswherePath = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
        if (Test-Path $vswherePath) {
            $null -ne (& $vswherePath -latest -requires 'Microsoft.VisualStudio.Component.VC.Tools.x86.x64' -property displayName)
        } else {
            $false
        }
    } -InstallUrl 'https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2022')

    # WiX Toolset (for MSI)
    $allPassed = $allPassed -and (Test-Prerequisite -Name 'WiX Toolset' -Check {
        $null -ne (Get-Command 'candle' -ErrorAction SilentlyContinue)
    } -InstallUrl 'https://wixtoolset.org/docs/getting-started/')

    # SignTool (for signing)
    $allPassed = $allPassed -and (Test-Prerequisite -Name 'SignTool' -Check {
        Test-Path $SignToolPath
    } -InstallUrl 'https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/')

    return $allPassed
}

# =============================================================================
# Build Flutter Windows App
# =============================================================================

function Build-FlutterApp {
    param([string]$Config = 'release')

    Write-Status '=== Building Flutter Windows App ==='

    $flutterArgs = @(
        'build',
        'windows',
        "--$Config"
    )

    if ($Config -eq 'release') {
        $flutterArgs += '--dart-define=BUILD_TYPE=production'
    }

    Push-Location $ProjectRoot
    try {
        Write-Status "Running: flutter $($flutterArgs -join ' ')"
        & (Join-Path $FlutterRoot 'bin\flutter.bat') @flutterArgs
        if ($LASTEXITCODE -ne 0) {
            throw "Flutter build failed with exit code $LASTEXITCODE"
        }
        Write-Status 'Flutter build completed' 'SUCCESS'
    } finally {
        Pop-Location
    }
}

# =============================================================================
# Create MSIX Package
# =============================================================================

function Build-MSIX {
    Write-Status '=== Building MSIX Package ==='

    # Create output directory
    $msixOutputDir = Join-Path $OutputDir 'msix'
    New-Directory $msixOutputDir

    # Build using msix package
    Push-Location $ProjectRoot
    try {
        Write-Status 'Creating MSIX package...'

        # Set certificate password if provided
        if ($CertificatePassword) {
            $securePassword = $CertificatePassword
            $passwordString = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
                [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
            )
            $env:CERT_PASSWORD = $passwordString
        }

        # Run msix:create
        $msixArgs = @('dart', 'run', 'msix:create')
        if ($SignPackages) {
            $msixArgs += '--sign'
        }

        Write-Status "Running: $($msixArgs -join ' ')"
        & 'dart' @msixArgs

        if ($LASTEXITCODE -ne 0) {
            throw "MSIX creation failed with exit code $LASTEXITCODE"
        }

        # Copy to output directory
        $msixSource = Join-Path $ProjectRoot 'build\windows\runner\Release\lemonade_nexus.msix'
        if (Test-Path $msixSource) {
            Copy-Item $msixSource -Destination $msixOutputDir -Force
            Write-Status "MSIX package created: $(Join-Path $msixOutputDir 'lemonade_nexus.msix')" 'SUCCESS'
        }

    } finally {
        Pop-Location
    }
}

# =============================================================================
# Create MSI Installer
# =============================================================================

function Build-MSI {
    Write-Status '=== Building MSI Installer ==='

    $msiOutputDir = Join-Path $OutputDir 'msi'
    New-Directory $msiOutputDir

    $wixDir = Join-Path $ProjectRoot 'windows\packaging\MSI'
    $buildDir = Join-Path $ProjectRoot 'build\windows\runner\Release'

    Push-Location $wixDir
    try {
        # Compile WiX source files
        Write-Status 'Compiling WiX source files...'

        $candleArgs = @(
            '-arch', 'x64',
            "-dBuildDir=$buildDir",
            '-out', (Join-Path $msiOutputDir 'obj\'),
            'Product.wxs',
            'Installer.wxs'
        )

        New-Directory (Join-Path $msiOutputDir 'obj')

        Write-Status "Running: candle $($candleArgs -join ' ')"
        & 'candle' @candleArgs

        if ($LASTEXITCODE -ne 0) {
            throw "Candle compilation failed with exit code $LASTEXITCODE"
        }

        # Link WiX object files
        Write-Status 'Linking WiX object files...'

        $lightArgs = @(
            '-cultures:en-us',
            '-out', (Join-Path $msiOutputDir 'lemonade_nexus_setup.msi'),
            '-sval',  # Skip validation
            (Join-Path $msiOutputDir 'obj\Product.wixobj'),
            (Join-Path $msiOutputDir 'obj\Installer.wixobj')
        )

        Write-Status "Running: light $($lightArgs -join ' ')"
        & 'light' @lightArgs

        if ($LASTEXITCODE -ne 0) {
            throw "Light linking failed with exit code $LASTEXITCODE"
        }

        Write-Status "MSI installer created: $(Join-Path $msiOutputDir 'lemonade_nexus_setup.msi')" 'SUCCESS'

    } finally {
        Pop-Location
    }
}

# =============================================================================
# Create Standalone EXE Package
# =============================================================================

function Build-EXE {
    Write-Status '=== Creating Standalone EXE Package ==='

    $exeOutputDir = Join-Path $OutputDir 'exe'
    New-Directory $exeOutputDir

    $buildDir = Join-Path $ProjectRoot 'build\windows\runner\Release'

    # Copy executable and required files
    $filesToCopy = @(
        'lemonade_nexus.exe',
        'flutter_windows.dll',
        'icudtl.dat',
        'data\app.so',
        'data\flutter_assets'
    )

    foreach ($file in $filesToCopy) {
        $source = Join-Path $buildDir $file
        if (Test-Path $source) {
            $destDir = Join-Path $exeOutputDir (Split-Path $file -Parent)
            New-Directory $destDir
            Copy-Item $source -Destination (Join-Path $exeOutputDir $file) -Force
        }
    }

    # Create ZIP archive
    $zipPath = Join-Path $exeOutputDir 'lemonade_nexus_portable.zip'
    if (Test-Path $exeOutputDir) {
        Compress-Archive -Path "$exeOutputDir\*" -DestinationPath $zipPath -Force
        Write-Status "Portable package created: $zipPath" 'SUCCESS'
    }
}

# =============================================================================
# Sign Package
# =============================================================================

function Sign-Package {
    param([string]$PackagePath)

    if (-not (Test-Path $SignToolPath)) {
        Write-Status 'SignTool not found, skipping signing' 'WARNING'
        return
    }

    if (-not (Test-Path $PackagePath)) {
        Write-Status "Package not found: $PackagePath" 'ERROR'
        return
    }

    Write-Status "Signing: $PackagePath"

    $signArgs = @(
        'sign',
        '/f', $CertificatePath,
        '/p', $CertificatePassword,
        '/t', $TimestampUrl,
        '/fd', 'sha256',
        '/a',
        $PackagePath
    )

    & $SignToolPath @signArgs

    if ($LASTEXITCODE -eq 0) {
        Write-Status "Successfully signed: $PackagePath" 'SUCCESS'
    } else {
        Write-Status "Failed to sign: $PackagePath" 'ERROR'
    }
}

# =============================================================================
# Clean Build
# =============================================================================

function Clean-Build {
    Write-Status '=== Cleaning Build Artifacts ==='

    $dirsToClean = @(
        (Join-Path $ProjectRoot 'build'),
        (Join-Path $ProjectRoot '.dart_tool'),
        (Join-Path $ProjectRoot '.flutter-plugins'),
        (Join-Path $ProjectRoot '.flutter-plugins-dependencies')
    )

    foreach ($dir in $dirsToClean) {
        if (Test-Path $dir) {
            Remove-Item -Path $dir -Recurse -Force
            Write-Status "Cleaned: $dir"
        }
    }

    Write-Status 'Build artifacts cleaned' 'SUCCESS'
}

# =============================================================================
# Main Execution
# =============================================================================

function Main {
    Write-Status '============================================'
    Write-Status "Lemonade Nexus VPN - Windows Package Builder"
    Write-Status "Build Type: $BuildType"
    Write-Status "Configuration: $Configuration"
    Write-Status '============================================'

    # Handle clean command
    if ($BuildType -eq 'clean') {
        Clean-Build
        return
    }

    # Check prerequisites
    if (-not (Test-Prerequisites)) {
        Write-Status 'Some prerequisites are missing. Please install them and try again.' 'ERROR'
        exit 1
    }

    # Build Flutter app (if not skipped)
    if (-not $SkipFlutterBuild) {
        Build-FlutterApp -Config $Configuration
    }

    # Build requested packages
    switch ($BuildType) {
        'msix' {
            Build-MSIX
        }
        'msi' {
            Build-MSI
        }
        'exe' {
            Build-EXE
        }
        'all' {
            Build-MSIX
            Build-MSI
            Build-EXE
        }
    }

    # Sign packages if requested
    if ($SignPackages -and $CertificatePath) {
        Write-Status '=== Signing Packages ==='

        $packages = @(
            (Join-Path $OutputDir 'msix\lemonade_nexus.msix'),
            (Join-Path $OutputDir 'msi\lemonade_nexus_setup.msi'),
            (Join-Path $OutputDir 'exe\lemonade_nexus.exe')
        )

        foreach ($package in $packages) {
            if (Test-Path $package) {
                Sign-Package -PackagePath $package
            }
        }
    }

    Write-Status '============================================'
    Write-Status 'Build Complete!'
    Write-Status "Output directory: $OutputDir"
    Write-Status '============================================'
}

# Run main function
Main
