$ErrorActionPreference = "Stop"

# Resolve the directory this script lives in so the build works from any cwd
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$appDir = Join-Path $scriptDir "apps\LemonadeNexus"

if (-not (Test-Path $appDir)) {
    Write-Host "Flutter app directory not found at $appDir"
    exit 1
}

Push-Location $appDir
try {
    Write-Host "Fetching Flutter dependencies..."
    flutter pub get
    if ($LASTEXITCODE -ne 0) {
        Write-Host "flutter pub get failed with exit code $LASTEXITCODE"
        exit $LASTEXITCODE
    }

    Write-Host "Building Flutter Windows application..."
    flutter build windows --release
    if ($LASTEXITCODE -ne 0) {
        Write-Host "flutter build windows failed with exit code $LASTEXITCODE"
        exit $LASTEXITCODE
    }

    Write-Host "Build successful!"
}
finally {
    Pop-Location
}
