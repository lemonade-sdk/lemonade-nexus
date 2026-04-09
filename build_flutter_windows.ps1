$ErrorActionPreference = "Stop"

# Set Flutter path
$flutterPath = "C:\Users\antmi\AppData\Local\Flutter\flutter"
$env:Path = "$env:Path;$flutterPath\bin"
$env:FLUTTER_ROOT = $flutterPath

# Navigate to Flutter project
Set-Location "C:\Users\antmi\lemonade-nexus\apps\LemonadeNexus"

# Run Flutter build
Write-Host "Building Flutter Windows application..."
flutter build windows --release

if ($LASTEXITCODE -eq 0) {
    Write-Host "Build successful!"
} else {
    Write-Host "Build failed with exit code $LASTEXITCODE"
    exit $LASTEXITCODE
}
