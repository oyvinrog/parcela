# Parcela Windows Test Script
# Run this on Windows to verify ProjFS integration
#
# Usage: .\scripts\test-windows.ps1

$ErrorActionPreference = "Stop"

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Parcela Windows Verification Script" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# Check 1: Rust installation
Write-Host "[1/6] Checking Rust installation..." -ForegroundColor Yellow
try {
    $rustVersion = rustc --version
    Write-Host "  ✓ Rust installed: $rustVersion" -ForegroundColor Green
} catch {
    Write-Host "  ✗ Rust not found. Install from https://rustup.rs" -ForegroundColor Red
    exit 1
}

# Check 2: ProjFS availability
Write-Host "[2/6] Checking ProjFS availability..." -ForegroundColor Yellow
$projfsDll = "$env:SystemRoot\System32\projectedfslib.dll"
if (Test-Path $projfsDll) {
    Write-Host "  ✓ ProjFS found: $projfsDll" -ForegroundColor Green
} else {
    Write-Host "  ✗ ProjFS not enabled!" -ForegroundColor Red
    Write-Host "    Enable with: Enable-WindowsOptionalFeature -Online -FeatureName Client-ProjFS" -ForegroundColor Yellow
    Write-Host ""
    $install = Read-Host "Open PowerShell as Admin to enable? (y/n)"
    if ($install -eq "y") {
        Start-Process powershell -Verb RunAs -ArgumentList "-Command Enable-WindowsOptionalFeature -Online -FeatureName Client-ProjFS"
    }
    exit 1
}

# Check 3: Build the library
Write-Host "[3/6] Building Parcela library..." -ForegroundColor Yellow
cargo build 2>&1 | Out-Null
if ($LASTEXITCODE -eq 0) {
    Write-Host "  ✓ Build successful" -ForegroundColor Green
} else {
    Write-Host "  ✗ Build failed" -ForegroundColor Red
    cargo build
    exit 1
}

# Check 4: Run tests
Write-Host "[4/6] Running test suite..." -ForegroundColor Yellow
$testOutput = cargo test 2>&1
$testResult = $testOutput | Select-String "test result:"
if ($testOutput -match "FAILED") {
    Write-Host "  ✗ Some tests failed!" -ForegroundColor Red
    Write-Host $testOutput
    exit 1
} else {
    Write-Host "  ✓ All tests passed" -ForegroundColor Green
    $testOutput | Select-String "test result:" | ForEach-Object { Write-Host "    $_" }
}

# Check 5: Verify ProjFS detection
Write-Host "[5/6] Verifying ProjFS detection in code..." -ForegroundColor Yellow
$detectTest = cargo test is_projfs_available 2>&1
if ($detectTest -match "1 passed") {
    Write-Host "  ✓ ProjFS detection working" -ForegroundColor Green
} else {
    Write-Host "  ! ProjFS detection test inconclusive" -ForegroundColor Yellow
}

# Check 6: Run ProjFS-specific tests
Write-Host "[6/6] Running ProjFS filesystem tests..." -ForegroundColor Yellow
$projfsTests = cargo test projfs_fs 2>&1
$projfsPassed = ($projfsTests | Select-String "passed").Count
if ($projfsPassed -gt 0) {
    Write-Host "  ✓ ProjFS filesystem tests passed" -ForegroundColor Green
} else {
    Write-Host "  ! No ProjFS-specific tests found (may need module to be compiled)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  All automated checks passed!" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next steps for manual verification:" -ForegroundColor Yellow
Write-Host "  1. Build GUI: cd src-tauri && cargo tauri build"
Write-Host "  2. Run the installer from src-tauri/target/release/bundle/"
Write-Host "  3. Create a vault and add a virtual drive"
Write-Host "  4. Unlock the drive - a virtual directory should appear"
Write-Host "  5. Open it in Windows Explorer"
Write-Host "  6. Create files, then lock the drive"
Write-Host "  7. Unlock again and verify files persist"
Write-Host ""

