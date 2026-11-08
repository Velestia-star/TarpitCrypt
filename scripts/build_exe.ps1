param(
    [switch]$NoWebView2Bundle
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$buildDir = Join-Path $root "build"
New-Item -ItemType Directory -Force -Path $buildDir | Out-Null
$bootstrapper = Join-Path $buildDir "MicrosoftEdgeWebview2Setup.exe"

if (-not $NoWebView2Bundle -and -not (Test-Path $bootstrapper)) {
    Write-Host "Downloading WebView2 Evergreen Bootstrapper..."
    try {
        Invoke-WebRequest `
            -Uri "https://go.microsoft.com/fwlink/p/?LinkId=2124703" `
            -OutFile $bootstrapper `
            -UseBasicParsing
    } catch {
        Write-Warning "WebView2 bootstrapper download failed; building without it."
        if (Test-Path $bootstrapper) { Remove-Item $bootstrapper -Force }
    }
}

$pyinstallerArgs = @(
    "-m", "PyInstaller",
    "--noconfirm", "--clean",
    "--onefile",
    "--windowed",
    "--name", "TarpitCrypt",
    "--paths", "armor",
    "--hidden-import", "armor_core",
    "--hidden-import", "decoy_kit",
    "--hidden-import", "armor_metrics",
    "--add-data", "docs;docs",
    "desktop_web.py"
)

if (Test-Path $bootstrapper) {
    Write-Host "Bundling WebView2 bootstrapper into the exe."
    $pyinstallerArgs += @("--add-data", "$bootstrapper;.")
} else {
    Write-Host "No WebView2 bootstrapper bundled; missing runtime will show a download link."
}

# Some Python 3.15 + cryptography wheels use the free-threaded ABI shim
# python3t.dll. If the local Python ships one, include it so _rust.pyd loads
# in the frozen app as well.
$basePython = (& python -c "import sys; print(sys.base_prefix)").Trim()
$abi3tShim = Join-Path $basePython "abi3t-compat\python3t.dll"
if (Test-Path $abi3tShim) {
    Write-Host "Bundling abi3t compatibility shim: $abi3tShim"
    $pyinstallerArgs += @("--add-binary", "$abi3tShim;.")
}

Write-Host "Building single-file exe..."
python @pyinstallerArgs

if ($LASTEXITCODE -ne 0) {
    throw "PyInstaller build failed (exit $LASTEXITCODE)"
}

$exe = Join-Path $root "dist\TarpitCrypt.exe"
if (-not (Test-Path $exe)) {
    throw "Build finished but $exe was not found"
}

$size = [math]::Round((Get-Item $exe).Length / 1MB, 1)
Write-Host "Build complete: $exe ($size MB)"

# Copy non-empty top-level text guides (e.g. the Chinese tutorial) next to the exe.
Get-ChildItem -Path $root -Filter "*.txt" -File |
    Where-Object { $_.Length -gt 0 } |
    Copy-Item -Destination (Join-Path $root "dist") -Force
Write-Host "Copied text guides to dist."
