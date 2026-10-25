$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root
$appVersion = (Get-Content -LiteralPath (Join-Path $root "VERSION") -Raw).Trim()

$candidateRoots = @(
    (Join-Path $root "src\WinUI3\bin"),
    (Join-Path $root "build")
)

Get-Process WindowsAppProtector.WinUI -ErrorAction SilentlyContinue | Where-Object {
    try {
        $processPath = $_.Path
        $candidateRoots | Where-Object {
            $processPath.StartsWith($_, [System.StringComparison]::OrdinalIgnoreCase)
        }
    }
    catch {
        $false
    }
} | Stop-Process -Force -ErrorAction SilentlyContinue

$payloadSource = Join-Path $root "build\publish-win-x64"
# Publish, rather than build output, includes both .NET and Windows App SDK runtimes.
if (Test-Path -LiteralPath $payloadSource) {
    $resolved = (Resolve-Path -LiteralPath $payloadSource).Path
    if ($resolved -ne (Join-Path $root "build\publish-win-x64")) { throw "Unexpected publish directory: $resolved" }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
& dotnet publish "$root\src\WinUI3\WindowsAppProtector.WinUI.csproj" -c Release -p:Platform=x64 -r win-x64 --self-contained true -o $payloadSource
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

foreach ($required in @("hostfxr.dll", "coreclr.dll", "Microsoft.UI.Xaml.dll")) {
    if (!(Test-Path -LiteralPath (Join-Path $payloadSource $required))) { throw "Missing app-local runtime: $required" }
}
$serviceSource = Join-Path $root "src\Service\WindowsAppProtector.Service.cs"
$serviceBuildDir = Join-Path $root "build\service"
$serviceExe = Join-Path $serviceBuildDir "WindowsAppProtector.Service.exe"
$buildDir = Join-Path $root "build\installer"
$payloadDir = Join-Path $buildDir "payload"
$distDir = Join-Path $root "dist\installer"
$setupSource = Join-Path $root "src\Installer\Setup.cs"
$manifest = Join-Path $root "src\Installer\app.manifest"
$icon = Join-Path $root "src\WinUI3\Assets\AppIcon.ico"
$setupExe = Join-Path $distDir "Setup.exe"
$versionedDistDir = Join-Path $root ("dist\releases\" + $appVersion)
$zipPath = Join-Path $buildDir "payload.zip"

foreach ($cleanupDir in @($buildDir, $distDir, $serviceBuildDir)) {
    if (Test-Path -LiteralPath $cleanupDir) {
        $resolved = (Resolve-Path -LiteralPath $cleanupDir).Path
        if (!$resolved.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase)) { throw "Unexpected cleanup directory: $resolved" }
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
New-Item -ItemType Directory -Path $serviceBuildDir | Out-Null
New-Item -ItemType Directory -Path $payloadDir | Out-Null
New-Item -ItemType Directory -Path $distDir | Out-Null

$csc = Join-Path $env:WINDIR "Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if (!(Test-Path $csc)) {
    throw "csc.exe not found: $csc"
}

& $csc /nologo /target:exe /optimize+ /reference:System.ServiceProcess.dll /reference:System.Runtime.Serialization.dll /out:$serviceExe $serviceSource
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

Copy-Item -Path (Join-Path $payloadSource "*") -Destination $payloadDir -Recurse -Force
Copy-Item -LiteralPath $serviceExe -Destination $payloadDir -Force
$payloadAssetsDir = Join-Path $payloadDir "Assets"
New-Item -ItemType Directory -Path $payloadAssetsDir -Force | Out-Null
Copy-Item -LiteralPath $icon -Destination (Join-Path $payloadAssetsDir "AppIcon.ico") -Force

& $csc /nologo /target:winexe /optimize+ /win32manifest:$manifest /win32icon:$icon /reference:System.IO.Compression.FileSystem.dll /out:$setupExe $setupSource
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

Add-Type -AssemblyName System.IO.Compression.FileSystem
if (Test-Path $zipPath) {
    Remove-Item -LiteralPath $zipPath -Force
}
[System.IO.Compression.ZipFile]::CreateFromDirectory($payloadDir, $zipPath, [System.IO.Compression.CompressionLevel]::Optimal, $false)

$zipBytes = [System.IO.File]::ReadAllBytes($zipPath)
$lengthBytes = [BitConverter]::GetBytes([Int64]$zipBytes.Length)
$markerBytes = [System.Text.Encoding]::ASCII.GetBytes("WAPZIP01")
$stream = [System.IO.File]::Open($setupExe, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write)
try {
    $stream.Write($zipBytes, 0, $zipBytes.Length)
    $stream.Write($lengthBytes, 0, $lengthBytes.Length)
    $stream.Write($markerBytes, 0, $markerBytes.Length)
}
finally {
    $stream.Dispose()
}

Write-Host "Created $setupExe"
New-Item -ItemType Directory -Path $versionedDistDir -Force | Out-Null
Copy-Item -LiteralPath $setupExe -Destination (Join-Path $versionedDistDir "Setup.exe") -Force
Write-Host "Preserved versioned installer at $(Join-Path $versionedDistDir 'Setup.exe')"
