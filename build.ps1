<#
.SYNOPSIS
    Builds VEYL into dist\VEYL: native core (MSVC via CMake), launcher and app (.NET 8),
    runs the native tests, optionally code-signs, writes manifest.json and packs
    everything into a single dist\VEYL-Setup.exe.

.EXAMPLE
    .\build.ps1                 # release build
    .\build.ps1 -Sign           # also sign with a local self-signed certificate
    .\build.ps1 -UpdateUrl https://example.com/veyl/manifest.json
#>
param(
    [switch]$Sign,
    [string]$UpdateUrl = "",
    [string]$Channel = "stable"
)

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
$dist = Join-Path $root "dist\VEYL"

function Step($text) { Write-Host "`n== $text" -ForegroundColor Yellow }

# ---------------------------------------------------------------- toolchain
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vs = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vs) { throw "Visual Studio with the C++ workload is required." }
$cmake = Join-Path $vs "Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
if (-not (Test-Path $cmake)) { $cmake = "cmake" }

# ---------------------------------------------------------------- native
Step "Native core"
& $cmake -S "$root\native" -B "$root\native\build" -G "Visual Studio 17 2022" -A x64 | Out-Null
if ($LASTEXITCODE) { throw "CMake configure failed" }
& $cmake --build "$root\native\build" --config Release
if ($LASTEXITCODE) { throw "Native build failed" }

Step "Native tests"
& "$root\native\build\Release\Veyl.Core.Tests.exe"
if ($LASTEXITCODE) { throw "Native tests failed" }
& "$root\native\build\Release\Veyl.Sandbox.Tests.exe"
if ($LASTEXITCODE) { throw "Sandbox tests failed" }


# ---------------------------------------------------------------- managed
Step "Publishing launcher and app"
if (Test-Path $dist) { Remove-Item $dist -Recurse -Force }
# Self-contained: the .NET runtime ships inside VEYL, so nothing needs installing first.
foreach ($proj in "src\Veyl.Launcher\Veyl.Launcher.csproj", "src\Veyl.App\Veyl.App.csproj") {
    dotnet publish "$root\$proj" -c Release -o $dist --nologo -v q -r win-x64 --self-contained true -p:DebugType=none
    if ($LASTEXITCODE) { throw "Publish failed: $proj" }
}

# Files the launcher verifies. The launcher can't meaningfully verify itself.
$verified = "Veyl.App.exe", "Veyl.App.dll", "Veyl.Shared.dll", "Veyl.Core.dll", "Veyl.SandboxHook.dll"

# ---------------------------------------------------------------- signing
$signtool = $null
if ($Sign) {
    Step "Signing"
    $subject = "CN=VEYL Local Code Signing"
    $cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Where-Object Subject -eq $subject | Select-Object -First 1
    if (-not $cert) {
        $cert = New-SelfSignedCertificate -Subject $subject -Type CodeSigningCert -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddYears(5)
        Write-Host "Created certificate $($cert.Thumbprint). Install with VEYL-Setup.exe --trust-cert to trust it."
    }
    Export-Certificate -Cert $cert -FilePath (Join-Path $dist "veyl-signing.cer") | Out-Null
    $signtool = (Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" | Sort-Object FullName -Descending | Select-Object -First 1).FullName
    $targets = @("VEYL.exe", "VEYL.dll") + $verified | ForEach-Object { Join-Path $dist $_ }
    & $signtool sign /fd SHA256 /sha1 $cert.Thumbprint /q @targets
    if ($LASTEXITCODE) { throw "Signing failed" }
}

# ---------------------------------------------------------------- manifest
Step "Manifest"
[xml]$props = Get-Content "$root\src\Directory.Build.props"
$version = $props.Project.PropertyGroup.Version
$files = [ordered]@{}
foreach ($f in $verified) { $files[$f] = (Get-FileHash (Join-Path $dist $f) -Algorithm SHA256).Hash.ToLower() }
$manifest = [ordered]@{
    product        = "VEYL"
    version        = $version
    channel        = $Channel
    buildDate      = (Get-Date -Format "yyyy-MM-dd")
    updateUrl      = $UpdateUrl
    downloadUrl    = ""
    files          = $files
    signatureFeeds = @()
}
$manifest | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $dist "manifest.json") -Encoding utf8

# ---------------------------------------------------------------- setup
Step "Packing VEYL-Setup.exe"
$payload = "$root\src\Veyl.Setup\payload.zip"
if (Test-Path $payload) { Remove-Item $payload }
Add-Type -AssemblyName System.IO.Compression.FileSystem
[IO.Compression.ZipFile]::CreateFromDirectory($dist, $payload, [IO.Compression.CompressionLevel]::Optimal, $false)
$setupOut = Join-Path $root "dist\setup"
dotnet publish "$root\src\Veyl.Setup\Veyl.Setup.csproj" -c Release -o $setupOut --nologo -v q -r win-x64 --self-contained true `
    -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:EnableCompressionInSingleFile=true -p:DebugType=none
if ($LASTEXITCODE) { throw "Setup publish failed" }
$setupExe = Join-Path $root "dist\VEYL-Setup.exe"
Move-Item (Join-Path $setupOut "VEYL-Setup.exe") $setupExe -Force
Remove-Item $setupOut -Recurse -Force
Remove-Item $payload
if ($signtool) {
    & $signtool sign /fd SHA256 /sha1 $cert.Thumbprint /q $setupExe
    if ($LASTEXITCODE) { throw "Signing setup failed" }
}

$sizeMb = [math]::Round((Get-Item $setupExe).Length / 1MB, 1)
Write-Host "`nBuilt VEYL $version" -ForegroundColor Green
Write-Host "  Installer: $setupExe ($sizeMb MB)"
Write-Host "  Unpacked build: $dist"
