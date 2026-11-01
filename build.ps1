<#
.SYNOPSIS
    Builds VEYL into dist\VEYL: native core (MSVC via CMake), launcher and app (.NET 8),
    runs the native tests, optionally code-signs, writes manifest.json and packs
    everything into a single dist\VEYL-Setup.exe.

.EXAMPLE
    .\build.ps1                 # release build
    .\build.ps1 -Sign           # also sign with a local self-signed certificate
    .\build.ps1 -UpdateUrl ""   # no update checks (the default checks GitHub Releases)
#>
param(
    [switch]$Sign,
    [string]$UpdateUrl = "https://github.com/Gurnski/VEYL/releases/latest/download/manifest.json",
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

Step "Native core, 32-bit sandbox monitor"
# Only Veyl.SandboxHook32.dll and a 32-bit test probe (see the Win32 branch in CMakeLists.txt).
& $cmake -S "$root\native" -B "$root\native\build32" -G "Visual Studio 17 2022" -A Win32 | Out-Null
if ($LASTEXITCODE) { throw "CMake configure (32-bit) failed" }
& $cmake --build "$root\native\build32" --config Release
if ($LASTEXITCODE) { throw "32-bit native build failed" }
# The sandbox tests and the 64-bit monitor look for the 32-bit files next to themselves.
Copy-Item "$root\native\build32\Release\Veyl.SandboxHook32.dll", "$root\native\build32\Release\Veyl.SandboxProbe32.exe" "$root\native\build\Release\" -Force

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

Copy-Item "$root\native\build\Release\Veyl.ShellMenu.dll" $dist

# Files the launcher verifies. The launcher can't meaningfully verify itself.
$verified = "Veyl.App.exe", "Veyl.App.dll", "Veyl.Shared.dll", "Veyl.Core.dll", "Veyl.SandboxHook.dll", "Veyl.SandboxHook32.dll", "Veyl.ShellMenu.dll"

[xml]$props = Get-Content "$root\src\Directory.Build.props"
$version = $props.Project.PropertyGroup.Version

# ---------------------------------------------------------------- certificate
# A self-signed certificate that lives only in this user's certificate store; its private key
# never leaves this PC. The Windows 11 menu package must be signed, so every build uses it.
# Setup trusts the public half (veyl-signing.cer) in the machine's TrustedPeople store only,
# which is what Windows checks for app packages. It is never added as a root certificate.
$subject = "CN=VEYL Local Code Signing"
$cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Where-Object { $_.Subject -eq $subject -and $_.HasPrivateKey } | Select-Object -First 1
if (-not $cert) {
    Step "Creating the signing certificate"
    # The extensions MSIX signing needs: code-signing usage, and "not a certificate authority".
    $cert = New-SelfSignedCertificate -Type Custom -Subject $subject -KeyUsage DigitalSignature -KeyAlgorithm RSA -KeyLength 3072 `
        -FriendlyName "VEYL local code signing" -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddYears(5) `
        -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.3", "2.5.29.19={text}")
    Write-Host "Created certificate $($cert.Thumbprint) in your personal certificate store."
    Write-Host "Back it up (certmgr.msc, export with the private key): later builds must use the same one."
}
Export-Certificate -Cert $cert -FilePath (Join-Path $dist "veyl-signing.cer") | Out-Null
$signtool = (Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" | Sort-Object FullName -Descending | Select-Object -First 1).FullName
$makeappx = (Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\makeappx.exe" | Sort-Object FullName -Descending | Select-Object -First 1).FullName
if (-not $signtool -or -not $makeappx) { throw "The Windows 10/11 SDK (signtool.exe, makeappx.exe) is required." }

# ---------------------------------------------------------------- Windows 11 menu package
Step "Windows 11 menu package"
$pkg = Join-Path $root "dist\menu-package"
if (Test-Path $pkg) { Remove-Item $pkg -Recurse -Force }
New-Item -ItemType Directory -Force "$pkg\Assets" | Out-Null
$xml = [IO.File]::ReadAllText("$root\packaging\menu\AppxManifest.xml").Replace('$PUBLISHER$', $subject).Replace('$VERSION$', "$version.0")
[IO.File]::WriteAllText("$pkg\AppxManifest.xml", $xml, (New-Object Text.UTF8Encoding $false))
# The package logo: the largest image in veyl.ico. Big icon images are stored as PNG already,
# so copy those bytes out; otherwise let System.Drawing convert the bitmap.
$ico = [IO.File]::ReadAllBytes("$root\assets\veyl.ico")
$best = $null
for ($i = 0; $i -lt [BitConverter]::ToUInt16($ico, 4); $i++) {
    $e = 6 + 16 * $i
    $w = if ($ico[$e] -eq 0) { 256 } else { $ico[$e] }
    if (-not $best -or $w -gt $best.W) { $best = @{ W = $w; Size = [BitConverter]::ToInt32($ico, $e + 8); Offset = [BitConverter]::ToInt32($ico, $e + 12) } }
}
$image = $ico[$best.Offset..($best.Offset + $best.Size - 1)]
if ($image[0] -eq 0x89 -and $image[1] -eq 0x50) {
    [IO.File]::WriteAllBytes("$pkg\Assets\logo.png", [byte[]]$image)
} else {
    Add-Type -AssemblyName System.Drawing
    $icon = New-Object System.Drawing.Icon("$root\assets\veyl.ico", $best.W, $best.W)
    $icon.ToBitmap().Save("$pkg\Assets\logo.png", [System.Drawing.Imaging.ImageFormat]::Png)
    $icon.Dispose()
}
$msix = Join-Path $dist "Veyl.Menu.msix"
& $makeappx pack /d $pkg /p $msix /nv /o | Out-Null
if ($LASTEXITCODE) { throw "makeappx failed" }
& $signtool sign /fd SHA256 /sha1 $cert.Thumbprint /q $msix
if ($LASTEXITCODE) { throw "Signing the menu package failed" }
Remove-Item $pkg -Recurse -Force

# ---------------------------------------------------------------- signing
if (-not $Sign) { $signtool = $null }  # the programs themselves are only signed with -Sign
if ($Sign) {
    Step "Signing"
    $targets = @("VEYL.exe", "VEYL.dll") + $verified | ForEach-Object { Join-Path $dist $_ }
    & $signtool sign /fd SHA256 /sha1 $cert.Thumbprint /q @targets
    if ($LASTEXITCODE) { throw "Signing failed" }
}

# ---------------------------------------------------------------- manifest
Step "Manifest"
$files = [ordered]@{}
foreach ($f in $verified) { $files[$f] = (Get-FileHash (Join-Path $dist $f) -Algorithm SHA256).Hash.ToLower() }
$manifest = [ordered]@{
    product        = "VEYL"
    version        = $version
    channel        = $Channel
    buildDate      = (Get-Date -Format "yyyy-MM-dd")
    updateUrl      = $UpdateUrl
    downloadUrl    = if ($UpdateUrl) { $UpdateUrl -replace "[^/]+$", "VEYL-Setup.exe" } else { "" }
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
