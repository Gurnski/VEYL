<#
.SYNOPSIS
    Builds VEYL and publishes it as a GitHub Release on Gurnski/VEYL, which is also
    VEYL's update server.

.DESCRIPTION
    Each release carries two files:
      VEYL-Setup.exe  the installer
      manifest.json   the build's manifest plus the installer's SHA-256 and size

    Installed copies fetch releases/latest/download/manifest.json at launch, and the app's
    "Download and install" fetches VEYL-Setup.exe and checks it against that SHA-256.
    The release is tagged v<Version> from src\Directory.Build.props, so bump the version
    there first. Needs the GitHub CLI signed in (gh auth login). The repository must be
    public for installed copies to see the release.

.EXAMPLE
    .\release.ps1                        # build, then publish v<version>
    .\release.ps1 -Sign                  # sign the build first
    .\release.ps1 -NotesFile notes.md    # release notes from a file (default: GitHub's generated notes)
    .\release.ps1 -SkipBuild             # publish the existing dist\ output
    .\release.ps1 -Replace               # re-upload the files to an existing release of this version
#>
param(
    [switch]$Sign,
    [switch]$SkipBuild,
    [switch]$Replace,
    [switch]$AllowDirty,
    [string]$NotesFile = ""
)

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
$repo = "Gurnski/VEYL"

function Step($text) { Write-Host "`n== $text" -ForegroundColor Yellow }

# Runs a native command for its exit code only. Windows PowerShell turns redirected stderr
# into a terminating error under $ErrorActionPreference = "Stop", so relax it for the call.
function Quiet([scriptblock]$cmd) {
    $old = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try { & $cmd *> $null; return $LASTEXITCODE } finally { $ErrorActionPreference = $old }
}

# ---------------------------------------------------------------- checks
$gh = Get-Command gh -ErrorAction SilentlyContinue
if (-not $gh) { $gh = Get-Item "$env:ProgramFiles\GitHub CLI\gh.exe" -ErrorAction SilentlyContinue }
if (-not $gh) { throw "The GitHub CLI isn't installed. Run: winget install GitHub.cli" }
if ($gh -is [System.Management.Automation.CommandInfo]) { $gh = $gh.Source } else { $gh = $gh.FullName }

if (Quiet { & $gh auth status }) { throw "The GitHub CLI isn't signed in. Run: gh auth login" }

[xml]$props = Get-Content "$root\src\Directory.Build.props"
$version = $props.Project.PropertyGroup.Version
$tag = "v$version"

git -C $root fetch --quiet origin
$dirty = git -C $root status --porcelain
if ($dirty -and -not $AllowDirty) { throw "There are uncommitted changes. Commit them first, or pass -AllowDirty." }
$head = git -C $root rev-parse HEAD
$remoteHead = git -C $root rev-parse origin/main
if ($head -ne $remoteHead) { throw "main isn't pushed (local $($head.Substring(0,7)), GitHub $($remoteHead.Substring(0,7))). Push first so the tag points at what you built." }

$exists = (Quiet { & $gh release view $tag --repo $repo }) -eq 0

if ($exists -and -not $Replace) { throw "Release $tag already exists. Bump <Version> in src\Directory.Build.props, or pass -Replace to overwrite its files." }

# ---------------------------------------------------------------- build
if (-not $SkipBuild) {
    Step "Building $version"
    & "$root\build.ps1" -Sign:$Sign
}

$setup = Join-Path $root "dist\VEYL-Setup.exe"
$built = Join-Path $root "dist\VEYL\manifest.json"
if (-not (Test-Path $setup) -or -not (Test-Path $built)) { throw "No build in dist\. Run without -SkipBuild." }

$manifest = Get-Content $built -Raw | ConvertFrom-Json
if ($manifest.version -ne $version) { throw "dist\ holds $($manifest.version), but the props say $version. Rebuild." }
if (-not $manifest.updateUrl) { throw "This build has no updateUrl, so installed copies would never see later releases. Rebuild without -UpdateUrl ''." }

# ---------------------------------------------------------------- release manifest
Step "Release manifest"
$manifest | Add-Member -NotePropertyName setupSha256 -NotePropertyValue (Get-FileHash $setup -Algorithm SHA256).Hash.ToLower() -Force
$manifest | Add-Member -NotePropertyName setupSize -NotePropertyValue (Get-Item $setup).Length -Force
$releaseDir = Join-Path $root "dist\release"
New-Item -ItemType Directory -Force $releaseDir | Out-Null
$releaseManifest = Join-Path $releaseDir "manifest.json"
$manifest | ConvertTo-Json -Depth 6 | Set-Content $releaseManifest -Encoding utf8
Write-Host "  setupSha256 $($manifest.setupSha256)"

# ---------------------------------------------------------------- publish
if ($exists) {
    Step "Replacing the files on $tag"
    & $gh release upload $tag $setup $releaseManifest --repo $repo --clobber
    if ($LASTEXITCODE) { throw "Upload failed" }
}
else {
    Step "Publishing $tag"
    # Not a draft or pre-release: releases/latest/download/ skips both, so installed copies wouldn't see it.
    [string[]]$ghArgs = @("release", "create", $tag, $setup, $releaseManifest, "--repo", $repo, "--target", $head, "--title", "VEYL $version", "--latest")
    if ($NotesFile) { $ghArgs += @("--notes-file", $NotesFile) } else { $ghArgs += "--generate-notes" }
    & $gh $ghArgs
    if ($LASTEXITCODE) { throw "Release failed" }
}

Write-Host "`nPublished VEYL $version" -ForegroundColor Green
Write-Host "  https://github.com/$repo/releases/tag/$tag"
