# Unsigned x64 MSI only. WiX .NET tool usage:
# https://docs.firegiant.com/wix/using-wix/#command-line-net-tool
# Install explicitly: dotnet tool install --global wix --version 5.0.2
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Binary,
    [Parameter(Mandatory = $true)][string]$Version,
    [Parameter(Mandatory = $true)][string]$Output
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$wixVersion = '5.0.2' # https://www.nuget.org/packages/wix/5.0.2
if ($env:OS -ne 'Windows_NT') { throw 'MSI build requires Windows and WiX v5.0.2' }
# Windows Installer ProductVersion: three fields, major/minor <=255, build <=65535.
# https://learn.microsoft.com/en-us/windows/win32/msi/productversion
if ($Version -notmatch '^\d+\.\d+\.\d+$') { throw 'Version must have three numeric fields' }
$parts = $Version.Split('.')
if ([uint64]$parts[0] -gt 255 -or [uint64]$parts[1] -gt 255 -or [uint64]$parts[2] -gt 65535) {
    throw 'Version exceeds Windows Installer ProductVersion limits'
}
$binaryItem = Get-Item -LiteralPath $Binary
if ($binaryItem.PSIsContainer -or ($binaryItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Binary must be a regular file' }
$Binary = $binaryItem.FullName
$Output = [IO.Path]::GetFullPath($Output)
if ([IO.Path]::GetExtension($Output) -ne '.msi' -or (Test-Path -LiteralPath $Output)) { throw 'Output must be a new .msi path' }
# Refuse an accidentally cross-built payload before authoring a 64-bit service.
# https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
$stream = [IO.File]::OpenRead($Binary)
$reader = New-Object IO.BinaryReader($stream)
try {
    if ($reader.ReadUInt16() -ne 0x5a4d) { throw 'Payload is not a PE executable' }
    $stream.Position = 0x3c
    $peOffset = $reader.ReadUInt32()
    if ($peOffset -gt $stream.Length - 6) { throw 'Invalid PE header offset' }
    $stream.Position = $peOffset
    if ($reader.ReadUInt32() -ne 0x00004550 -or $reader.ReadUInt16() -ne 0x8664) { throw 'Payload must be Windows x64 (AMD64)' }
} finally { $reader.Dispose() }
$actual = & wix --version
if ($LASTEXITCODE -ne 0 -or ($actual -split '\+')[0].Trim() -ne $wixVersion) { throw "Requires pinned WiX $wixVersion" }
$parent = Split-Path -Parent $Output
[void](New-Item -ItemType Directory -Path $parent -Force)
$work = Join-Path $parent ('.msi-build-' + [guid]::NewGuid())
[void](New-Item -ItemType Directory -Path $work)
try {
    $before = (Get-FileHash -LiteralPath $Binary -Algorithm SHA256).Hash
    $payload = Join-Path $work 'aegishook.exe'
    Copy-Item -LiteralPath $Binary -Destination $payload
    if ((Get-FileHash -LiteralPath $payload -Algorithm SHA256).Hash -ne $before) { throw 'STOP: payload changed during staging' }
    & wix build (Join-Path $PSScriptRoot 'Product.wxs') -arch x64 -d "Version=$Version" -d "Payload=$payload" -intermediateFolder (Join-Path $work 'obj') -o (Join-Path $work 'endpoint.msi')
    if ($LASTEXITCODE -ne 0) { throw "WiX build failed: $LASTEXITCODE" }
    if ((Get-FileHash -LiteralPath $Binary -Algorithm SHA256).Hash -ne $before) { throw 'STOP: input binary changed during build' }
    Move-Item -LiteralPath (Join-Path $work 'endpoint.msi') -Destination $Output
    Write-Output "UNSIGNED MSI: $Output"
    Get-FileHash -LiteralPath $Output -Algorithm SHA256
} finally { Remove-Item -LiteralPath $work -Recurse -Force }
# S6 signs only after the owner resolves the signing purchase. No certificate,
# credential, signtool or keychain access belongs in this unsigned S4 path.
