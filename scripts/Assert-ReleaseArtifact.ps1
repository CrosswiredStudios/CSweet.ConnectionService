[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Directory,
    [Parameter(Mandatory)][string]$ExpectedVersion,
    [Parameter(Mandatory)][string]$SourceCommit
)
$ErrorActionPreference = 'Stop'
if ($ExpectedVersion -notmatch '^\d+\.\d+\.\d+$' -or $SourceCommit -notmatch '^[0-9a-f]{40}$') { throw 'Invalid release identity.' }
$packageId = 'CSweet.ConnectionService.Protocol'
$repository = 'https://github.com/CrosswiredStudios/CSweet.ConnectionService'
$packageName = "$packageId.$ExpectedVersion.nupkg"
$expectedFiles = @($packageName, "$ExpectedVersion.md", 'release-evidence.json', 'SHA256SUMS') | Sort-Object
$actualFiles = @(Get-ChildItem -LiteralPath $Directory -Force | ForEach-Object {
    if ($_.PSIsContainer -or $_.LinkType) { throw 'Release entries must be ordinary files.' }
    $_.Name
}) | Sort-Object
if (($expectedFiles -join '|') -cne ($actualFiles -join '|')) { throw 'Unexpected release artifact contents.' }
$hashed = @{}
foreach ($line in Get-Content -LiteralPath (Join-Path $Directory 'SHA256SUMS')) {
    $match = [regex]::Match($line, '^([0-9a-f]{64})  ([A-Za-z0-9._-]+)$')
    $name = $match.Groups[2].Value; $digest = $match.Groups[1].Value
    if (!$match.Success -or $hashed.ContainsKey($name)) { throw 'Invalid checksum manifest.' }
    if ($name -eq 'SHA256SUMS' -or $name -cnotin $expectedFiles) { throw 'Unexpected checksum target.' }
    if ((Get-FileHash -LiteralPath (Join-Path $Directory $name) -Algorithm SHA256).Hash.ToLowerInvariant() -cne $digest) { throw 'Release checksum mismatch.' }
    $hashed[$name] = $digest
}
if ($hashed.Count -ne $expectedFiles.Count - 1) { throw 'Incomplete checksum manifest.' }
$evidence = Get-Content -LiteralPath (Join-Path $Directory 'release-evidence.json') -Raw | ConvertFrom-Json
if ($evidence.packageId -cne $packageId -or $evidence.version -cne $ExpectedVersion -or
    $evidence.sourceCommit -cne $SourceCommit -or $evidence.sourceHasLocalChanges -isnot [bool] -or $evidence.sourceHasLocalChanges -or
    $evidence.packageSha256 -cne $hashed[$packageName]) { throw 'Release evidence does not match the reviewed source/package.' }
if ((Get-Content -LiteralPath (Join-Path $Directory "$ExpectedVersion.md") -First 1) -cnotmatch ('^# ' + [regex]::Escape($ExpectedVersion) + '($| - )')) { throw 'Incorrect release notes.' }
Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive = [System.IO.Compression.ZipFile]::OpenRead((Join-Path (Resolve-Path -LiteralPath $Directory).Path $packageName))
try {
    $reader = [System.IO.StreamReader]::new($archive.GetEntry("$packageId.nuspec").Open())
    try { $metadata = ([xml]$reader.ReadToEnd()).package.metadata } finally { $reader.Dispose() }
    if ($metadata.id -cne $packageId -or $metadata.version -cne $ExpectedVersion -or
        $metadata.repository.url -cne $repository -or $metadata.repository.commit -cne $SourceCommit) { throw 'Incorrect NuGet identity or source provenance.' }
} finally { $archive.Dispose() }
Write-Host "Verified immutable release: $packageId $ExpectedVersion at $SourceCommit; SHA256 $($hashed[$packageName])."
