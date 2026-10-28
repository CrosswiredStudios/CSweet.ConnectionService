[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true
$repoRoot = Split-Path $PSScriptRoot -Parent
Push-Location $repoRoot
try {
    dotnet restore CSweet.ConnectionService.slnx --configfile NuGet.Config
    dotnet test CSweet.ConnectionService.slnx -c Release --no-restore --logger 'trx;LogFileName=managed-connections.trx' --results-directory artifacts/test-results
    dotnet pack src/CSweet.ConnectionService.Protocol -c Release --no-build --no-restore -o artifacts/packages
    $props = [xml](Get-Content Directory.Build.props -Raw)
    $version = [string]$props.Project.PropertyGroup.Version
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $path = Join-Path $repoRoot "artifacts/packages/CSweet.ConnectionService.Protocol.$version.nupkg"
    $archive = [System.IO.Compression.ZipFile]::OpenRead($path)
    try {
        $entry = $archive.GetEntry('CSweet.ConnectionService.Protocol.nuspec')
        if (!$entry) { throw 'Missing protocol package metadata.' }
        $reader = [System.IO.StreamReader]::new($entry.Open())
        try { $metadata = [xml]$reader.ReadToEnd() } finally { $reader.Dispose() }
        $package = $metadata.SelectSingleNode("/*[local-name()='package']/*[local-name()='metadata']")
        if ($package.id -ne 'CSweet.ConnectionService.Protocol' -or $package.version -ne $version) { throw 'Incorrect protocol package identity.' }
        if ($package.license.type -ne 'expression' -or $package.license.InnerText -ne 'MIT' -or !$archive.GetEntry('LICENSE')) { throw 'Missing MIT package licensing.' }
        if (!$archive.GetEntry('lib/net10.0/CSweet.ConnectionService.Protocol.dll') -or !$archive.GetEntry('README.md')) { throw 'Missing protocol assembly/readme.' }
    } finally { $archive.Dispose() }
    $cache = Join-Path $repoRoot ('artifacts/consumer-packages/' + [Guid]::NewGuid().ToString('N'))
    dotnet restore tests/ProtocolConsumer/ProtocolConsumer.csproj --configfile tests/ProtocolConsumer/NuGet.Config --packages $cache --force --no-http-cache
    dotnet run --project tests/ProtocolConsumer -c Release --no-restore "-p:RestorePackagesPath=$cache"
    Write-Host "Verified local protocol package $version. Nothing was published or deployed."
} finally { Pop-Location }
