param([ValidatePattern('^[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?$')][string]$Version = '1.1.1')
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath($PSScriptRoot)
$buildBase = [IO.Path]::GetFullPath((Join-Path $root '.build'))
$buildRunRoot = Join-Path $buildBase ([Guid]::NewGuid().ToString('N'))
$destination = Join-Path $buildRunRoot 'TrollDock'
$toolDestination = Join-Path $destination 'tools'
$artifacts = Join-Path $root 'artifacts'
$zipPath = Join-Path $artifacts "TrollDock-$Version-win-x64.zip"
New-Item -ItemType Directory -Force -Path $destination, $artifacts | Out-Null
try {
    # A fresh output directory prevents saved data from a previous run entering a release.
    dotnet publish (Join-Path $root 'TrollDock/TrollDock.csproj') -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:EnableCompressionInSingleFile=true -p:Version=$Version -o $destination
    if ($LASTEXITCODE -ne 0) { throw 'Build failed.' }
    python (Join-Path $root 'certificate-tools/download_tools.py') --output $toolDestination
    if ($LASTEXITCODE -ne 0) { throw 'Tool download or verification failed.' }
    foreach ($file in @('README.md', 'LICENSE', 'THIRD_PARTY_NOTICES.txt')) {
        Copy-Item -LiteralPath (Join-Path $root $file) -Destination $destination
    }
    Copy-Item -LiteralPath (Join-Path $root 'docs') -Destination (Join-Path $destination 'docs') -Recurse -Force
    Copy-Item -LiteralPath (Join-Path $root 'certificate-tools/licenses') -Destination (Join-Path $toolDestination 'licenses') -Recurse -Force
    Copy-Item -LiteralPath (Join-Path $root 'certificate-tools/manifest.json') -Destination (Join-Path $toolDestination 'manifest.json')
    $unexpected = @(Get-ChildItem -LiteralPath $destination -Recurse -File | Where-Object { $_.Extension -match '^\.(ipa|deb|p12|pfx|mobileprovision|tdcert|log)$' -or $_.FullName -match '[\\/]data[\\/]' })
    if ($unexpected.Count) { throw 'Refusing to package private data or application fixtures.' }
    Compress-Archive -Path (Join-Path $destination '*') -DestinationPath $zipPath -Force
    $hash = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
    [IO.File]::WriteAllText((Join-Path $artifacts 'SHA256SUMS.txt'), "$hash  $([IO.Path]::GetFileName($zipPath))`n", [Text.UTF8Encoding]::new($false))
    Write-Host "Ready: $zipPath"
}
finally {
    $resolvedRunRoot = [IO.Path]::GetFullPath($buildRunRoot)
    if ($resolvedRunRoot.StartsWith($buildBase + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase) -and [IO.Path]::GetFileName($resolvedRunRoot) -match '^[0-9a-f]{32}$' -and (Test-Path -LiteralPath $resolvedRunRoot)) {
        Remove-Item -LiteralPath $resolvedRunRoot -Recurse -Force
    }
}
