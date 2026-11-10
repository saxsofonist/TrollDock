param(
    [string]$Python = 'python',
    [string]$WorkDirectory = (Join-Path $PSScriptRoot '.build-zsign'),
    [string]$SourceArchive = '',
    [string]$MSBuild = '',
    [string]$Toolset = 'v145',
    [string]$VCToolsVersion = '14.50.35717',
    [string]$WindowsSdk = '10.0.26100.0'
)
$ErrorActionPreference = 'Stop'
$buildArguments = @((Join-Path $PSScriptRoot 'build-zsign.py'), '--work-directory', $WorkDirectory,
    '--toolset', $Toolset, '--vc-tools-version', $VCToolsVersion, '--windows-sdk', $WindowsSdk)
if ($SourceArchive) { $buildArguments += @('--source-archive', $SourceArchive) }
if ($MSBuild) { $buildArguments += @('--msbuild', $MSBuild) }
& $Python @buildArguments
if ($LASTEXITCODE -ne 0) { throw "zsign build failed with exit code $LASTEXITCODE" }
