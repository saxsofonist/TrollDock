param([switch]$IncludeTools)
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
foreach ($project in @('TrollDock.Transport.Tests', 'TrollDock.AppTests', 'TrollDock.CertificateTests', 'TrollDock.WorkflowTests', 'DebWorkflowTests', 'TrollDock.UiTests')) {
    dotnet run --project (Join-Path $root $project)
    if ($LASTEXITCODE -ne 0) { throw "$project failed." }
}
if ($IncludeTools) {
    python (Join-Path $root 'certificate-tools/download_tools.py')
    if ($LASTEXITCODE -ne 0) { throw 'Tool download or verification failed.' }
    python (Join-Path $root 'certificate-tools/make-test-ipa.py')
    if ($LASTEXITCODE -ne 0) { throw 'Synthetic fixture generation failed.' }
    dotnet run --project (Join-Path $root 'TrollDock.ToolTests')
    if ($LASTEXITCODE -ne 0) { throw 'TrollDock.ToolTests failed.' }
}
Write-Host 'All requested tests passed. No apps or packages were installed on a phone.'
