[CmdletBinding()]
param(
    [ValidateSet('Auto', 'Direct', 'China')][string]$NetworkProfile = 'Auto',
    [string]$EnvironmentDirectory = '.venv',
    [switch]$Recreate
)

$ErrorActionPreference = 'Stop'
$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$venvRoot = [IO.Path]::GetFullPath((Join-Path $repoRoot $EnvironmentDirectory))
if (-not $venvRoot.StartsWith($repoRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'The Python virtual environment must be located inside the repository.'
}

$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) { throw 'Python 3 is required.' }
$versionText = & $python.Source --version 2>&1
if ($LASTEXITCODE -ne 0 -or $versionText -notmatch 'Python 3\.') { throw 'Python 3 is required.' }

if ($Recreate -and (Test-Path $venvRoot)) {
    Remove-Item -LiteralPath $venvRoot -Recurse -Force
}
if (-not (Test-Path $venvRoot)) {
    & $python.Source -m venv $venvRoot
    if ($LASTEXITCODE -ne 0) { throw 'Failed to create the Python virtual environment.' }
}

$venvPython = if ($IsWindows -or $env:OS -eq 'Windows_NT') {
    Join-Path $venvRoot 'Scripts/python.exe'
} else {
    Join-Path $venvRoot 'bin/python'
}
if (-not (Test-Path -LiteralPath $venvPython -PathType Leaf)) {
    throw "Virtual-environment Python was not found: $venvPython"
}

$indexes = @(
    @{ Name = 'Direct'; Uri = 'https://pypi.org/simple/pip/'; Index = 'https://pypi.org/simple' },
    @{ Name = 'China'; Uri = 'https://pypi.tuna.tsinghua.edu.cn/simple/pip/'; Index = 'https://pypi.tuna.tsinghua.edu.cn/simple' }
)
if ($NetworkProfile -eq 'Auto') {
    $reachable = foreach ($candidate in $indexes) {
        $timer = [Diagnostics.Stopwatch]::StartNew()
        try {
            Invoke-WebRequest -Uri $candidate.Uri -Method Head -TimeoutSec 4 -UseBasicParsing | Out-Null
            $timer.Stop()
            [pscustomobject]@{ Milliseconds = $timer.ElapsedMilliseconds; Candidate = $candidate }
        } catch {}
    }
    if ($reachable) {
        $selected = ($reachable | Sort-Object Milliseconds | Select-Object -First 1).Candidate
    } else {
        $selected = $indexes[0]
        Write-Host 'PyPI probes failed; using the official index.' -ForegroundColor Yellow
    }
} elseif ($NetworkProfile -eq 'China') {
    $selected = $indexes[1]
} else {
    $selected = $indexes[0]
}

Write-Host "Python package network: $($selected.Name) ($($selected.Index))" -ForegroundColor DarkGray
& $venvPython -m pip install --disable-pip-version-check --index-url $selected.Index --upgrade pip
if ($LASTEXITCODE -ne 0) { throw 'pip upgrade failed.' }
& $venvPython -m pip install --disable-pip-version-check --index-url $selected.Index -r (Join-Path $repoRoot 'deploy/requirements-deploy.txt')
if ($LASTEXITCODE -ne 0) { throw 'Deployment dependencies failed to install.' }

[pscustomobject]@{
    Python = $venvPython
    Index = $selected.Index
    Version = (& $venvPython --version 2>&1)
}
