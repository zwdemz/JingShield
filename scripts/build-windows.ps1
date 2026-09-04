[CmdletBinding()]
param(
    [ValidateSet('amd64', 'arm64')][string]$Arch = 'amd64',
    [string]$Output = 'bin/jingshield-windows-amd64.exe',
    [switch]$SkipFrontendBuild,
    [switch]$SkipTests
)

$ErrorActionPreference = 'Stop'
$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$outputPath = [IO.Path]::GetFullPath((Join-Path $repoRoot $Output))

if (-not $SkipFrontendBuild) {
    Push-Location (Join-Path $repoRoot 'web')
    try {
        npm run build
        if ($LASTEXITCODE -ne 0) { throw 'Frontend build failed.' }
    } finally {
        Pop-Location
    }
}

if (-not $SkipTests) {
    Push-Location $repoRoot
    try {
        go test ./...
        if ($LASTEXITCODE -ne 0) { throw 'Go tests failed.' }
    } finally {
        Pop-Location
    }
}

$outputDirectory = Split-Path -Parent $outputPath
New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
$oldCgo, $oldGoos, $oldGoarch = $env:CGO_ENABLED, $env:GOOS, $env:GOARCH
try {
    $env:CGO_ENABLED = '0'
    $env:GOOS = 'windows'
    $env:GOARCH = $Arch
    Push-Location $repoRoot
    try {
        # The project entry is ./cmd/jingshield (there is no root main.go).
        go build -ldflags '-s -w -H=windowsgui' -trimpath -o $outputPath ./cmd/jingshield
        if ($LASTEXITCODE -ne 0) { throw 'Windows build failed.' }
    } finally {
        Pop-Location
    }
    [pscustomobject]@{
        Binary = $outputPath
        Architecture = $Arch
        SizeMB = [math]::Round((Get-Item -LiteralPath $outputPath).Length / 1MB, 2)
        SHA256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $outputPath).Hash.ToLowerInvariant()
        LinkerFlags = '-s -w -H=windowsgui'
    }
} finally {
    $env:CGO_ENABLED, $env:GOOS, $env:GOARCH = $oldCgo, $oldGoos, $oldGoarch
}
