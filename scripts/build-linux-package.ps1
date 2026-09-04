[CmdletBinding()]
param(
    [string]$Version,
    [ValidateSet('amd64', 'arm64')][string]$Arch = 'amd64',
    [string]$OutputDirectory = 'release',
    [ValidateSet('Auto', 'Direct', 'China')][string]$NetworkProfile = 'Auto',
    [switch]$SkipFrontendBuild,
    [switch]$SkipTests
)

$ErrorActionPreference = 'Stop'
$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$outputRoot = [IO.Path]::GetFullPath((Join-Path $repoRoot $OutputDirectory))
if (-not $Version) {
    $packageJson = Get-Content -Raw (Join-Path $repoRoot 'web/package.json') | ConvertFrom-Json
    $Version = [string]$packageJson.version
}
if ($Version -notmatch '^[0-9A-Za-z][0-9A-Za-z._-]{0,63}$') {
    throw 'Version may contain only letters, digits, dots, underscores, and hyphens.'
}

foreach ($command in @('go', 'tar')) {
    if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
        throw "Required command is unavailable: $command"
    }
}
if (-not $SkipFrontendBuild -and -not (Get-Command npm -ErrorAction SilentlyContinue)) {
    throw 'npm is required unless -SkipFrontendBuild is specified.'
}

$packageName = "jingshield-$Version-linux-$Arch"
$stageRoot = Join-Path $outputRoot ('.stage-' + [guid]::NewGuid().ToString('N'))
$bundleRoot = Join-Path $stageRoot $packageName
$archive = Join-Path $outputRoot "$packageName.tar.gz"
$checksum = "$archive.sha256"

New-Item -ItemType Directory -Path $outputRoot -Force | Out-Null
New-Item -ItemType Directory -Path $bundleRoot -Force | Out-Null

$oldCgo = $env:CGO_ENABLED
$oldGoos = $env:GOOS
$oldGoarch = $env:GOARCH
$oldGoProxy = $env:GOPROXY
try {
    if ($NetworkProfile -eq 'Auto') {
        $candidates = @(
            @{ Name = 'Direct'; Uri = 'https://proxy.golang.org/golang.org/x/text/@v/list'; Proxy = 'https://proxy.golang.org,direct' },
            @{ Name = 'China'; Uri = 'https://goproxy.cn/golang.org/x/text/@v/list'; Proxy = 'https://goproxy.cn,direct' }
        )
        $reachable = foreach ($candidate in $candidates) {
            $timer = [Diagnostics.Stopwatch]::StartNew()
            try {
                Invoke-WebRequest -Uri $candidate.Uri -Method Head -TimeoutSec 4 -UseBasicParsing | Out-Null
                $timer.Stop()
                [pscustomobject]@{ Milliseconds = $timer.ElapsedMilliseconds; Candidate = $candidate }
            } catch {}
        }
        if ($reachable) {
            $selected = ($reachable | Sort-Object Milliseconds | Select-Object -First 1).Candidate
            $env:GOPROXY = $selected.Proxy
            Write-Host "Go module network: $($selected.Name) ($($selected.Proxy))" -ForegroundColor DarkGray
        } else {
            $env:GOPROXY = 'https://proxy.golang.org,direct'
            Write-Host 'Go proxy probes failed; using the official proxy with direct fallback.' -ForegroundColor Yellow
        }
    } elseif ($NetworkProfile -eq 'China') {
        $env:GOPROXY = 'https://goproxy.cn,direct'
    } else {
        $env:GOPROXY = 'https://proxy.golang.org,direct'
    }

    if (-not $SkipFrontendBuild) {
        Push-Location (Join-Path $repoRoot 'web')
        try {
            if (-not (Test-Path 'node_modules')) { npm ci }
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

    $payloadDir = Join-Path $bundleRoot 'payload'
    $configDir = Join-Path $bundleRoot 'config'
    $systemdDir = Join-Path $bundleRoot 'systemd'
    New-Item -ItemType Directory -Path $payloadDir, $configDir, $systemdDir -Force | Out-Null

    $env:CGO_ENABLED = '0'
    $env:GOOS = 'linux'
    $env:GOARCH = $Arch
    Push-Location $repoRoot
    try {
        go build -trimpath -ldflags '-s -w' -o (Join-Path $payloadDir 'jingshield') ./cmd/jingshield
        if ($LASTEXITCODE -ne 0) { throw 'Linux binary build failed.' }
    } finally {
        Pop-Location
    }

    Copy-Item (Join-Path $repoRoot 'run.sh') (Join-Path $bundleRoot 'run.sh')
    Copy-Item (Join-Path $repoRoot 'upgrade.sh') (Join-Path $bundleRoot 'upgrade.sh')
    Copy-Item (Join-Path $repoRoot 'deploy/linux/config.yaml') (Join-Path $configDir 'config.yaml')
    Copy-Item (Join-Path $repoRoot 'deploy/linux/jingshield.service') (Join-Path $systemdDir 'jingshield.service')
    Copy-Item (Join-Path $repoRoot 'rules') (Join-Path $bundleRoot 'rules') -Recurse
    [IO.File]::WriteAllText((Join-Path $bundleRoot 'VERSION'), "$Version`n", [Text.UTF8Encoding]::new($false))

    $manifestLines = Get-ChildItem -Path $bundleRoot -Recurse -File |
        Where-Object Name -ne 'SHA256SUMS' |
        Sort-Object FullName |
        ForEach-Object {
            $relative = [IO.Path]::GetRelativePath($bundleRoot, $_.FullName).Replace('\', '/')
            $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash.ToLowerInvariant()
            "$hash  $relative"
        }
    [IO.File]::WriteAllLines((Join-Path $bundleRoot 'SHA256SUMS'), $manifestLines, [Text.UTF8Encoding]::new($false))

    if (Test-Path $archive) { Remove-Item -LiteralPath $archive -Force }
    if (Test-Path $checksum) { Remove-Item -LiteralPath $checksum -Force }
    tar -czf $archive -C $stageRoot $packageName
    if ($LASTEXITCODE -ne 0) { throw 'Package archive creation failed.' }

    $archiveHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash.ToLowerInvariant()
    [IO.File]::WriteAllText($checksum, "$archiveHash  $([IO.Path]::GetFileName($archive))`n", [Text.UTF8Encoding]::new($false))
    [pscustomobject]@{
        Package = $archive
        Checksum = $checksum
        Version = $Version
        Architecture = $Arch
        GoProxy = $env:GOPROXY
        SizeMB = [math]::Round((Get-Item $archive).Length / 1MB, 2)
    }
} finally {
    $env:CGO_ENABLED = $oldCgo
    $env:GOOS = $oldGoos
    $env:GOARCH = $oldGoarch
    $env:GOPROXY = $oldGoProxy
    if (Test-Path $stageRoot) {
        $resolvedStage = [IO.Path]::GetFullPath($stageRoot)
        if ($resolvedStage.StartsWith($outputRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
            Remove-Item -LiteralPath $resolvedStage -Recurse -Force
        }
    }
}
