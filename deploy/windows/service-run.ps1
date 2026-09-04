[CmdletBinding()]
param([string]$InstallRoot = "$env:ProgramData\JingShield")

$ErrorActionPreference = 'Stop'
$exe = Join-Path $InstallRoot 'bin\jingshield.exe'
$config = Join-Path $InstallRoot 'config.yaml'
$envFile = Join-Path $InstallRoot 'jingshield.env'
$pidFile = Join-Path $InstallRoot 'jingshield.pid'

Get-Content -LiteralPath $envFile | ForEach-Object {
    if ($_ -match '^\s*([^#][^=]*)=(.*)$') {
        [Environment]::SetEnvironmentVariable($matches[1].Trim(), $matches[2], 'Process')
    }
}

$process = Start-Process -FilePath $exe -ArgumentList @('serve', '-c', $config) -WorkingDirectory $InstallRoot -PassThru -NoNewWindow
Set-Content -LiteralPath $pidFile -Value $process.Id -Encoding ascii
try {
    $process.WaitForExit()
    exit $process.ExitCode
} finally {
    Remove-Item -LiteralPath $pidFile -Force -ErrorAction SilentlyContinue
}

