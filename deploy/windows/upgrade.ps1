[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Candidate,
    [string]$InstallRoot = "$env:ProgramData\JingShield"
)

$ErrorActionPreference = 'Stop'
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw '请以管理员身份运行 PowerShell。' }

$candidatePath = (Resolve-Path -LiteralPath $Candidate).Path
$exe = Join-Path $InstallRoot 'bin\jingshield.exe'
$next = Join-Path $InstallRoot 'bin\jingshield.next.exe'
$config = Join-Path $InstallRoot 'config.yaml'
$envFile = Join-Path $InstallRoot 'jingshield.env'
$pidFile = Join-Path $InstallRoot 'jingshield.pid'
$backup = Join-Path $InstallRoot ("bin\jingshield.backup.{0}.exe" -f (Get-Date -Format 'yyyyMMddHHmmss'))
$taskName = 'JingShield'
foreach ($required in @($candidatePath, $exe, $config, $envFile)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) { throw "缺少文件：$required" }
}

Get-Content -LiteralPath $envFile | ForEach-Object {
    if ($_ -match '^\s*([^#][^=]*)=(.*)$') { Set-Item -Path "Env:$($matches[1].Trim())" -Value $matches[2] }
}
Copy-Item -LiteralPath $candidatePath -Destination $next -Force
& $next help | Out-Null
if ($LASTEXITCODE -ne 0) { throw '候选二进制无法运行。' }
& $next migrate -c $config
if ($LASTEXITCODE -ne 0) { throw '候选版本数据库迁移失败。' }
Copy-Item -LiteralPath $exe -Destination $backup

Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1
if (Test-Path -LiteralPath $pidFile) {
    $processId = [int](Get-Content -LiteralPath $pidFile -Raw)
    $process = Get-Process -Id $processId -ErrorAction SilentlyContinue
    if ($process -and $process.Path -eq $exe) { Stop-Process -Id $processId -Force }
}

try {
    Move-Item -LiteralPath $next -Destination $exe -Force
    Start-ScheduledTask -TaskName $taskName
    Start-Sleep -Seconds 3
    $response = Invoke-WebRequest -Uri 'http://127.0.0.1:18080/admin/' -UseBasicParsing -TimeoutSec 10
    if ($response.StatusCode -ne 200) { throw "健康检查返回 HTTP $($response.StatusCode)" }
    Write-Host "升级成功；回滚文件：$backup" -ForegroundColor Green
} catch {
    Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    Copy-Item -LiteralPath $backup -Destination $exe -Force
    Start-ScheduledTask -TaskName $taskName
    throw "升级失败，已回滚：$($_.Exception.Message)"
}

