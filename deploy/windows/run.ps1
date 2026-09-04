[CmdletBinding()]
param(
    [string]$InstallRoot = "$env:ProgramData\JingShield",
    [switch]$Initialize,
    [string]$Username
)

$ErrorActionPreference = 'Stop'
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw '请以管理员身份运行 PowerShell。'
}

$exe = Join-Path $InstallRoot 'bin\jingshield.exe'
$config = Join-Path $InstallRoot 'config.yaml'
$envFile = Join-Path $InstallRoot 'jingshield.env'
$wrapper = Join-Path $InstallRoot 'service-run.ps1'
foreach ($required in @($exe, $config, $envFile, $wrapper)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) { throw "缺少文件：$required" }
}

Get-Content -LiteralPath $envFile | ForEach-Object {
    if ($_ -match '^\s*([^#][^=]*)=(.*)$') { Set-Item -Path "Env:$($matches[1].Trim())" -Value $matches[2] }
}

$tlsDir = Join-Path $InstallRoot 'tls'
$cert = Join-Path $tlsDir 'jingshield.crt'
$key = Join-Path $tlsDir 'jingshield.key'
if (-not (Test-Path -LiteralPath $cert) -or -not (Test-Path -LiteralPath $key)) {
    New-Item -ItemType Directory -Path $tlsDir -Force | Out-Null
    $hosts = @('localhost', '127.0.0.1') + (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -ne '127.0.0.1' } | Select-Object -ExpandProperty IPAddress)
    & $exe cert --cert $cert --key $key --hosts ($hosts -join ',') --days 10950
    if ($LASTEXITCODE -ne 0) { throw '生成自签名证书失败。' }
}

& $exe migrate -c $config
if ($LASTEXITCODE -ne 0) { throw '数据库迁移失败。' }
if ($Initialize) {
    if (-not $Username) { $Username = Read-Host '请输入初始管理员用户名' }
    if ($Username -notmatch '^[A-Za-z0-9_.-]{3,50}$') { throw '管理员用户名格式无效。' }
    & $exe init -c $config --username $Username
    if ($LASTEXITCODE -ne 0) { throw '管理员初始化失败。' }
}

$taskName = 'JingShield'
if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
    Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
}
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$wrapper`" -InstallRoot `"$InstallRoot`""
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -RestartCount 5 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -StartWhenAvailable
$taskPrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Principal $taskPrincipal -Force | Out-Null
Start-ScheduledTask -TaskName $taskName
Start-Sleep -Seconds 2
$task = Get-ScheduledTask -TaskName $taskName
Write-Host "JingShield 已启动，计划任务状态：$($task.State)" -ForegroundColor Green
