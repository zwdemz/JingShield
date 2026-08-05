[CmdletBinding()]
param(
    [string]$BaseUrl = 'http://127.0.0.1:18080',
    [string]$HostHeader = '127.0.0.1',
    [int]$SettleSeconds = 11,
    [switch]$SkipCertificateCheck
)

$ErrorActionPreference = 'Stop'

if ($PSVersionTable.PSVersion.Major -lt 7) {
    throw '该脚本需要 PowerShell 7 或更高版本。'
}

$base = $BaseUrl.TrimEnd('/')
$browserHeaders = @{
    'Host'                      = $HostHeader
    'User-Agent'                = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36'
    'Accept'                    = 'text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8'
    'Accept-Language'           = 'zh-CN,zh;q=0.9,en;q=0.8'
    'Accept-Encoding'           = 'identity'
    'Upgrade-Insecure-Requests' = '1'
}
$webSession = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$tlsOptions = @{}
if ($SkipCertificateCheck) { $tlsOptions['SkipCertificateCheck'] = $true }

function Test-ZeroBits {
    param([byte[]]$Hash, [int]$Bits)
    $fullBytes = [math]::Floor($Bits / 8)
    for ($index = 0; $index -lt $fullBytes; $index++) {
        if ($Hash[$index] -ne 0) { return $false }
    }
    $remaining = $Bits % 8
    if ($remaining -eq 0) { return $true }
    $mask = (0xff -shl (8 - $remaining)) -band 0xff
    return (($Hash[$fullBytes] -band $mask) -eq 0)
}

function Complete-WAFChallenge {
    param([string]$Html)
    $token = [regex]::Match($Html, 'data-token="([^"]+)"').Groups[1].Value
    $action = [regex]::Match($Html, 'data-action="([^"]+)"').Groups[1].Value
    $wait = [int][regex]::Match($Html, 'data-wait="(\d+)"').Groups[1].Value
    $difficulty = [int][regex]::Match($Html, 'data-difficulty="(\d+)"').Groups[1].Value
    if (-not $token -or -not $action -or $difficulty -le 0) {
        throw '无法解析 WAF 验证挑战。'
    }
    Write-Host "收到安全挑战，等待 $wait 秒并计算 PoW……" -ForegroundColor DarkGray
    if ($wait -gt 0) { Start-Sleep -Seconds $wait }
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        for ($proof = 0; ; $proof++) {
            $inputBytes = [Text.Encoding]::UTF8.GetBytes("$token|$proof")
            if (Test-ZeroBits -Hash ($sha256.ComputeHash($inputBytes)) -Bits $difficulty) { break }
        }
    } finally {
        $sha256.Dispose()
    }
    $verifyHeaders = $browserHeaders.Clone()
    $verifyHeaders['Accept'] = 'application/json'
    $response = Invoke-WebRequest -Uri "$base/cc/verify" -Method Post -Headers $verifyHeaders -WebSession $webSession `
        -ContentType 'application/x-www-form-urlencoded' -Body @{ action = $action; token = $token; proof = [string]$proof } `
        -UseBasicParsing -SkipHttpErrorCheck -TimeoutSec 30 @tlsOptions
    if ($response.StatusCode -ne 200) {
        throw "WAF 验证失败：HTTP $($response.StatusCode) $($response.Content)"
    }
}

function Invoke-WAFRequest {
    param([string]$Name, [string]$Uri, [hashtable]$Headers = $browserHeaders)
    $response = Invoke-WebRequest -Uri $Uri -Headers $Headers -WebSession $webSession -UseBasicParsing -SkipHttpErrorCheck -TimeoutSec 15 @tlsOptions
    $code = $null
    $message = $null
    try {
        $json = $response.Content | ConvertFrom-Json
        $code = $json.code
        $message = $json.message
    } catch {
        $title = [regex]::Match($response.Content, '<title>(.*?)</title>').Groups[1].Value
        if ($title) { $message = $title }
    }
    [pscustomobject]@{ Test = $Name; HTTP = [int]$response.StatusCode; Code = $code; Result = $message; Content = $response.Content }
}

Write-Host "等待 $SettleSeconds 秒，使 CC URL 多样性检测窗口自然过期……" -ForegroundColor DarkGray
Start-Sleep -Seconds $SettleSeconds

$results = @()
$normal = Invoke-WAFRequest -Name '正常访问' -Uri "$base/"
if ($normal.Result -match '安全检测') {
    Complete-WAFChallenge -Html $normal.Content
    Start-Sleep -Milliseconds 1200
    $normal = Invoke-WAFRequest -Name '正常访问' -Uri "$base/"
}
$results += $normal
Start-Sleep -Milliseconds 1300

$xss = [uri]::EscapeDataString('<script>alert(1)</script>')
$results += Invoke-WAFRequest -Name 'XSS 特征' -Uri "$base/?q=$xss"
Start-Sleep -Milliseconds 1900

$sql = [uri]::EscapeDataString("' OR 1=1")
$results += Invoke-WAFRequest -Name 'SQL 注入特征' -Uri "$base/?id=$sql"
Start-Sleep -Seconds 1

$unknownHeaders = $browserHeaders.Clone()
$unknownHeaders['Host'] = 'unknown.jingshield.test'
$results += Invoke-WAFRequest -Name '未知 Host' -Uri "$base/" -Headers $unknownHeaders

$results | Select-Object Test, HTTP, Code, Result | Format-Table -AutoSize

$failures = @()
if ($results[0].HTTP -ne 200) { $failures += '正常访问没有返回 200' }
if ($results[1].HTTP -ne 403 -or $results[1].Code -ne -110) { $failures += 'XSS 测试未返回 HTTP 403 / code -110' }
if ($results[2].HTTP -ne 403 -or $results[2].Code -ne -100) { $failures += 'SQL 注入测试未返回 HTTP 403 / code -100' }
if ($results[3].HTTP -ne 421) { $failures += '未知 Host 未返回 421' }

if ($failures.Count) {
    Write-Host "`n测试未完全通过：" -ForegroundColor Yellow
    $failures | ForEach-Object { Write-Host "- $_" -ForegroundColor Yellow }
    exit 1
}

Write-Host "`nWAF 冒烟测试通过。可在控制台的“攻击事件”和“访问审计”查看记录。" -ForegroundColor Green
