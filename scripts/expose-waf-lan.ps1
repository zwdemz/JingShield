[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ListenAddress,
    [ValidateRange(1, 65535)][int]$ListenPort = 18443,
    [Parameter(Mandatory = $true)]
    [string]$TargetAddress,
    [ValidateRange(1, 65535)][int]$TargetPort = 18443,
    [Parameter(Mandatory = $true)]
    [string]$AllowedSubnet,
    [switch]$Remove
)

$ErrorActionPreference = 'Stop'
$ruleName = "JingShield WAF $ListenPort LAN"
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'This script must be run from an elevated PowerShell session.'
}

if ($Remove) {
    netsh interface portproxy delete v4tov4 listenaddress=$ListenAddress listenport=$ListenPort | Out-Null
    Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    Write-Host "Removed https://${ListenAddress}:${ListenPort} port forwarding."
    exit 0
}

if (-not (Get-NetIPAddress -AddressFamily IPv4 -IPAddress $ListenAddress -ErrorAction SilentlyContinue)) {
    throw "Listen address $ListenAddress is not assigned to this computer."
}
$targetCheck = Test-NetConnection -ComputerName $TargetAddress -Port $TargetPort -WarningAction SilentlyContinue
if (-not $targetCheck.TcpTestSucceeded) {
    throw "Target ${TargetAddress}:${TargetPort} is not reachable."
}

Set-Service -Name iphlpsvc -StartupType Automatic
Start-Service -Name iphlpsvc

# Replace only this exact listener so the script can be run again safely.
netsh interface portproxy delete v4tov4 listenaddress=$ListenAddress listenport=$ListenPort | Out-Null
netsh interface portproxy add v4tov4 listenaddress=$ListenAddress listenport=$ListenPort connectaddress=$TargetAddress connectport=$TargetPort
if ($LASTEXITCODE -ne 0) {
    throw 'Failed to create the Windows port proxy.'
}

Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule
New-NetFirewallRule -DisplayName $ruleName `
    -Description "LAN access to JingShield at ${TargetAddress}:${TargetPort}" `
    -Direction Inbound -Action Allow -Protocol TCP `
    -LocalAddress $ListenAddress -LocalPort $ListenPort `
    -RemoteAddress $AllowedSubnet -Profile Private | Out-Null

Write-Host "Ready: https://${ListenAddress}:${ListenPort} -> https://${TargetAddress}:${TargetPort}"
Write-Host "Allowed clients: $AllowedSubnet"
