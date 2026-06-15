# Test-WMIStaticPort.ps1
# Description: Audits WMI static port registry configuration and standalone host settings.

Write-Host "Auditing WMI static port configuration..." -ForegroundColor Cyan
$vulnerable = $false

# 1. Audit AppID Endpoints Registry Setting
$WmiAppIdPath = "HKLM:\SOFTWARE\Classes\AppID\{8BC3F05E-D86B-11D0-A075-00C04FB68820}"
$EndpointsVal = Get-ItemProperty -Path $WmiAppIdPath -Name "Endpoints" -ErrorAction SilentlyContinue

if ($EndpointsVal) {
    $Endpoints = $EndpointsVal.Endpoints
    if ($Endpoints -contains "ncacn_ip_tcp,0,24158") {
        Write-Host "[+] WMI static port registry endpoint is configured correctly (TCP 24158)." -ForegroundColor Green
    } else {
        Write-Host "[!] NON-COMPLIANT: WMI Endpoints registry value is: '$($Endpoints -join ', ')' (Expected: 'ncacn_ip_tcp,0,24158')" -ForegroundColor Red
        $vulnerable = $true
    }
} else {
    Write-Host "[!] NON-COMPLIANT: Wmi AppID 'Endpoints' value is missing." -ForegroundColor Red
    $vulnerable = $true
}

# 2. Audit WMI Service Execution Type
$WinmgmtPath = "HKLM:\SYSTEM\CurrentControlSet\Services\winmgmt"
$TypeVal = Get-ItemProperty -Path $WinmgmtPath -Name "Type" -ErrorAction SilentlyContinue

if ($TypeVal) {
    $Type = $TypeVal.Type
    if ($Type -eq 16) {
        Write-Host "[+] WMI is configured to run as a standalone process (Type = 16)." -ForegroundColor Green
    } else {
        Write-Host "[!] NON-COMPLIANT: WMI service execution type is: $Type (Expected: 16 [OWN_PROCESS])" -ForegroundColor Red
        $vulnerable = $true
    }
} else {
    Write-Host "[!] NON-COMPLIANT: WMI service registry key is missing or inaccessible." -ForegroundColor Red
    $vulnerable = $true
}

if ($vulnerable) {
    Write-Host "Audit result: NON-COMPLIANT" -ForegroundColor Red
} else {
    Write-Host "Audit result: COMPLIANT" -ForegroundColor Green
}
