# Get-RdpRestrictedAdminStatus.ps1
# Description: Checks the configuration state of RDP Restricted Admin and session security settings.

$LsaPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
$ValueName = "DisableRestrictedAdmin"

Write-Host "Checking local LSA registry settings..." -ForegroundColor Cyan

if (Test-Path $LsaPath) {
    $Value = Get-ItemProperty -Path $LsaPath -Name $ValueName -ErrorAction SilentlyContinue
    if ($null -ne $Value) {
        if ($Value.DisableRestrictedAdmin -eq 0) {
            Write-Host "[+] RDP Restricted Admin Mode: Enabled (Value = 0)." -ForegroundColor Green
        } else {
            Write-Host "[-] RDP Restricted Admin Mode: Disabled (Value = $($Value.DisableRestrictedAdmin))." -ForegroundColor Red
        }
    } else {
        Write-Host "[+] RDP Restricted Admin Mode: Enabled (Default state: No registry restriction)." -ForegroundColor Green
    }
}

Write-Host "Checking RDP Session Security registry settings..." -ForegroundColor Cyan
$RdpPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"

$ExpectedRdpSettings = @{
    "DisablePasswordSaving" = 1
    "fSingleSessionPerUser" = 1
    "fDisableCdm"           = 1
    "fDisableCcm"           = 1
    "fDisableLpt"           = 1
    "fDisablePNPRedir"      = 1
    "fPromptForPassword"    = 1
    "fEncryptRPCTraffic"    = 1
    "MinEncryptionLevel"    = 3
    "MaxIdleTime"           = 900000
    "MaxDisconnectionTime"  = 60000
}

if (Test-Path $RdpPolicyPath) {
    $PolicyValues = Get-ItemProperty -Path $RdpPolicyPath -ErrorAction SilentlyContinue
    foreach ($Setting in $ExpectedRdpSettings.Keys) {
        $Val = $PolicyValues.$Setting
        $Expected = $ExpectedRdpSettings[$Setting]
        $Color = if ($Val -eq $Expected) { "Green" } else { "Red" }
        Write-Host "    - $($Setting): $Val (Expected: $Expected)" -ForegroundColor $Color
    }
} else {
    Write-Host "[-] RDP Session Policies path not found." -ForegroundColor Red
}
