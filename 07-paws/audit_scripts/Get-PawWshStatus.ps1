# Get-PawWshStatus.ps1
# Description: Audits Windows Script Host registry state and script file extension association handlers on PAWs.

Write-Host "--- Auditing Windows Script Host Hardening ---" -ForegroundColor Cyan

$script:Vulnerable = $false

# 1. Audit WSH Registry settings
$RegistryHklm = "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings"
if (Test-Path $RegistryHklm) {
    $ValHklm = (Get-ItemProperty -Path $RegistryHklm -Name "Enabled" -ErrorAction SilentlyContinue).Enabled
    if ($ValHklm -eq 0) {
        Write-Host "    - HKLM WSH Enabled: 0 (Secure)" -ForegroundColor Green
    } else {
        Write-Host "    - VULNERABLE: HKLM WSH is enabled or not configured (Value: '$ValHklm')" -ForegroundColor Red
        $script:Vulnerable = $true
    }
} else {
    Write-Host "    - VULNERABLE: HKLM WSH settings key is missing (Expected: Enabled = 0)" -ForegroundColor Red
    $script:Vulnerable = $true
}

# 2. Audit file associations
$Extensions = @("vbs", "vbe", "js", "jse", "wsf", "wsh", "hta")
foreach ($Ext in $Extensions) {
    $ProgIdPath = "HKLM:\SOFTWARE\Classes\.$Ext"
    if (Test-Path $ProgIdPath) {
        $Handler = (Get-ItemProperty -Path $ProgIdPath -Name "" -ErrorAction SilentlyContinue).""
        if ($Handler -eq "txtfile" -or $Handler -match "notepad") {
            Write-Host "    - Extension .$Ext Handler: $Handler (Secure)" -ForegroundColor Green
        } else {
            Write-Host "    - VULNERABLE: Extension .$Ext Handler is '$Handler' (Expected: txtfile/notepad)" -ForegroundColor Red
            $script:Vulnerable = $true
        }
    } else {
        Write-Host "    - VULNERABLE: Extension .$Ext Class Registry key not found." -ForegroundColor Red
        $script:Vulnerable = $true
    }
}

if ($script:Vulnerable) {
    Write-Host "Audit Result: VULNERABLE" -ForegroundColor Red
    exit 1
} else {
    Write-Host "Audit Result: SECURE" -ForegroundColor Green
    exit 0
}
