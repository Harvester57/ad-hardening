# Audit-GPOPrecedence.ps1
# Description: Verifies GPO precedence on DC OU, and checks local EFS and background refresh registry configuration.

Import-Module ActiveDirectory
Import-Module GroupPolicy

Write-Host "--- Auditing Default Policies and Precedence ---" -ForegroundColor Cyan

# 1. Audit GPO Precedence on Domain Controllers OU
$DomainInfo = Get-ADDomain
$DCOUDN = "OU=Domain Controllers,$($DomainInfo.DistinguishedName)"

try {
    $OUInfo = Get-GPInheritance -Target $DCOUDN -ErrorAction Stop
    
    Write-Host "`nLinked GPOs on Domain Controllers OU:" -ForegroundColor Yellow
    $HardeningGPOFound = $false
    $HardeningOrder = 999
    $DefaultDCOrder = 999
    
    foreach ($link in $OUInfo.GpoLinks) {
        $status = if ($link.Enabled) { "Enabled" } else { "Disabled" }
        Write-Host "    - Link Order: $($link.Order) | GPO Name: $($link.DisplayName) | Status: $status" -ForegroundColor White
        
        if ($link.DisplayName -like "*Hardening*" -and $link.Enabled) {
            $HardeningGPOFound = $true
            $HardeningOrder = $link.Order
        }
        if ($link.DisplayName -eq "Default Domain Controllers Policy") {
            $DefaultDCOrder = $link.Order
        }
    }
    
    if ($HardeningGPOFound -and $HardeningOrder -lt $DefaultDCOrder) {
        Write-Host "`n[+] GPO Precedence: Compliant. Custom hardening GPO has higher precedence (Order $HardeningOrder) than Default DC Policy (Order $DefaultDCOrder)." -ForegroundColor Green
    } else {
        Write-Host "`n[!] VULNERABLE: No active dedicated hardening GPO found with higher precedence than Default DC Policy." -ForegroundColor Red
    }
} catch {
    Write-Host "[!] Could not retrieve GPO information for DC OU. Error: $($_.Exception.Message)" -ForegroundColor Red
}

# 2. Audit EFS Registry status
$EfsPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\EFS"
$EfsVal = Get-ItemProperty -Path $EfsPath -Name "EfsConfiguration" -ErrorAction SilentlyContinue
if ($EfsVal -and $EfsVal.EfsConfiguration -eq 1) {
    Write-Host "[+] EFS Configuration: Secure (Disabled)." -ForegroundColor Green
} else {
    Write-Host "[!] VULNERABLE: EFS is not disabled in registry policies." -ForegroundColor Red
}

# 3. Audit Background Refresh status
$SysPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
$BkgVal = Get-ItemProperty -Path $SysPath -Name "DisableBkGndGroupPolicy" -ErrorAction SilentlyContinue
if ($BkgVal -and $BkgVal.DisableBkGndGroupPolicy -eq 0) {
    Write-Host "[+] Group Policy Background Refresh: Secure (Active)." -ForegroundColor Green
} else {
    Write-Host "[!] VULNERABLE: Group Policy background refresh is turned off in registry." -ForegroundColor Red
}
