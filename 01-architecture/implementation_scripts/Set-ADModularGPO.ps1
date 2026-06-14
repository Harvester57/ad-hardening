# Set-ADModularGPO.ps1
# Description: Creates DC hardening GPO with top precedence, disables EFS, and enables background refresh locally.

Import-Module ActiveDirectory
Import-Module GroupPolicy

Write-Host "Applying Default Policies hardening baseline..." -ForegroundColor Cyan

# 1. Create and Link DC Hardening GPO
$DomainInfo = Get-ADDomain
$DCOUDN = "OU=Domain Controllers,$($DomainInfo.DistinguishedName)"
$GPOName = "SEC_DomainControllers_Hardening"

try {
    $GPO = Get-GPO -Name $GPOName -ErrorAction SilentlyContinue
    if (-not $GPO) {
        $GPO = New-GPO -Name $GPOName -Comment "Dedicated GPO for Domain Controllers hardening. Requirements: REQ-ARCH-005." -ErrorAction Stop
        Write-Host "[+] GPO '$GPOName' created successfully." -ForegroundColor Green
    } else {
        Write-Host "[+] GPO '$GPOName' already exists." -ForegroundColor Yellow
    }
    
    $Links = (Get-GPInheritance -Target $DCOUDN).GpoLinks
    $IsLinked = $false
    foreach ($link in $Links) {
        if ($link.DisplayName -eq $GPOName) {
            $IsLinked = $true
            break
        }
    }
    
    if (-not $IsLinked) {
        New-GPLink -Name $GPOName -Target $DCOUDN -LinkEnabled Yes -ErrorAction Stop | Out-Null
        Write-Host "[+] GPO '$GPOName' linked to Domain Controllers OU." -ForegroundColor Green
    } else {
        Write-Host "[+] GPO '$GPOName' is already linked to Domain Controllers OU." -ForegroundColor Yellow
    }
    
    Set-GPLink -Name $GPOName -Target $DCOUDN -Order 1 -ErrorAction Stop | Out-Null
    Write-Host "[+] GPO '$GPOName' set to link order 1 (highest precedence)." -ForegroundColor Green
} catch {
    Write-Host "[!] Failed to configure GPO structure. Error: $($_.Exception.Message)" -ForegroundColor Red
}

# 2. Configure Local Registry for EFS (Disable)
$EfsPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\EFS"
if (-not (Test-Path $EfsPath)) {
    New-Item -Path $EfsPath -Force | Out-Null
}
Set-ItemProperty -Path $EfsPath -Name "EfsConfiguration" -Value 1 -Type DWord -Force
Write-Host "[+] EFS registry policy configured to Disabled." -ForegroundColor Green

# 3. Configure Local Registry for GP Background Refresh (Active)
$SysPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
if (-not (Test-Path $SysPath)) {
    New-Item -Path $SysPath -Force | Out-Null
}
Set-ItemProperty -Path $SysPath -Name "DisableBkGndGroupPolicy" -Value 0 -Type DWord -Force
Write-Host "[+] Group Policy background refresh registry policy enabled." -ForegroundColor Green
