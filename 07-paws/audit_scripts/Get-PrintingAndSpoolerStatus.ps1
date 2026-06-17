# Get-PrintingAndSpoolerStatus.ps1
# Description: Audits print spooler status and Point and Print configurations on the local PAW.

Write-Host "--- Auditing PAW Secure Printing and Spooler Hardening ---" -ForegroundColor Cyan

$script:Vulnerable = $false

# 1. Audit Spooler Service Startup Type
$Service = Get-Service -Name "Spooler" -ErrorAction SilentlyContinue
if ($null -ne $Service) {
    # Check StartupType
    $StartupType = (Get-CimInstance -ClassName Win32_Service -Filter "Name='Spooler'").StartMode
    # StartMode can be "Disabled", "Manual", "Auto"
    $Color = if ($StartupType -eq "Disabled") { "Green" } else { "Red" }
    Write-Host "  [-] Print Spooler Service Startup: $StartupType (Expected: Disabled)" -ForegroundColor $Color
    if ($StartupType -ne "Disabled") {
        $script:Vulnerable = $true
    }
} else {
    Write-Host "  [+] Print Spooler Service is not present on this machine." -ForegroundColor Green
}

# 2. Audit Point and Print Registry Restriction
$Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
$Name = "RestrictDriverInstallationToAdministrators"
$Expected = 1

if (Test-Path $Path) {
    $Reg = Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue
    $Val = $Reg.$Name
    if ($Val -eq $Expected) {
        Write-Host "  [+] Path $($Path) | $($Name): $Val (Expected: $Expected)" -ForegroundColor Green
    } else {
        Write-Host "  [!] MISMATCH: Path $($Path) | $($Name): $Val (Expected: $Expected)" -ForegroundColor Red
        $script:Vulnerable = $true
    }
} else {
    Write-Host "  [!] NOT FOUND: Path $($Path) (Expected: $Name = $Expected)" -ForegroundColor Red
    $script:Vulnerable = $true
}

if ($script:Vulnerable) {
    Write-Host "Audit Result: VULNERABLE" -ForegroundColor Red
    exit 1
} else {
    Write-Host "Audit Result: SECURE" -ForegroundColor Green
    exit 0
}
