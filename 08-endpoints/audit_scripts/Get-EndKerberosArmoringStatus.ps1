# Get-EndKerberosArmoringStatus.ps1
# Description: Audits client-side Kerberos Armoring configuration on Tier 2 endpoints.

Write-Host "--- Auditing Endpoint Kerberos Armoring Configuration ---" -ForegroundColor Cyan

$ClientRegPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"
$Vulnerable = $false

$ClientValue = Get-ItemProperty -Path $ClientRegPath -Name "EnableCbacAndArmor" -ErrorAction SilentlyContinue
$DevicePKInit = Get-ItemProperty -Path $ClientRegPath -Name "DevicePKInitEnabled" -ErrorAction SilentlyContinue
$DeviceBehavior = Get-ItemProperty -Path $ClientRegPath -Name "DevicePKInitBehavior" -ErrorAction SilentlyContinue
$RequireFast = Get-ItemProperty -Path $ClientRegPath -Name "RequireFast" -ErrorAction SilentlyContinue

# 1. Audit Client-side support for claims and armoring
if ($null -ne $ClientValue -and $ClientValue.EnableCbacAndArmor -eq 1) {
    Write-Host "[+] Client-side Kerberos Armoring is ENABLED (EnableCbacAndArmor = 1)." -ForegroundColor Green
} else {
    Write-Host "[!] VULNERABLE: Client-side Kerberos Armoring is DISABLED or missing." -ForegroundColor Red
    $Vulnerable = $true
}

# 2. Audit Certificate device authentication
if ($null -ne $DevicePKInit -and $DevicePKInit.DevicePKInitEnabled -eq 1 -and $null -ne $DeviceBehavior -and $DeviceBehavior.DevicePKInitBehavior -eq 0) {
    Write-Host "[+] Certificate device authentication is ENABLED: Automatic." -ForegroundColor Green
} else {
    Write-Host "[!] VULNERABLE: Certificate device authentication is not compliant or not configured." -ForegroundColor Red
    $Vulnerable = $true
}

# 3. Audit RequireFast (for endpoints, 0 or absent is acceptable for opportunistic FAST)
if ($null -eq $RequireFast -or $RequireFast.RequireFast -eq 0) {
    Write-Host "[+] Kerberos Armoring mode is configured for opportunistic negotiation (RequireFast = 0)." -ForegroundColor Green
} else {
    Write-Host "[-] Information: RequireFast is set to $($RequireFast.RequireFast)." -ForegroundColor Yellow
}

if ($Vulnerable) {
    Write-Output "Non-Compliant"
    exit 1
} else {
    Write-Output "Compliant"
    exit 0
}
