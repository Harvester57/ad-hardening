# Get-KerberosArmoringStatus.ps1
# Description: Audits the Kerberos Armoring (FAST) configuration on DCs and clients.

Write-Host "--- Auditing Kerberos Armoring (FAST) Configuration ---" -ForegroundColor Cyan

$DomainRole = (Get-CimInstance -ClassName Win32_ComputerSystem).DomainRole
$IsDC = ($DomainRole -eq 4) -or ($DomainRole -eq 5)
$ClientRegPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"
$KdcRegPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters"

# 1. Audit Client-side support
$ClientValue = Get-ItemProperty -Path $ClientRegPath -Name "EnableCbacAndArmor" -ErrorAction SilentlyContinue

if ($null -ne $ClientValue) {
    $ClientState = $ClientValue.EnableCbacAndArmor
    if ($ClientState -eq 1) {
        Write-Host "[+] Client-side Kerberos Armoring is ENABLED (EnableCbacAndArmor = 1)." -ForegroundColor Green
    } else {
        Write-Host "[!] Client-side Kerberos Armoring is DISABLED (EnableCbacAndArmor = $($ClientState))." -ForegroundColor Red
    }
} else {
    Write-Host "[!] Client-side Kerberos Armoring configuration is MISSING (Disabled by default)." -ForegroundColor Red
}

# 2. Audit KDC support if Domain Controller
if ($IsDC) {
    Write-Host "Domain Controller detected. Auditing KDC support..." -ForegroundColor Cyan
    $KdcValue = Get-ItemProperty -Path $KdcRegPath -Name "EnableCbacAndArmor" -ErrorAction SilentlyContinue
    if ($null -ne $KdcValue) {
        $KdcState = $KdcValue.EnableCbacAndArmor
        if ($KdcState -eq 1) {
            Write-Host "[+] KDC support for claims and armoring is ENABLED (Supported: 1)." -ForegroundColor Green
        } elseif ($KdcState -eq 2) {
            Write-Host "[+] KDC support for claims and armoring is ENABLED (Always provide claims: 2)." -ForegroundColor Green
        } elseif ($KdcState -eq 3) {
            Write-Host "[+] KDC support for claims and armoring is ENABLED and ENFORCED (Fail unarmored: 3)." -ForegroundColor Green
        } else {
            Write-Host "[!] KDC support for claims and armoring is configured with unrecognized value: $($KdcState)." -ForegroundColor Red
        }
    } else {
        Write-Host "[!] KDC support for claims and armoring configuration is MISSING (Disabled by default)." -ForegroundColor Red
    }
}
