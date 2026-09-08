# Get-KerberosArmoringStatus.ps1
# Description: Audits the Kerberos Armoring (FAST) and PKInit Freshness configuration on Domain Controllers and clients.

Write-Host "--- Auditing Kerberos Armoring (FAST) Configuration ---" -ForegroundColor Cyan

$DomainRole = (Get-CimInstance -ClassName Win32_ComputerSystem).DomainRole
$IsDC = ($DomainRole -eq 4) -or ($DomainRole -eq 5)
$ClientRegPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"
$KdcRegPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters"

$Vulnerable = $false

# 1. Audit Client-side support
$ClientValue = Get-ItemProperty -Path $ClientRegPath -Name "EnableCbacAndArmor" -ErrorAction SilentlyContinue
$DevicePKInit = Get-ItemProperty -Path $ClientRegPath -Name "DevicePKInitEnabled" -ErrorAction SilentlyContinue
$DeviceBehavior = Get-ItemProperty -Path $ClientRegPath -Name "DevicePKInitBehavior" -ErrorAction SilentlyContinue

if ($null -ne $ClientValue -and $ClientValue.EnableCbacAndArmor -eq 1) {
    Write-Host "[+] Client-side Kerberos Armoring is ENABLED (EnableCbacAndArmor = 1)." -ForegroundColor Green
} else {
    Write-Host "[!] VULNERABLE: Client-side Kerberos Armoring is DISABLED or missing." -ForegroundColor Red
    $Vulnerable = $true
}

if ($null -ne $DevicePKInit -and $DevicePKInit.DevicePKInitEnabled -eq 1 -and $null -ne $DeviceBehavior -and $DeviceBehavior.DevicePKInitBehavior -eq 0) {
    Write-Host "[+] Certificate device authentication is ENABLED: Automatic." -ForegroundColor Green
} else {
    Write-Host "[!] VULNERABLE: Certificate device authentication is not compliant or not configured." -ForegroundColor Red
    $Vulnerable = $true
}

# 2. Audit KDC support if Domain Controller
if ($IsDC) {
    Write-Host "Domain Controller detected. Auditing KDC support..." -ForegroundColor Cyan
    $KdcCbac = Get-ItemProperty -Path $KdcRegPath -Name "EnableCbacAndArmor" -ErrorAction SilentlyContinue
    $KdcLevel = Get-ItemProperty -Path $KdcRegPath -Name "CbacAndArmorLevel" -ErrorAction SilentlyContinue
    $KdcFresh = Get-ItemProperty -Path $KdcRegPath -Name "PKINITFreshness" -ErrorAction SilentlyContinue

    if ($null -ne $KdcCbac -and $KdcCbac.EnableCbacAndArmor -eq 1 -and $null -ne $KdcLevel) {
        $LevelVal = $KdcLevel.CbacAndArmorLevel
        if ($LevelVal -eq 1) {
            Write-Host "[+] KDC support for claims and armoring is ENABLED (Supported: 1)." -ForegroundColor Green
        } elseif ($LevelVal -eq 2) {
            Write-Host "[+] KDC support for claims and armoring is ENABLED (Always provide claims: 2)." -ForegroundColor Green
        } elseif ($LevelVal -eq 3) {
            Write-Host "[+] KDC support for claims and armoring is ENABLED and ENFORCED (Fail unarmored: 3)." -ForegroundColor Green
        } else {
            Write-Host "[!] VULNERABLE: KDC CbacAndArmorLevel configured with invalid value: $($LevelVal)." -ForegroundColor Red
            $Vulnerable = $true
        }
    } else {
        Write-Host "[!] VULNERABLE: KDC support for claims and armoring is MISSING or misconfigured." -ForegroundColor Red
        $Vulnerable = $true
    }

    if ($null -ne $KdcFresh -and ($KdcFresh.PKINITFreshness -eq 1 -or $KdcFresh.PKINITFreshness -eq 2)) {
        Write-Host "[+] KDC PKInit Freshness Extension is ENABLED (Value: $($KdcFresh.PKINITFreshness))." -ForegroundColor Green
    } else {
        Write-Host "[!] VULNERABLE: KDC PKInit Freshness Extension is MISSING or disabled." -ForegroundColor Red
        $Vulnerable = $true
    }
}

if ($Vulnerable) {
    Write-Output "Non-Compliant"
    exit 1
} else {
    Write-Output "Compliant"
    exit 0
}
