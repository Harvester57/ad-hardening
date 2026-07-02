# Get-PdcTimeSyncStatus.ps1
# Description: Audits Windows Time Service configuration on the local Domain Controller.

Write-Host "--- Auditing PDC Time Synchronization Status ---" -ForegroundColor Cyan

# 1. Determine if local computer is the PDC Emulator
try {
    $Domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    $PdcName = $Domain.PdcRoleOwner.Name
    $ComputerFQDN = "$env:COMPUTERNAME.$env:USERDNSDOMAIN"
    $IsPdc = ($PdcName -eq $ComputerFQDN) -or ($PdcName.Split(".")[0] -eq $env:COMPUTERNAME)
} catch {
    Write-Warning "Could not dynamically determine PDC Emulator FSMO role owner."
    $IsPdc = $false
}

$W32TimeParams = "HKLM:\System\CurrentControlSet\Services\W32Time\Parameters"
$W32TimeConfig = "HKLM:\System\CurrentControlSet\Services\W32Time\Config"

$TypeVal = Get-ItemProperty -Path $W32TimeParams -Name "Type" -ErrorAction SilentlyContinue
$AnnounceVal = Get-ItemProperty -Path $W32TimeConfig -Name "AnnounceFlags" -ErrorAction SilentlyContinue

$Service = Get-Service -Name w32time -ErrorAction SilentlyContinue

if ($null -eq $Service -or $Service.Status -ne "Running") {
    Write-Host "[!] VULNERABLE: Windows Time Service (w32time) is not running." -ForegroundColor Red
    exit 1
}

if ($IsPdc) {
    Write-Host "[*] Active role: PDC Emulator FSMO owner." -ForegroundColor White
    if ($TypeVal.Type -eq "NTP" -and $AnnounceVal.AnnounceFlags -eq 5) {
        Write-Host "[+] Compliant: PDC Emulator configured as reliable NTP source (Type: NTP, Announce: 5)." -ForegroundColor Green
        exit 0
    } else {
        Write-Host "[!] NON-COMPLIANT: PDC Emulator has incorrect settings (Type: $($TypeVal.Type), Announce: $($AnnounceVal.AnnounceFlags))." -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "[*] Active role: Standard Domain Controller." -ForegroundColor White
    if ($TypeVal.Type -eq "NT5DS" -and $AnnounceVal.AnnounceFlags -eq 10) {
        Write-Host "[+] Compliant: Standard Domain Controller using NT5DS domain hierarchy." -ForegroundColor Green
        exit 0
    } else {
        Write-Host "[!] NON-COMPLIANT: DC is not using standard NT5DS settings (Type: $($TypeVal.Type), Announce: $($AnnounceVal.AnnounceFlags))." -ForegroundColor Red
        exit 1
    }
}
