# Configure-PdcTimeSync.ps1
# Description: Configures Windows Time Service on the PDC Emulator or default DC time settings.

Write-Host "Applying hardening: Configure NTP Time Synchronization on PDC Emulator..." -ForegroundColor Cyan

# 1. Determine if local computer is the PDC Emulator
try {
    $Domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    $PdcName = $Domain.PdcRoleOwner.Name
    $ComputerFQDN = "$env:COMPUTERNAME.$env:USERDNSDOMAIN"
    $IsPdc = ($PdcName -eq $ComputerFQDN) -or ($PdcName.Split(".")[0] -eq $env:COMPUTERNAME)
} catch {
    Write-Warning "Could not dynamically determine PDC Emulator FSMO role owner. Defaulting to NT5DS client mode."
    $IsPdc = $false
}

$W32TimeParams = "HKLM:\System\CurrentControlSet\Services\W32Time\Parameters"
$W32TimeConfig = "HKLM:\System\CurrentControlSet\Services\W32Time\Config"

if ($IsPdc) {
    Write-Host "[+] This system is the active PDC Emulator. Configuring as reliable NTP source..." -ForegroundColor Green
    
    # Configure parameters
    Set-ItemProperty -Path $W32TimeParams -Name "Type" -Value "NTP" -Type String -Force
    # Set default external NTP source (e.g. time.windows.com or local air-gapped clock)
    Set-ItemProperty -Path $W32TimeParams -Name "NtpServer" -Value "time.windows.com,0x8" -Type String -Force
    # Configure AnnounceFlags to 5 (Reliable Time Server)
    Set-ItemProperty -Path $W32TimeConfig -Name "AnnounceFlags" -Value 5 -Type DWord -Force
    
    # Apply changes to w32time service
    $Null = Start-Process w32tm -ArgumentList "/config /manualpeerlist:`"time.windows.com,0x8`" /syncfromflags:manual /reliable:yes /update" -Wait -NoNewWindow
    Write-Host "[+] System w32tm manual peer list updated to time.windows.com." -ForegroundColor Green
} else {
    Write-Host "[-] This system is NOT the PDC Emulator. Enforcing NT5DS domain hierarchy sync..." -ForegroundColor Yellow
    
    # Configure parameters
    Set-ItemProperty -Path $W32TimeParams -Name "Type" -Value "NT5DS" -Type String -Force
    Set-ItemProperty -Path $W32TimeConfig -Name "AnnounceFlags" -Value 10 -Type DWord -Force
    
    # Apply changes to w32time service
    $Null = Start-Process w32tm -ArgumentList "/config /syncfromflags:domhier /reliable:no /update" -Wait -NoNewWindow
    Write-Host "[+] System w32tm configured to synchronize from domain hierarchy." -ForegroundColor Green
}

# Restart Windows Time Service to apply settings
Restart-Service w32time -Force
Write-Host "[+] Windows Time Service (w32time) restarted." -ForegroundColor Green
