# [REQ-DC-031] Configure NTP Time Synchronization on the PDC Emulator

## Target Scope
* **Applicable Systems**: Domain Controllers (specifically the PDC Emulator FSMO role owner)
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022, Windows Server 2025

---

## Implementation Details
* **Priority**: High (Essential for secure Kerberos authentication and time synchronization)
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Administrative Templates\System\Windows Time Service`
  * **Registry Locations**:
    * `HKLM\System\CurrentControlSet\Services\W32Time\Parameters` -> `Type` = `"NTP"`
    * `HKLM\System\CurrentControlSet\Services\W32Time\Config` -> `AnnounceFlags` = `5` (REG_DWORD)
    * `HKLM\System\CurrentControlSet\Services\W32Time\Parameters` -> `NtpServer` = `"[NtpServerAddress],0x8"` (REG_SZ)

---

## Rationale
Active Directory relies heavily on Kerberos authentication, which has a default maximum clock skew limit of 5 minutes to prevent replay attacks. If the system clocks of Domain Controllers and member endpoints drift, authentication will fail, causing directory service outages.

The Domain Controller holding the Primary Domain Controller (PDC) Emulator FSMO role acts as the root time source for the entire Active Directory forest. All other Domain Controllers synchronize their time from the PDC Emulator, and member servers and workstations synchronize their time from their local authenticating Domain Controllers (using the NT5DS domain hierarchy).

If the PDC Emulator is not configured to synchronize with a reliable external time source or hardware clock:
1. **Clock Drift Outages**: The entire forest clock can drift over time, eventually exceeding the 5-minute skew limit for external integrations or causing authentication failures.
2. **Replay Attacks**: A lack of synchronized time compromises the security of Kerberos tokens, leaving the environment vulnerable to replay attacks.

Configuring the PDC Emulator as a reliable NTP server synchronizing with a secure, trusted reference clock prevents time drift and secures Kerberos transactions.

---

## Legacy Impact & Compatibility
* **Integration Services Conflict**: When Domain Controllers run as virtual machines (e.g., on Hyper-V or VMware ESXi), the hypervisor's integration services may try to synchronize the guest's clock with the physical host. This conflict can lead to time synchronization issues. Hyper-V/VMware time synchronization must be disabled on virtual Domain Controllers if they are configured to synchronize via NTP.
* **Network Connectivity**: In air-gapped environments, the PDC Emulator must be configured to synchronize from a local hardware clock (such as a GPS-based NTP appliance) rather than an internet-based server.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

To configure the PDC Emulator time synchronization via a dedicated GPO linked to the Domain Controllers OU (utilizing WMI filtering to target only the PDC Emulator):

#### 1. Create a WMI Filter for the PDC Emulator Role
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Right-click **WMI Filters** in the console tree and select **New**.
3. Name the filter `Target PDC Emulator`.
4. Add the following WQL query:
   ```sql
   Select * from Win32_DirectoryServerInfo where DomainRole = 5
   ```
5. Click **Save**.

#### 2. Configure Windows Time Service Policy
1. Create a new GPO named `SEC_DomainControllers_TimeSync` and link it to the **Domain Controllers** OU.
2. Under the WMI Filtering section of the GPO, select the `Target PDC Emulator` filter.
3. Edit the GPO and navigate to:
   `Computer Configuration\Policies\Administrative Templates\System\Windows Time Service\Time Providers`
4. Configure the following policies:
   * **Configure Windows NTP Client**:
     * Set to **Enabled**.
     * **NtpServer**: `time.windows.com,0x8` (or the IP/FQDN of your local hardware NTP server in air-gapped systems).
     * **Type**: `NTP`.
     * **CrossSiteSyncFlags**: `2` (All).
     * **ResolvePeerBackoffMinutes**: `15`.
     * **ResolvePeerBackoffMaxTimes**: `7`.
     * **SpecialPollInterval**: `3600`.
     * **EventLogFlags**: `3`.
   * **Enable Windows NTP Client**:
     * Set to **Enabled**.
   * **Enable Windows NTP Server**:
     * Set to **Enabled**.
5. Navigate to:
   `Computer Configuration\Policies\Administrative Templates\System\Windows Time Service`
6. Configure the settings:
   * **Global Configuration Settings**:
     * Set to **Enabled**.
     * **AnnounceFlags**: `5` (Reliable Time Server).
7. Force update policy on the PDC Emulator.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Use this method to apply the setting locally on the active PDC Emulator.

[Download Script: Configure-PdcTimeSync.ps1](implementation_scripts/Configure-PdcTimeSync.ps1)

```powershell
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
```

*To verify time synchronization status:*

[Download Script: Get-PdcTimeSyncStatus.ps1](audit_scripts/Get-PdcTimeSyncStatus.ps1)

```powershell
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
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Section 2.1 (Domain Controller requirements)
* **CIS Benchmark**: CIS Microsoft Windows Server Benchmark - Section 18.9.51.1 (Ensure 'Configure Windows NTP Client' is set to 'Enabled')
* **Microsoft Security Guidance**: Windows Time Service Technical Reference
