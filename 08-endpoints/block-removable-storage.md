# [REQ-END-004] Block Removable Storage

## Target Scope
* **Applicable Systems**: Tier 2 client workstations.
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * Computer Configuration\Administrative Templates\System\Removable Storage Access
  * HKLM\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices

---

## Rationale
Removable storage media, such as USB flash drives, external SSDs, and optical discs, represent a significant risk vector for corporate network environments. 

Attackers use USB drives to bypass network-based security boundaries (such as firewalls and intrusion detection systems), introducing malware directly onto local workstation hosts via physical sneakernets. USB drives are also a primary tool for insider threat data exfiltration, enabling users to copy proprietary or sensitive information off company terminals onto untracked hardware. Restricting removable storage access at the operating system level prevents both unauthorized data ingress (malware infection) and data egress (unauthorized data copying).

---

## Legacy Impact & Compatibility
* **User Restrictions**: Users cannot read from or write to external USB storage devices, SD cards, or external CD/DVD readers. Any connected mass storage device will be rejected by the file system.
* **Administrative Tools**: Support technicians must use network-based shares, administrative shares, or secure file-transfer systems to deploy scripts or updates to client workstations.
* **Exceptions**: Keyboards, mice, printers, and smart card readers are not blocked, as they do not register under the Removable Storage device class.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Create or edit a GPO linked to the workstations OU (e.g., `GPO_Hardening_Workstations`).
3. Navigate to:
   `Computer Configuration\Administrative Templates\System\Removable Storage Access`
4. Configure the setting:
   * **Policy**: `All Removable Storage classes: Deny all access`
   * **Setting**: `Enabled`

*Alternatively, if you only want to block write access while allowing read-only access (for specific profiles), configure:*
* **Policy**: `Removable Disks: Deny write access` -> `Enabled`

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following scripts locally to configure registry keys to block all removable storage devices.

[Download Script: Block-RemovableStorage.ps1](implementation_scripts/Block-RemovableStorage.ps1)

```powershell
# Block-RemovableStorage.ps1
# Configures local registry parameters to deny access to all removable storage classes.

Write-Host "--- Restricting Removable Storage Devices ---" -ForegroundColor Cyan

$RemovableStoragePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices"

if (-not (Test-Path $RemovableStoragePath)) {
    New-Item -Path $RemovableStoragePath -Force | Out-Null
}

# Deny_All = 1 blocks all removable storage classes
Set-ItemProperty -Path $RemovableStoragePath -Name "Deny_All" -Value 1 -Type DWord

Write-Host "[+] Removable storage block configured." -ForegroundColor Green
```

*To audit removable storage block configurations:*
[Download Script: Test-RemovableStorage.ps1](audit_scripts/Test-RemovableStorage.ps1)

```powershell
# Test-RemovableStorage.ps1
# Audits registry values for removable storage blocks.

Write-Host "--- Auditing Removable Storage Restrictions ---" -ForegroundColor Cyan

$RemovableStoragePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices"

$DenyAllProp = Get-ItemProperty -Path $RemovableStoragePath -Name "Deny_All" -ErrorAction SilentlyContinue
$DenyAllVal = if ($DenyAllProp) { $DenyAllProp.Deny_All } else { 0 }
$DenyColor = if ($DenyAllVal -eq 1) { "Green" } else { "Red" }

Write-Host "    - Removable Storage Deny_All: $DenyAllVal (Required = 1)" -ForegroundColor $DenyColor
```

---

## 🔗 Sources & Compliance References
* **CIS Microsoft Windows 10 Benchmark**: Section 18.9.82 (All Removable Storage classes: Deny all access)
* **ANSSI AD Hardening Guide**: Section on hardware and external communication control.
