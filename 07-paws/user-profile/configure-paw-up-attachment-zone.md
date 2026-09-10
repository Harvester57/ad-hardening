# [REQ-PAW-149] User Profile: Preservation of Attachment Zone Information for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 Active Directory and identity infrastructure administration. *(For Tier 2 Client Workstations and Member Servers, refer to baseline [REQ-END-160](../../08-endpoints/user-profile/configure-end-up-attachment-zone.md)).*
* **Operating Systems**: Windows 10 Enterprise (version 1809 and above), Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: High
* **GPO Paths / Registry Locations**:
  * **Preserve Zone Information in File Attachments**:
    * GPO Path: `User Configuration\Administrative Templates\Windows Components\Attachment Manager\Do not preserve zone information in file attachments` -> **Disabled** (Forces `SaveZoneInformation` = `2`)
    * Computer GPO Path: `Computer Configuration\Administrative Templates\Windows Components\Attachment Manager\Do not preserve zone information in file attachments` -> **Disabled**
    * Registry Path: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments`
    * Value Name: `SaveZoneInformation`
    * Value Type: `REG_DWORD`
    * Value Data: `2` (Enabled / Enforce mandatory preservation of Zone.Identifier alternate data streams)

---

## Rationale
Privileged Access Workstations (PAWs) are strictly isolated systems dedicated to managing Tier 0 assets. Web browsing and direct email access are prohibited on PAWs. However, administrative files, deployment scripts, security patches, and utility binaries may occasionally be transferred to PAWs via approved, encrypted management channels or staging shares. Preserving Mark-of-the-Web (MOTW) zone information ensures that the operating system's internal defense layers remain fully informed of the file's external provenance.

### 1. Attachment Manager & Mark-of-the-Web Internals
The Windows Attachment Manager (`IAttachmentExecute` interface) tracks the origin of files by writing an NTFS Alternate Data Stream (ADS) named `Zone.Identifier`:
* A tag of `ZoneId=3` signifies that the file originated from the Internet, while `ZoneId=4` indicates a restricted zone.
* On a hardened PAW, WDAC, SmartScreen, and PowerShell Execution Policies evaluate this metadata:
  * **PowerShell Execution Policy & Constrained Language Mode**: Unrestricted or RemoteSigned scripts tagged with `ZoneId=3` require explicit administrator unblocking or are executed in Constrained Language Mode (CLM) to prevent arbitrary .NET invocation.
  * **Windows Defender Application Control (WDAC)**: SmartScreen and AppLocker rules integrate with MOTW to apply heightened scrutiny to downloaded binaries.
  * **Shell Execution Gates**: Windows Explorer prompts for explicit administrative confirmation before executing any untrusted file.
* If `SaveZoneInformation` is set to `1` (or if the policy is enabled), Windows strips this metadata, misleading security subsystems into treating untrusted external payloads as local, native files.

### 2. Tier 0 Threat Vectors & PAW Isolation
* **Preventing Staged Payload Execution**: If an adversary stages a payload via an internal jump server or network share, MOTW preservation ensures that PAW security agents recognize the file as untrusted, preventing silent background execution.
* **Integrity Validation for Administrative Updates**: Ensures that third-party administrative utilities transferred from outside networks trigger reputation checks and cannot bypass WDAC/AppLocker trust checks.
* Setting `SaveZoneInformation = 2` enforces immutable provenance tracking across the PAW filesystem.

### 3. MITRE ATT&CK Mapping
* **T1566.001 - Phishing: Spearphishing Attachment**: Inadvertent delivery of malicious payloads.
* **T1204.002 - User Execution: Malicious File**: Executing untrusted files on administrative consoles.
* **T1553.005 - Subvert Trust Controls: Mark-of-the-Web Bypass**: Stripping zone metadata to evade PAW security controls.

---

## Legacy Impact & Compatibility
* **PAW Dedicated Role**: Direct web browsing and email clients are strictly banned on PAWs. Administrative packages and scripts deployed via enterprise management systems (MECM, Intune, or approved secure shares) are properly signed and unblocked via automated deployment manifests.
* **Zero Disruption**: Standard administrative tasks, RSAT, and native system utilities operate without disruption.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to Tier 0 Privileged Access Workstations (e.g., `GPO_Hardening_PAW`).
3. Navigate to: `User Configuration \ Administrative Templates \ Windows Components \ Attachment Manager`
   *(Optionally also navigate to `Computer Configuration \ Administrative Templates \ Windows Components \ Attachment Manager`)*
4. Configure the policy:
   * **Policy**: `Do not preserve zone information in file attachments` -> Set to **Disabled**
   *(Note: Setting this policy to Disabled enforces SaveZoneInformation = 2, ensuring zone information is preserved).*
5. Alternatively, configure the registry value via Group Policy Preferences:
   * Navigate to: `Computer Configuration \ Preferences \ Windows Settings \ Registry`
   * Right-click **Registry** -> **New** -> **Registry Item** and configure:
     * **Action**: `Update`
     * **Hive**: `HKEY_LOCAL_MACHINE`
     * **Key Path**: `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments`
     * **Value Name**: `SaveZoneInformation`
     * **Value Type**: `REG_DWORD`
     * **Value Data**: `2`
6. Link the GPO to the dedicated PAW Organizational Unit and enforce replication using `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to enforce the preservation of attachment zone information on the PAW console:

[Download Script: Configure-PawAuditAttachmentzone.ps1](../implementation_scripts/Configure-PawAuditAttachmentzone.ps1)

```powershell
# Configure-PawAuditAttachmentzone.ps1
Write-Host "Enforcing System Mitigation control: attachment-zone..." -ForegroundColor Cyan

# Set Registry value: SaveZoneInformation
if (-not (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments")) { New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Force | Out-Null }
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "SaveZoneInformation" -Value 2 -Type DWord -Force
Write-Host "    Enforced SaveZoneInformation = 2" -ForegroundColor Green


```

*To audit the hardening status:*

[Download Script: Get-PawAuditAttachmentzoneStatus.ps1](../audit_scripts/Get-PawAuditAttachmentzoneStatus.ps1)

```powershell
# Get-PawAuditAttachmentzoneStatus.ps1
$script:Vulnerable = $false

# Audit Registry value: SaveZoneInformation
$RegVal = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "SaveZoneInformation" -ErrorAction SilentlyContinue
if (-not $RegVal -or $RegVal.SaveZoneInformation -ne 2) {
    $script:Vulnerable = $true
}

if ($script:Vulnerable) {
    Write-Output "Non-Compliant"
    exit 1
} else {
    Write-Output "Compliant"
    exit 0
}
```

---

## Sources & Compliance References
* **CIS Benchmark**: CIS Microsoft Windows 10 Enterprise Benchmark: Section 19.7.x (Attachment Manager); CIS Microsoft Windows 11 Enterprise Benchmark: Section 19.7.x
* **DISA STIG**: Windows 10 STIG Rule WN10-UC-000030, Windows 11 STIG Rule WN11-UC-000030
* **ANSSI Active Directory Hardening Guide**: Recommendation R37 (Securing workstation trust boundaries and download integrity)
* **Microsoft Privileged Access Guidance**: Securing Privileged Access: System-Level Hardening and Memory Protections
