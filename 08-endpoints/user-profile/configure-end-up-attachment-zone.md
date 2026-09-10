# [REQ-END-160] User Profile: Preservation of Attachment Zone Information for Endpoints

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations and Member Servers. *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-149](../../07-paws/user-profile/configure-paw-up-attachment-zone.md)).*
* **Operating Systems**: Windows 10 Enterprise/Professional (all supported builds), Windows 11 Enterprise/Pro, Windows Server 2016, 2019, 2022, and 2025.

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
Mark-of-the-Web (MOTW) is a vital Windows defensive mechanism that tags files downloaded from the Internet or untrusted external zones with contextual provenance metadata. When a file is received via a web browser, email client (e.g., Microsoft Outlook), or chat application, the Windows Attachment Manager (`IAttachmentExecute` API) writes an NTFS Alternate Data Stream (ADS) named `Zone.Identifier` to the downloaded file.

### 1. Attachment Manager & Mark-of-the-Web Internals
When a downloaded file is saved to an NTFS volume, the Attachment Manager writes the `Zone.Identifier` stream:
* A value of `ZoneId=3` denotes the `URLZONE_INTERNET` zone, while `ZoneId=4` denotes the `URLZONE_UNTRUSTED` zone.
* Security components across Windows evaluate this zone metadata before allowing code execution:
  * **Microsoft Defender SmartScreen**: Triggers reputation checks and blocks unknown or suspicious downloaded executables.
  * **Microsoft Office Protected View**: Opens downloaded documents in an isolated AppContainer sandbox, strictly disabling VBA macros and embedded OLE objects.
  * **Windows Shell Security Warnings**: Presents the "Open File - Security Warning" dialog to prevent accidental or drive-by executions.
  * **Attack Surface Reduction (ASR)**: Rules such as "Block executable files from running unless they meet a prevalence, age, or trusted list criterion" rely directly on MOTW tags.
* If `SaveZoneInformation` is set to `1` (or if the policy "Do not preserve zone information in file attachments" is Enabled), Windows strips or omits the `Zone.Identifier` stream, causing the operating system to treat external payloads as trusted local files and completely blinding SmartScreen and Office Protected View.

### 2. Threat Vectors & Exploitation Mechanics
* **Drive-By Downloads and Phishing Payloads**: Threat actors distributing malware via email attachments or malicious web downloads rely on stripping or evading MOTW. If zone information is omitted, malicious executables run without SmartScreen reputation checks.
* **Malicious Macro Execution**: In the absence of MOTW, Microsoft Office does not activate Protected View for downloaded documents, allowing malicious VBA or Excel 4.0 (XLM) macros to execute immediately upon opening.
* Configuring `SaveZoneInformation = 2` (by setting the GPO policy to **Disabled**) guarantees that all downloaded attachments retain their cryptographic and contextual zone tags.

### 3. MITRE ATT&CK Mapping
* **T1566.001 - Phishing: Spearphishing Attachment**: Delivering malicious attachments via email lures.
* **T1204.002 - User Execution: Malicious File**: Coercing users into executing untrusted downloaded payloads.
* **T1553.005 - Subvert Trust Controls: Mark-of-the-Web Bypass**: Evading security controls that depend on MOTW zone tagging.

---

## Legacy Impact & Compatibility
* **Standard User Experience**: Standard users downloading legitimate business files from the Internet will see standard SmartScreen and Protected View notifications. Files can be unblocked by clicking "Unblock" in file properties if authorized.
* **Intranet and Trusted Sites**: Files downloaded from sites in the Local Intranet or Trusted Sites zones receive lower zone identifiers (`ZoneId=1` or `ZoneId=2`), preventing unnecessary prompt fatigue for internal tools.
* **Filesystem Support**: MOTW requires NTFS or ReFS filesystems that support alternate data streams. FAT32/exFAT removable drives do not support ADS, so enterprise removable drive policies should mandate NTFS.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to workstations and member servers (e.g., `GPO_Hardening_Endpoints`).
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
6. Link the GPO to the appropriate Organizational Unit and verify policy enforcement using `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to enforce the preservation of attachment zone information:

[Download Script: Configure-EndAuditAttachmentzone.ps1](../implementation_scripts/Configure-EndAuditAttachmentzone.ps1)

```powershell
# Configure-EndAuditAttachmentzone.ps1
Write-Host "Enforcing System Mitigation control: attachment-zone..." -ForegroundColor Cyan

# Set Registry value: SaveZoneInformation
if (-not (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments")) { New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Force | Out-Null }
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "SaveZoneInformation" -Value 2 -Type DWord -Force
Write-Host "    Enforced SaveZoneInformation = 2" -ForegroundColor Green


```

*To audit the hardening status:*

[Download Script: Get-EndAuditAttachmentzoneStatus.ps1](../audit_scripts/Get-EndAuditAttachmentzoneStatus.ps1)

```powershell
# Get-EndAuditAttachmentzoneStatus.ps1
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
* **Microsoft Security Guidance**: Attachment Manager Architecture and Mark of the Web Security Controls
