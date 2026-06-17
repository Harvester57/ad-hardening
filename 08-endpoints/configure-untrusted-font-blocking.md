# [REQ-END-029] Configure Untrusted Font Blocking

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers.
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional, Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Administrative Templates\System\Mitigation Options\Untrusted Font Blocking`
  * **Registry Location**: `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\MitigationOptions`
    * **Value Name**: `MitigationOptions_FontBocking`
    * **Value Type**: `REG_SZ`
    * **Value Data**: `1000000000000`

---

## Rationale
Font files (TrueType, OpenType, and others) are highly complex formats that require advanced parsing logic. Historically, font parsing in Windows was performed by the Graphics Device Interface (GDI) within the operating system kernel. Vulnerabilities in the kernel-mode font parser (such as buffer overflows or remote code execution) have been frequently exploited by threat actors to execute arbitrary code with kernel-level privileges.

Enabling Untrusted Font Blocking limits the attack surface of the graphics subsystem:
1. **Kernel Attack Surface Reduction**: Restricting the system to only load trusted fonts installed in the `%windir%\Fonts` system directory prevents the processing of malicious, web-delivered, or embedded font files.
2. **Mitigation of Document-Based Exploits**: Prevents malicious font files embedded in Microsoft Office documents, PDFs, or web pages from triggering parsing vulnerabilities in the context of the current user.

---

## Legacy Impact & Compatibility
* **Web Browsers & Web Fonts**: Web browsers (such as Microsoft Edge or Google Chrome) and web applications that dynamically download custom fonts (e.g., Google Fonts, font icon libraries like FontAwesome) may fail to render those fonts, reverting to system default fallback fonts. This may result in styling anomalies or missing icons.
* **Embedded Fonts in Documents**: Microsoft Office files or PDFs utilizing custom embedded fonts that are not locally installed in the system directory will render using default system fonts, potentially affecting layout alignment.
* **Deployment Validation**: It is recommended to deploy this setting in Audit Mode (`3000000000000`) initially to monitor event log entries (Event ID 305 inside the `Microsoft-Windows-Security-Mitigations/KernelMode` log) before fully enforcing the block policy.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`) on a domain controller or management host.
2. Create a new GPO or edit an existing one (e.g., `GPO_Hardening_Endpoints`).
3. Navigate to:
   `Computer Configuration\Policies\Administrative Templates\System\Mitigation Options`
4. Configure the following setting:
   * **Policy**: `Untrusted Font Blocking`
   * **Setting**: `Enabled`
   * **Mitigation Options**: `Block untrusted fonts and log events`
5. Link the GPO to the appropriate Organizational Unit (OU) containing the target client endpoints and member servers.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Use this method to apply the setting locally on standalone systems or during reference image build phases.

[Download Script: Configure-UntrustedFontBlocking.ps1](implementation_scripts/Configure-UntrustedFontBlocking.ps1)

```powershell
# Configure-UntrustedFontBlocking.ps1
# Description: Configures Untrusted Font Blocking mitigation to block untrusted fonts and log events.

$RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\MitigationOptions"
$ValueName = "MitigationOptions_FontBocking"
$ValueData = "1000000000000"

Write-Host "Applying hardening requirement: Configure Untrusted Font Blocking..." -ForegroundColor Cyan

if (-not (Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
}

Set-ItemProperty -Path $RegPath -Name $ValueName -Value $ValueData -Type String -Force | Out-Null
Write-Host "Hardening applied successfully." -ForegroundColor Green
```

*To verify the setting has been applied:*

[Download Script: Get-UntrustedFontBlockingStatus.ps1](audit_scripts/Get-UntrustedFontBlockingStatus.ps1)

```powershell
# Get-UntrustedFontBlockingStatus.ps1
# Description: Checks the current configuration state of Untrusted Font Blocking registry setting.

$RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\MitigationOptions"
$ValueName = "MitigationOptions_FontBocking"
$ExpectedValue = "1000000000000"

Write-Host "Auditing hardening requirement: Configure Untrusted Font Blocking..." -ForegroundColor Cyan

if (Test-Path $RegPath) {
    $value = Get-ItemProperty -Path $RegPath -Name $ValueName -ErrorAction SilentlyContinue
    if ($null -ne $value -and $value.$ValueName -eq $ExpectedValue) {
        Write-Host "Audit Result: Compliant. Untrusted fonts are blocked and logged ($($ValueName) = $($ExpectedValue))." -ForegroundColor Green
        exit 0
    }
}

Write-Host "Audit Result: Non-Compliant. Untrusted fonts are not configured to block and log." -ForegroundColor Red
exit 1
```

---

## Sources & Compliance References
* **Microsoft Learn**: Block untrusted fonts in an enterprise (MitigationOptions registry configurations)
* **CIS Benchmark**: CIS Microsoft Windows Client Benchmark - Section 18.9.30.1 (System Options / Mitigation Options)
