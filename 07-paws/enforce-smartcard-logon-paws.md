# [REQ-PAW-031] Enforce Smart Card Logon for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) (Tier 0 Workstations)
* **Operating Systems**: Windows 10/11 Enterprise

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Interactive logon: Require smart card` -> **Enabled**
  * **Registry Location**: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` -> `ScForceOption` = `1` (REG_DWORD)

---

## Rationale
Enforcing smart card requirements at the local operating system level on administrative workstations provides vital physical and logical isolation:

1. **Password Logon Interface Block**: Requiring a smart card at logon tells Winlogon to suppress the default username and password fields. This forces the credential provider to only accept certificate-based smart card inserts. An attacker who has somehow acquired a user's password (e.g. via social engineering or physical shoulder surfing) will be unable to log on interactively because the endpoint will not display the password input fields.
2. **Mitigation of Credential Replay Attacks**: Traditional password logons store NTHashes locally in the LSA database or cache, which can be extracted by dumping LSASS memory. By using smart card credentials, the logon process utilizes public-key cryptography (Kerberos PKINIT) where the private key never leaves the secure boundaries of the smart card's hardware security chip.
3. **Session Interruption and Removal Enforcement**: Enforcing smart card logons naturally aligns with the smart card removal behavior requirement. Removing the smart card locks the session, and re-entry is impossible without physically re-inserting the token and inputting the PIN.

---

## Legacy Impact & Compatibility
* **Hard Block for Non-Smart Card Users**: Administrators without active smart cards or security tokens (like YubiKeys) will be completely blocked from logging on to the PAW. Pre-provisioning and certificate enrollment procedures are strict pre-requisites.
* **Safe Mode Exemption**: The local Administrator account is exempt from the smart card requirement only when the system is booted into Safe Mode or using the Recovery Console. In normal operation, local accounts cannot log on interactively if smart cards are enforced.
* **System Component Trust**: Workstations must trust the root and intermediate certification authorities issuing the smart card certificates, requiring active enrollment in domain CA policies.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

To enforce smart card logon on all PAWs via Group Policy:
1. Open the **Group Policy Management Console** (`gpmc.msc`) on a domain controller or administrative host.
2. Edit your dedicated PAW Group Policy Object (e.g., `GPO_Hardening_PAWs`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
4. In the details pane, double-click **Interactive logon: Require smart card**.
5. Select **Enabled** and click **OK**.
6. Ensure the GPO is linked to the PAW Organizational Unit (OU).

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Use these scripts locally on a PAW endpoint to enforce or audit the local smart card requirement.

[Download Script: Set-PAWSmartCardEnforcement.ps1](implementation_scripts/Set-PAWSmartCardEnforcement.ps1)

```powershell
# Set-PAWSmartCardEnforcement.ps1
# Description: Configures the registry to require smart cards for interactive logons on PAWs.
# Target Engine: Windows PowerShell 5.1

Write-Host "Enforcing smart card interactive logon requirement..." -ForegroundColor Cyan

$RegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$ValueName = "ScForceOption"
$ValueData = 1

if (-not (Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
}

Set-ItemProperty -Path $RegPath -Name $ValueName -Value $ValueData -Type DWord -Force
Write-Host "Smart card interactive logon requirement applied successfully." -ForegroundColor Green
```

*To audit the local smart card requirement on PAWs:*

[Download Script: Test-PAWSmartCardEnforcement.ps1](audit_scripts/Test-PAWSmartCardEnforcement.ps1)

```powershell
# Test-PAWSmartCardEnforcement.ps1
# Description: Audits if the registry is configured to require smart cards for interactive logons on PAWs.
# Target Engine: Windows PowerShell 5.1

Write-Host "--- Auditing PAW Smart Card Interactive Logon Requirement ---" -ForegroundColor Cyan

$RegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$ValueName = "ScForceOption"
$ExpectedValue = 1

$Vulnerable = $false

if (Test-Path $RegPath) {
    $Property = Get-ItemProperty -Path $RegPath -Name $ValueName -ErrorAction SilentlyContinue
    if ($null -ne $Property -and $Property.$ValueName -eq $ExpectedValue) {
        Write-Host "    - Registry Setting: $ValueName | Actual: $($Property.$ValueName) (Expected: $ExpectedValue)" -ForegroundColor Green
    } else {
        $actualVal = if ($null -ne $Property) { $Property.$ValueName } else { "Not Found" }
        Write-Host "    - Registry Setting: $ValueName | Actual: $actualVal (Expected: $ExpectedValue)" -ForegroundColor Red
        $Vulnerable = $true
    }
} else {
    Write-Host "    - Registry Path: $RegPath | Actual: Path Not Found (Expected: Path Exists)" -ForegroundColor Red
    $Vulnerable = $true
}

if ($Vulnerable) {
    Write-Host "Audit Result: VULNERABLE" -ForegroundColor Red
    exit 1
} else {
    Write-Host "Audit Result: SECURE" -ForegroundColor Green
    exit 0
}
```

---

## Sources & Compliance References
* **CIS Microsoft Windows 10/11 Client Benchmark**: Section 2.3.9.5 (Interactive logon: Smart card removal behavior) and Section 2.3.9.6 (Interactive logon: Require smart card).
* **ANSSI AD Hardening Guide**: Recommendations on workstation physical and logical isolation, and enforcing multi-factor authentication.
* **Microsoft Security Guidance**: Enforcing multi-factor authentication for high-value hosts.
