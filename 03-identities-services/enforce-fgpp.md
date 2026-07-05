# [REQ-ID-001] Enforce Fine-Grained Password Policies

## Target Scope
* **Applicable Systems**: Domain Controllers
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**: Active Directory System Container: `CN=Password Settings Container,CN=System,DC=[Domain]`

---

## Rationale
Active Directory default domain password policies apply globally to all user accounts. These global policies are often configured with lower complexity and length requirements to avoid overwhelming standard users. However, such settings are inadequate for highly privileged accounts (Tier 0 and Tier 1 administrators), which are primary targets for credential stuffing, brute-force, and offline cracking attacks.

Enforcing Fine-Grained Password Policies (FGPP) via Password Settings Objects (PSOs) allows administrators to apply distinct, highly restrictive password and account lockout policies to specific users or groups. By mandating longer password lengths and stricter lockout thresholds for privileged identities, the domain's defense-in-depth posture is significantly bolstered without affecting standard users.

---

## Legacy Impact & Compatibility
* **Application Compatibility**: Legacy applications, automated scripts, or administrative tools that authenticate using service accounts or administrative credentials might fail if they do not support passwords longer than 14 characters or are hardcoded to fail on password complexity.
* **Pre-remediation Audit**: Before applying the policy to administrative groups, audit administrative accounts to ensure their current passwords comply with the new length requirements, or force a password reset upon applying the PSO.

---

## Implementation Steps

### Option A: Active Directory Administrative Center (ADAC) Configuration (Preferred)

1. Open the **Active Directory Administrative Center** (`dsac.exe`) on a Domain Controller or management server.
2. Switch to the Tree View, select your domain, and navigate to:
   `System\Password Settings Container`
3. Right-click the **Password Settings Container**, select **New**, and then click **Password Settings**.
4. Configure the Password Settings Object (PSO):
   * **Name**: `Tier0-Admin-PSO`
   * **Precedence**: `10`
   * **Enforce minimum password length**: `20`
   * **Password must meet complexity requirements**: Checked
   * **Enforce password history**: `24`
   * **Store password using reversible encryption**: Unchecked
   * **Number of failed logon attempts allowed (lockout threshold)**: `5`
   * **Reset failed logon attempts count after**: `30 minutes`
   * **Account lockout duration**: `30 minutes`
5. Under **Directly Applies To**, click **Add** and select the security group containing your Tier 0 and Tier 1 administrators (e.g., `Grp_Tier0_Admins`).
6. Click **OK** to save and apply the PSO.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script to create and apply the Fine-Grained Password Policy using PowerShell.

[Download Script: Set-AdminPasswordPolicy.ps1](implementation_scripts/Set-AdminPasswordPolicy.ps1)

```powershell
# Set-AdminPasswordPolicy.ps1
# Description: Creates a secure Fine-Grained Password Policy for administrative accounts.

Import-Module ActiveDirectory

Write-Host "Applying hardening requirement: Enforce Fine-Grained Password Policies..." -ForegroundColor Cyan

$AdminPSOName = "Tier0-Admin-PSO"
$ExistingPSO = Get-ADFineGrainedPasswordPolicy -Filter "Name -eq '$AdminPSOName'"

if (-not $ExistingPSO) {
    # Create the Fine-Grained Password Policy (PSO)
    New-ADFineGrainedPasswordPolicy -Name $AdminPSOName `
        -Precedence 10 `
        -ComplexityEnabled $true `
        -MinPasswordLength 20 `
        -PasswordHistoryCount 24 `
        -ReversibleEncryptionEnabled $false `
        -LockoutDuration "00:30:00" `
        -LockoutObservationWindow "00:30:00" `
        -LockoutThreshold 5 `
        -MinPasswordAge "1.00:00:00" `
        -MaxPasswordAge "60.00:00:00"
        
    Write-Host "PSO '$AdminPSOName' created successfully." -ForegroundColor Green
} else {
    Write-Host "PSO '$AdminPSOName' already exists." -ForegroundColor Yellow
}
```

*To verify the applied Fine-Grained Password Policies:*
[Download Script: Get-AdminPasswordPolicyStatus.ps1](audit_scripts/Get-AdminPasswordPolicyStatus.ps1)

```powershell
# Get-AdminPasswordPolicyStatus.ps1
# Description: Audits Fine-Grained Password Policies in the Active Directory domain.

Import-Module ActiveDirectory

Write-Host "--- Auditing Fine-Grained Password Policies ---" -ForegroundColor Cyan

$psoList = Get-ADFineGrainedPasswordPolicy -Filter *

if ($psoList) {
    foreach ($pso in $psoList) {
        Write-Host "[+] PSO Name: $($pso.Name)" -ForegroundColor Green
        Write-Host "    - Precedence: $($pso.Precedence)" -ForegroundColor White
        Write-Host "    - MinPasswordLength: $($pso.MinPasswordLength)" -ForegroundColor White
        Write-Host "    - LockoutThreshold: $($pso.LockoutThreshold)" -ForegroundColor White
        Write-Host "    - LockoutDuration: $($pso.LockoutDuration)" -ForegroundColor White
    }
} else {
    Write-Host "[-] No Fine-Grained Password Policies found in the domain." -ForegroundColor Yellow
}
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Section 3.1 (User Password policies)
* **CIS Benchmark**: CIS Microsoft Windows Server Benchmark - Section 1.1 (Password Policy)
* **Microsoft Security Guidance**: AD DS Fine-Grained Password Policies Step-by-Step Guide
