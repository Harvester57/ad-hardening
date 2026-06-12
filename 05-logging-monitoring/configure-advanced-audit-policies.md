# Hardening Requirement: Configure Advanced Security Audit Policies

## Target Scope
* **Applicable Systems**: Domain Controllers, Member Servers, Tier 2 Client Workstations.
* **Operating Systems**: Windows Server 2016 (and above), Windows 10/11 Enterprise.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **Policy Override**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings` (Value: Enabled)
  * **Advanced Policies**: `Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies`
  * **Registry Location**: `HKLM\System\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy` (Value: 1)

---

## Rationale
Standard Windows event logging is basic and fails to capture critical event vectors, leading to visibility gaps during compromises. Configuring Advanced Security Audit Policies allows precise logging of Success/Failure states for critical areas without overloading local event log storage.

Enforcing advanced auditing policies provides the following security coverages:
1. **Authentication and Credential Security**: Kerberos TGT and TGS ticket requests (Event IDs 4768, 4769, 4770) detect Kerberoasting, Service Ticket abuse, and Silver/Golden ticket operations. Credential Validation (Event ID 4776) identifies NTLM usage and brute-force attempts.
2. **Account and Privilege Monitoring**: Audit User Account Management (Event IDs 4720, 4722, 4724) tracks creation and password resets. Audit Security Group Management (Event IDs 4728, 4732, 4756) detects unauthorized membership changes in highly privileged groups like Domain Admins.
3. **Execution and Directory Access**: Process Creation (Event ID 4688) tracks executing binaries. Directory Service Changes (Event ID 5136) and Directory Service Access (Event ID 4662) log Active Directory object modifications and querying to discover reconnaissance activity.
4. **Logon and Tampering Auditing**: Logon and Special Logon auditing (Event IDs 4624, 4625, 4672) tracks remote access, elevation events, and suspicious logons. Policy Change (Event ID 4719) detects when auditing configurations are disabled or altered by adversaries trying to hide their footprints.

---

## Legacy Impact & Compatibility
* **Event Log Volume**: Enabling these detailed policies will increase log volume. The local Security Event Log size must be sized appropriately (minimum 1GB on Domain Controllers, 512MB on Member Servers and Workstations) to prevent logs from rotating out too quickly.
* **Override Enforcement**: Forcing advanced policies to override legacy settings ensures that older group policies do not accidentally weaken system visibility. Ensure that this GPO setting is applied across all organizational units.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

#### 1. Enforce Advanced Audit Overrides
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Create or edit a GPO linked to the target systems (e.g., `GPO_Hardening_Logging_Baseline`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
4. Configure the setting:
   * **Policy**: `Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings`
   * **Setting**: `Enabled`

#### 2. Configure Advanced Audit Policy Settings
1. In the same GPO, navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies`
2. Configure the following subcategory policies:

| Category | Subcategory | Setting |
| :--- | :--- | :--- |
| **Account Logon** | `Audit Kerberos Authentication Service` | Success and Failure |
| **Account Logon** | `Audit Kerberos Service Ticket Operations` | Success and Failure |
| **Account Logon** | `Audit Credential Validation` | Success and Failure |
| **Account Management** | `Audit User Account Management` | Success and Failure |
| **Account Management** | `Audit Security Group Management` | Success and Failure |
| **Detailed Tracking** | `Audit Process Creation` | Success and Failure |
| **Detailed Tracking** | `Audit PNP Activity` | Success |
| **DS Access** | `Audit Directory Service Changes` | Success and Failure |
| **DS Access** | `Audit Directory Service Access` | Success and Failure |
| **Logon/Logoff** | `Audit Logon` | Success and Failure |
| **Logon/Logoff** | `Audit Special Logon` | Success |
| **Logon/Logoff** | `Audit Account Lockout` | Success and Failure |
| **Logon/Logoff** | `Audit Other Logon/Logoff Events` | Success and Failure |
| **Object Access** | `Audit Detailed File Share` | Failure |
| **Object Access** | `Audit Other Object Access Events` | Success and Failure |
| **Policy Change** | `Audit Policy Change` | Success and Failure |
| **Policy Change** | `Audit Authentication Policy Change` | Success |
| **Policy Change** | `Audit MPSSVC Rule-Level Policy Change` | Success and Failure |
| **Policy Change** | `Audit Other Policy Change Events` | Failure |
| **Privilege Use** | `Audit Sensitive Privilege Use` | Success and Failure |
| **System** | `Audit Other System Events` | Success and Failure |
| **System** | `Audit Security State Change` | Success |
| **System** | `Audit Security System Extension` | Success |
| **System** | `Audit System Integrity` | Success and Failure |

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following scripts locally to query and enforce Advanced Security Audit Policies.

[Download Script: Set-AdvancedAuditPolicies.ps1](implementation_scripts/Set-AdvancedAuditPolicies.ps1)

```powershell
# Set-AdvancedAuditPolicies.ps1
# Configures Advanced Security Audit Policies and registry override values.

Write-Host "--- Applying Advanced Audit Policies Remediation ---" -ForegroundColor Cyan

# 1. Enforce Force Audit Policy Override (SCENoApplyLegacyAuditPolicy = 1)
Write-Host "[+] Enforcing Advanced Audit Policy Registry Override..." -ForegroundColor Gray
$LsaPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
if (-not (Test-Path $LsaPath)) {
    New-Item -Path $LsaPath -Force | Out-Null
}
Set-ItemProperty -Path $LsaPath -Name "SCENoApplyLegacyAuditPolicy" -Value 1 -Type DWord
Write-Host "    Force advanced audit policy override enabled." -ForegroundColor Green

# 2. Configure Advanced Audit Policy subcategories
$Policies = @(
    @{ Subcategory = "Kerberos Authentication Service"; Success = "enable"; Failure = "enable" },
    @{ Subcategory = "Kerberos Service Ticket Operations"; Success = "enable"; Failure = "enable" },
    @{ Subcategory = "Credential Validation"; Success = "enable"; Failure = "enable" },
    @{ Subcategory = "User Account Management"; Success = "enable"; Failure = "enable" },
    @{ Subcategory = "Security Group Management"; Success = "enable"; Failure = "enable" },
    @{ Subcategory = "Process Creation"; Success = "enable"; Failure = "enable" },
    @{ Subcategory = "PNP Activity"; Success = "enable"; Failure = "disable" },
    @{ Subcategory = "Directory Service Changes"; Success = "enable"; Failure = "enable" },
    @{ Subcategory = "Directory Service Access"; Success = "enable"; Failure = "enable" },
    @{ Subcategory = "Logon"; Success = "enable"; Failure = "enable" },
    @{ Subcategory = "Special Logon"; Success = "enable"; Failure = "disable" },
    @{ Subcategory = "Policy Change"; Success = "enable"; Failure = "enable" },
    @{ Subcategory = "Account Lockout"; Success = "enable"; Failure = "enable" },
    @{ Subcategory = "Other Logon/Logoff Events"; Success = "enable"; Failure = "enable" },
    @{ Subcategory = "Detailed File Share"; Success = "disable"; Failure = "enable" },
    @{ Subcategory = "Other Object Access Events"; Success = "enable"; Failure = "enable" },
    @{ Subcategory = "Authentication Policy Change"; Success = "enable"; Failure = "disable" },
    @{ Subcategory = "MPSSVC Rule-Level Policy Change"; Success = "enable"; Failure = "enable" },
    @{ Subcategory = "Other Policy Change Events"; Success = "disable"; Failure = "enable" },
    @{ Subcategory = "Sensitive Privilege Use"; Success = "enable"; Failure = "enable" },
    @{ Subcategory = "Other System Events"; Success = "enable"; Failure = "enable" },
    @{ Subcategory = "Security State Change"; Success = "enable"; Failure = "disable" },
    @{ Subcategory = "Security System Extension"; Success = "enable"; Failure = "disable" },
    @{ Subcategory = "System Integrity"; Success = "enable"; Failure = "enable" }
)

foreach ($P in $Policies) {
    $Sub = $P.Subcategory
    $Succ = $P.Success
    $Fail = $P.Failure
    
    $AuditpolArgs = "/set /subcategory:`"$Sub`" /success:$Succ /failure:$fail"
    $Process = Start-Process auditpol -ArgumentList $AuditpolArgs -Wait -NoNewWindow -PassThru
    if ($Process.ExitCode -eq 0) {
        Write-Host "    Audit policy '$($Sub)' set to Success:$($Succ) / Failure:$($Fail)." -ForegroundColor Green
    } else {
        Write-Error "    Failed to set audit policy for '$($Sub)'. Exit Code: $($Process.ExitCode)"
    }
}

Write-Host "Advanced Audit Policies applied successfully." -ForegroundColor Cyan
```

*To verify the settings have been applied:*

[Download Script: Test-AdvancedAuditPolicies.ps1](audit_scripts/Test-AdvancedAuditPolicies.ps1)

```powershell
# Test-AdvancedAuditPolicies.ps1
# Audits Advanced Audit Policy settings and the force override configuration.

Write-Host "--- Auditing Advanced Security Audit Policies ---" -ForegroundColor Cyan

# 1. Audit Force Audit Policy Override (SCENoApplyLegacyAuditPolicy)
$LsaPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
$OverrideVal = Get-ItemProperty -Path $LsaPath -Name "SCENoApplyLegacyAuditPolicy" -ErrorAction SilentlyContinue
$OverrideSetting = 0
if ($OverrideVal) {
    $OverrideSetting = $OverrideVal.SCENoApplyLegacyAuditPolicy
}

$OverrideColor = "Red"
if ($OverrideSetting -eq 1) {
    $OverrideColor = "Green"
}
Write-Host "    - Force Advanced Audit Policy Override: $($OverrideSetting) (Required = 1)" -ForegroundColor $OverrideColor

# 2. Audit specific subcategories
$RequiredPolicies = @(
    @{ Subcategory = "Kerberos Authentication Service"; Expected = "Success and Failure" },
    @{ Subcategory = "Kerberos Service Ticket Operations"; Expected = "Success and Failure" },
    @{ Subcategory = "Credential Validation"; Expected = "Success and Failure" },
    @{ Subcategory = "User Account Management"; Expected = "Success and Failure" },
    @{ Subcategory = "Security Group Management"; Expected = "Success and Failure" },
    @{ Subcategory = "Process Creation"; Expected = "Success and Failure" },
    @{ Subcategory = "PNP Activity"; Expected = "Success" },
    @{ Subcategory = "Directory Service Changes"; Expected = "Success and Failure" },
    @{ Subcategory = "Directory Service Access"; Expected = "Success and Failure" },
    @{ Subcategory = "Logon"; Expected = "Success and Failure" },
    @{ Subcategory = "Special Logon"; Expected = "Success" },
    @{ Subcategory = "Policy Change"; Expected = "Success and Failure" },
    @{ Subcategory = "Account Lockout"; Expected = "Success and Failure" },
    @{ Subcategory = "Other Logon/Logoff Events"; Expected = "Success and Failure" },
    @{ Subcategory = "Detailed File Share"; Expected = "Failure" },
    @{ Subcategory = "Other Object Access Events"; Expected = "Success and Failure" },
    @{ Subcategory = "Authentication Policy Change"; Expected = "Success" },
    @{ Subcategory = "MPSSVC Rule-Level Policy Change"; Expected = "Success and Failure" },
    @{ Subcategory = "Other Policy Change Events"; Expected = "Failure" },
    @{ Subcategory = "Sensitive Privilege Use"; Expected = "Success and Failure" },
    @{ Subcategory = "Other System Events"; Expected = "Success and Failure" },
    @{ Subcategory = "Security State Change"; Expected = "Success" },
    @{ Subcategory = "Security System Extension"; Expected = "Success" },
    @{ Subcategory = "System Integrity"; Expected = "Success and Failure" }
)

Write-Host "[+] Querying Advanced Security Audit Policies..." -ForegroundColor Yellow

foreach ($Policy in $RequiredPolicies) {
    $Sub = $Policy.Subcategory
    $Exp = $Policy.Expected
    $RawOutput = auditpol.exe /get /subcategory:$Sub /r
    
    # Parse CSV format from auditpol: Machine,Subcategory,GUID,PolicyVal
    $Lines = $RawOutput -split "`r?`n"
    $Found = $false
    foreach ($Line in $Lines) {
        if ($Line -like "*,$Sub,*") {
            $Parts = $Line -split ","
            $Actual = $Parts[3]
            $Found = $true
            
            $IsMatch = $false
            if ($Exp -eq "Success and Failure") {
                if ($Actual -match "Success and Failure" -or $Actual -match "Success & Failure") {
                    $IsMatch = $true
                }
            } else {
                if ($Actual -match $Exp) {
                    $IsMatch = $true
                }
            }
            
            $Color = "Red"
            if ($IsMatch) {
                $Color = "Green"
            }
            Write-Host "    - Subcategory: $($Sub) | Setting: $($Actual) (Expected: $($Exp))" -ForegroundColor $Color
        }
    }
    if (-not $Found) {
        Write-Host "    - Subcategory: $($Sub) | Status: NOT CONFIGURED" -ForegroundColor Red
    }
}
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Recommendation R48 (Audit Policy)
* **CIS Benchmark**: CIS Windows Server 2016 Benchmark v2.0.0 - Section 9 (Audit Policy)
* **Microsoft Security Baseline Focus**: Windows Server and Member Server Audit Policies
