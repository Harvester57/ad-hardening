# [REQ-ID-017] Disable Machine Account Quota

## Target Scope
* **Applicable Systems**: Domain Controllers, Domain Environment
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **AD Attribute**: `ms-DS-MachineAccountQuota` (Domain Root object)
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment`
  * **Policy**: `Add workstations to domain`
  * **Registry Location (SecEdit / User Rights Assignment)**: `SeMachineAccountPrivilege`

---

## Rationale
By default, Active Directory grants all authenticated users the ability to add up to 10 computer objects to the domain. This default configuration (defined by the `ms-DS-MachineAccountQuota` attribute on the domain head) poses a severe security risk:

1. **Privilege Escalation & RBCD**: Non-privileged domain users can create rogue computer accounts. An attacker with a compromised domain account can register a computer and use it to exploit Resource-Based Constrained Delegation (RBCD) or Kerberos relayer attacks to escalate privileges to Domain Admin.
2. **Credential Harvesting**: Attackers can use rogue computer accounts to request Kerberos tickets, perform Kerberoasting, or execute AS-REP Roasting attacks on accounts mapped to those computer objects.
3. **Bypass of Network Controls**: Allowing unmanaged, non-compliant, or rogue machines to join the domain increases the overall attack surface and permits unauthorized systems to access internal resources.
4. **Name Squatting**: Unauthorized users can register computer accounts with names matching sensitive or prospective servers, hijacking traffic or interfering with legitimate resource provisioning.

Restricting this behavior by setting `ms-DS-MachineAccountQuota` to 0 and removing `Authenticated Users` from the "Add workstations to domain" user right ensures that only authorized administrators can introduce computer accounts to the directory.

---

## Legacy Impact & Compatibility
* **Workstation Joins**: Standard users will no longer be able to join their own computers to the domain using their standard user accounts. 
* **Automated Provisioning**: Automated deployment tools, OS imaging scripts, or deployment servers (such as MDT or SCCM) that rely on generic domain user accounts to join target systems to the domain will fail.
* **Mitigations**:
  * **Pre-Staging**: Administrators should pre-create the computer account object in the target Organizational Unit (OU) and grant specific domain users or groups (e.g., workstation technicians) permissions to join the computer to the domain (specifically, write validation to change host name, and reset password rights on the pre-created object).
  * **OU Delegation**: Explicitly delegate permissions to create and delete computer objects on specific OUs (e.g., workstations OU) to dedicated IT operations or technician security groups.

---

## Implementation Steps

### Option A: Active Directory Administrative Center & GPMC (Preferred)

#### Step 1: Set ms-DS-MachineAccountQuota to 0
1. Log on to a Domain Controller or administrative host with **Domain Admins** credentials.
2. Open **Active Directory Users and Computers** (`dsa.msc`).
3. Click **View** in the top menu and ensure **Advanced Features** is checked.
4. Right-click the root domain object (e.g., `domain.local`) and select **Properties**.
5. Navigate to the **Attribute Editor** tab.
6. Scroll down to select the **ms-DS-MachineAccountQuota** attribute and click **Edit**.
7. Change the value to **0** and click **OK**.
8. Click **Apply** and then **OK**.

#### Step 2: Restrict 'Add workstations to domain' GPO
1. Open the **Group Policy Management Console** (`gpmc.msc`) on a management host.
2. Edit the **Default Domain Controllers Policy** or another GPO applying to all Domain Controllers.
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment`
4. Locate the policy **Add workstations to domain**.
5. Double-click the policy, check **Define these policy settings**, and ensure that only authorized administrative groups (e.g., `Administrators`) are added. Remove **Authenticated Users**.
6. Click **Apply** and then **OK**.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following scripts to audit and remediate these settings.

#### 1. Local Audit (Audit-MachineAccountQuota.ps1)

[Download Script: Audit-MachineAccountQuota.ps1](audit_scripts/Audit-MachineAccountQuota.ps1)

```powershell
# Audit-MachineAccountQuota.ps1
# Description: Audits the domain-wide machine account quota attribute and local Add workstations to domain user right assignment.

Import-Module ActiveDirectory

Write-Host "--- Auditing Machine Account Quota Settings ---" -ForegroundColor Cyan

# 1. Audit domain-wide ms-DS-MachineAccountQuota
try {
    $Domain = Get-ADDomain -ErrorAction Stop
    $Quota = $Domain.MachineAccountQuota

    if ($Quota -ne 0) {
        Write-Host "VULNERABLE: Domain-wide ms-DS-MachineAccountQuota is set to $($Quota) (should be 0)." -ForegroundColor Red
    } else {
        Write-Host "Status: Compliant. Domain-wide ms-DS-MachineAccountQuota is set to 0." -ForegroundColor Green
    }
} catch {
    Write-Host "VULNERABLE: Could not audit ms-DS-MachineAccountQuota. Error: $($_.Exception.Message)" -ForegroundColor Red
}

# 2. Audit local User Rights Assignment for SeMachineAccountPrivilege
try {
    $SecCfg = "$($env:temp)\auditpolicy.inf"
    secedit /export /cfg $SecCfg /quiet

    if (Test-Path $SecCfg) {
        $cfgContent = Get-Content -Path $SecCfg
        $privilege = $cfgContent | Where-Object { $_ -like "SeMachineAccountPrivilege*" }

        if ($privilege) {
            $parts = $privilege -split "="
            if ($parts.Count -eq 2) {
                $value = $parts[1].Trim()
                if ($value -eq "*S-1-5-32-544") {
                    Write-Host "Status: Compliant. SeMachineAccountPrivilege is restricted to Administrators." -ForegroundColor Green
                } elseif ($value -eq "") {
                    Write-Host "Status: Compliant. SeMachineAccountPrivilege is empty (no one has the privilege)." -ForegroundColor Green
                } else {
                    Write-Host "VULNERABLE: SeMachineAccountPrivilege is assigned to: $($value) (should be restricted to Administrators or empty)." -ForegroundColor Red
                }
            } else {
                Write-Host "VULNERABLE: Could not parse SeMachineAccountPrivilege line: $($privilege)" -ForegroundColor Red
            }
        } else {
            Write-Host "VULNERABLE: SeMachineAccountPrivilege line not defined in exported local policy (defaults to Authenticated Users)." -ForegroundColor Red
        }
        Remove-Item -Path $SecCfg -Force
    } else {
        Write-Host "VULNERABLE: Could not export local security policy database using secedit." -ForegroundColor Red
    }
} catch {
    Write-Host "VULNERABLE: Could not audit SeMachineAccountPrivilege. Error: $($_.Exception.Message)" -ForegroundColor Red
}
```

#### 2. Local Remediation (Set-MachineAccountQuota.ps1)

[Download Script: Set-MachineAccountQuota.ps1](implementation_scripts/Set-MachineAccountQuota.ps1)

```powershell
# Set-MachineAccountQuota.ps1
# Description: Sets the domain-wide machine account quota to 0 and restricts the local Add workstations to domain user right to Administrators.

Import-Module ActiveDirectory

Write-Host "Applying hardening requirement: Disable Machine Account Quota..." -ForegroundColor Cyan

# 1. Remediate domain-wide ms-DS-MachineAccountQuota
try {
    $Domain = Get-ADDomain -ErrorAction Stop
    if ($Domain.MachineAccountQuota -ne 0) {
        Set-ADDomain -Identity $Domain.DistinguishedName -Replace @{ "ms-DS-MachineAccountQuota" = 0 } -ErrorAction Stop
        Write-Host "[+] Domain-wide ms-DS-MachineAccountQuota successfully set to 0." -ForegroundColor Green
    } else {
        Write-Host "[-] Domain-wide ms-DS-MachineAccountQuota is already set to 0." -ForegroundColor Yellow
    }
} catch {
    Write-Error "Failed to set ms-DS-MachineAccountQuota. Error: $($_.Exception.Message)"
}

# 2. Remediate local User Rights Assignment (SeMachineAccountPrivilege)
try {
    $SecDb = "$($env:temp)\localpolicy.sdb"
    $SecCfg = "$($env:temp)\localpolicy.inf"
    
    # Export current security policy
    secedit /export /cfg $SecCfg /quiet
    
    if (Test-Path $SecCfg) {
        $cfgContent = Get-Content -Path $SecCfg
        $newCfg = New-Object System.Collections.Generic.List[string]
        $hasPrivilege = $false
        
        foreach ($line in $cfgContent) {
            if ($line -like "SeMachineAccountPrivilege*") {
                $line = "SeMachineAccountPrivilege = *S-1-5-32-544"
                $hasPrivilege = $true
            }
            $newCfg.Add($line) | Out-Null
        }
        
        if (-not $hasPrivilege) {
            # Add to [Privilege Rights] section
            $privIndex = $newCfg.IndexOf("[Privilege Rights]")
            if ($privIndex -ge 0) {
                $newCfg.Insert($privIndex + 1, "SeMachineAccountPrivilege = *S-1-5-32-544")
            } else {
                # Fallback: append section and value
                $newCfg.Add("[Privilege Rights]") | Out-Null
                $newCfg.Add("SeMachineAccountPrivilege = *S-1-5-32-544") | Out-Null
            }
        }
        
        # Save updated configuration
        $newCfg | Set-Content -Path $SecCfg
        
        # Configure local security policy
        secedit /configure /db $SecDb /cfg $SecCfg /areas USER_RIGHTS /quiet
        
        # Cleanup temporary files
        Remove-Item -Path $SecCfg -Force
        Remove-Item -Path $SecDb -Force
        
        Write-Host "[+] Local User Rights Assignment SeMachineAccountPrivilege successfully restricted to Administrators (*S-1-5-32-544)." -ForegroundColor Green
    } else {
        Write-Error "Failed to export local security policy for remediation."
    }
} catch {
    Write-Error "Failed to configure SeMachineAccountPrivilege. Error: $($_.Exception.Message)"
}
```

---

## Sources & Compliance References
* **ANSSI Active Directory Hardening Guide**: Section 3.1.2 / CERT-FR AD Checklist (vuln_user_accounts_machineaccountquota)
* **CIS Benchmark**: CIS Microsoft Windows Server 2016 Benchmark v2.0.0 - Section 2.2.4 (Add workstations to domain)
* **Microsoft Security Guidance**: Active Directory ms-DS-MachineAccountQuota mitigation guidance
