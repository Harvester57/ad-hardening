# [REQ-ID-017] Disable Machine Account Quota

## Target Scope
* **Applicable Systems**: Domain Controllers, Domain Environment
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022, Windows Server 2025

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
By default, Active Directory sets the domain-level attribute `ms-DS-MachineAccountQuota` to **10** on the domain head (`DC=domain,DC=com`) and assigns the `SeMachineAccountPrivilege` ("Add workstations to domain") User Right to the `Authenticated Users` group. This default configuration allows any standard user, compromised domain identity, or unprivileged service account to introduce up to 10 computer objects into the directory.

Active Directory governs computer creation through two distinct mechanisms:
1. **The `ms-DS-MachineAccountQuota` Domain Attribute**: Enforced during direct LDAP/LDAPS operations. Even if local or GPO user rights are restricted, an attacker communicating over LDAP can create computer objects as long as `ms-DS-MachineAccountQuota` is greater than zero.
2. **The `SeMachineAccountPrivilege` User Right Assignment**: Evaluated by the Security Account Manager (SAMR) and NetJoinDomain RPC interfaces when workstations join via standard Windows APIs.

Allowing unprivileged users to create machine accounts introduces critical security risks across multiple Active Directory subsystems:

1. **Privilege Escalation via Resource-Based Constrained Delegation (RBCD)**:
   * **The SPN Prerequisite**: Exploiting Resource-Based Constrained Delegation requires an account configured with a Service Principal Name (SPN). Standard user accounts cannot register an SPN without elevated administrative permissions (the `servicePrincipalName` attribute write is restricted). In contrast, computer accounts automatically receive default SPNs (e.g., `HOST/<computername>`, `RestrictedKrbHost/<computername>`) upon creation, and the creating user is designated as the object's creator/owner (`mS-DS-CreatorSID`), retaining full DACL control.
   * **Coercion and Relaying Vector**: When an attacker coerces authentication from an unconstrained or privileged server (e.g., via PetitPotam, PrinterBug/SpoolSample, DFSCoerce, or ShadowCoerce) and relays that NTLM authentication to LDAP/LDAPS, or when an attacker has write permissions over a target computer's `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute, they configure the victim system to trust the newly created rogue machine account.
   * **Kerberos S4U Abuse**: Using the credentials of the rogue computer account, the attacker executes Kerberos S4U2self (Service-for-User-to-Self) and S4U2proxy protocol extensions to obtain a valid Kerberos service ticket impersonating ANY domain user (including a Domain Admin or Enterprise Admin) to services (CIFS, HTTP, LDAP, WSMAN) on the target host, achieving full host or domain takeover.

2. **Active Directory Certificate Services (ADCS) Exploitation**:
   * **Template Enrollment**: Many enterprise ADCS certificate templates grant enrollment permissions to `Domain Computers` (such as default "Machine" or "Computer" templates, or custom enrollment templates).
   * **Domain Takeover**: If vulnerable certificate templates are present in the environment—such as ESC1 (templates allowing the enrollee to specify a Subject Alternative Name / `ENROLLEE_SUPPLIES_SUBJECT`), ESC2/ESC3 (enrollment agent misuse), ESC6 (`EDITF_ATTRIBUTESUBJECTALTNAME2` enabled on the CA), or ESC13 (certificate templates linked to issuing policies)—an attacker with a rogue computer account can enroll for a machine certificate, supply the SAN of a Domain Controller or privileged administrative account, and immediately escalate to Domain Admin.
   * **Credential Relaying**: A rogue machine account also supplies the computer identity required to participate in ESC8 attacks (relaying coerced machine NTLM authentication to ADCS HTTP Web Enrollment or CES endpoints).

3. **Local Privilege Escalation via Local Kerberos Relaying (KrbRelay / KrbRelayUp)**:
   * On domain-joined Windows endpoints and servers, attack chains such as KrbRelayUp allow local non-administrative users to elevate directly to `NT AUTHORITY\SYSTEM`.
   * The exploit leverages `ms-DS-MachineAccountQuota` to dynamically provision a computer account in Active Directory, configures RBCD against the local machine, triggers a local RPC connection to coerce machine Kerberos authentication, and relays the ticket locally to execute arbitrary code as SYSTEM.

4. **Active Directory Integrated DNS (ADIDNS) Poisoning & WPAD Hijacking**:
   * By default, Active Directory-integrated DNS zones allow authenticated machine accounts to register and dynamically update host (`A`) and reverse (`PTR`) DNS records.
   * Attackers can leverage rogue computer accounts to poison DNS zones, hijack hostnames of anticipated servers, or register `wpad` (Web Proxy Auto-Discovery) records. This allows the attacker to intercept corporate web traffic, harvest NetNTLM credentials, or conduct adversary-in-the-middle (AitM) attacks.

5. **Network Access Control (NAC) & 802.1X Perimeter Bypass**:
   * Many corporate 802.1X wired and wireless network architectures authenticate connecting devices via machine credentials (e.g., PEAP-MSCHAPv2) or machine certificates linked to domain computer accounts.
   * An attacker connected to an untrusted switch port, guest network, or rogue access point can create a machine account, complete 802.1X machine authentication, and gain unrestricted network placement into internal corporate workstation or server VLANs.

6. **Shadow Credentials (`msDS-KeyCredentialLink`) & Evasive Persistence**:
   * Because the creator possesses owner permissions on the newly created machine account, an attacker can write to the `msDS-KeyCredentialLink` attribute to configure public-key credentials (PKINIT). The attacker can then request Kerberos TGTs at will, maintaining persistent directory access without ever modifying the machine's password or triggering password rotation alarms.
   * Machine accounts automatically join the `Domain Computers` global group, granting them persistent ambient access to read Active Directory LDAP partitions, SYSVOL and Netlogon shares, Group Policy Objects, and any internal resources open to domain members.

7. **Historical Precedent: sAMAccountName Spoofing (noPac / CVE-2021-42278 & CVE-2021-42287)**:
   * The noPac exploit demonstrated how unprivileged computer creation is weaponized: attackers created a computer account, stripped the trailing `$`, obtained a TGT, renamed the account to match a Domain Controller, and requested a service ticket via S4U2self to impersonate the DC. While specific CVEs are patched, setting `ms-DS-MachineAccountQuota` to 0 eliminates the fundamental entry point for any future exploit chain that relies on creating arbitrary machine objects.

Restricting this behavior by setting `ms-DS-MachineAccountQuota` to **0** and removing `Authenticated Users` from the `SeMachineAccountPrivilege` ("Add workstations to domain") user right ensures that only authorized administrators and dedicated provisioning systems can introduce computer objects into the directory.

---

## Legacy Impact & Compatibility

* **Self-Service & BYOD Domain Joins Blocked**:
  * Standard domain users will no longer be able to join their own computers, home lab systems, or testing virtual machines to the domain using their standard user accounts.
  * Any user attempting to join a machine via Windows Settings or Control Panel using standard credentials will receive an error: `0x524` (`ERROR_NO_SUCH_LOGON_SESSION`), `ERROR_ACCESS_DENIED` (`5`), or `NERR_MachineAccountQuotaExceeded` (`2691` / `0xA83`).
  * Self-service domain joins must be formally decommissioned in favor of centralized, automated provisioning workflows.

* **Automated Provisioning & Imaging Workflows**:
  * Automated operating system deployment solutions that rely on generic, unprivileged domain credentials to join target systems will fail during the domain-join step.
  * Impacted systems include:
    * **Microsoft Endpoint Configuration Manager (MECM / SCCM)**: OSD Task Sequences using a standard user account in the "Apply Network Settings" or "Join Domain or Workgroup" step.
    * **Microsoft Deployment Toolkit (MDT)**: Deployment shares using join credentials in `CustomSettings.ini`.
    * **Windows Deployment Services (WDS) / PXE**: Unattended setup files (`unattend.xml`) with embedded domain join credentials.
    * **Windows Autopilot**: User-driven Hybrid Azure AD / Entra ID Join flows utilizing the Intune Connector for Active Directory (ODJ).
    * **Virtual Desktop Infrastructure (VDI)**: VMware Horizon / vCenter Guest Customization Specifications, Citrix Machine Creation Services (MCS), and Citrix Provisioning Services (PVS).
    * **Infrastructure-as-Code (IaC) & Automation**: Terraform (`azurerm_virtual_machine_extension` / `windows_virtual_machine`), HashiCorp Packer, Ansible (`ansible.windows.win_domain_membership`), and PowerShell Desired State Configuration (DSC `xComputer`).

* **Heterogeneous & Non-Windows Systems**:
  * Linux distributions joining Active Directory via `realm join` (realmd), SSSD, or Samba (`net ads join`).
  * Unix and macOS enterprise identity brokers (e.g., Centrify / Delinea, Quest Authentication Services / QAS, PBIS Open).
  * Storage appliances (e.g., NetApp ONTAP, Dell EMC PowerStore / Isilon, TrueNAS) joining Active Directory for SMB/NFS multi-protocol shares.
  * All non-Windows joining workflows must use dedicated, delegated service accounts rather than unprivileged user accounts.

* **Critical Compatibility: Netjoin Domain Join Hardening (KB5020276 / CVE-2022-37966 / CVE-2022-38042)**:
  * In response to CVE-2022-37966, Microsoft introduced Netjoin domain join hardening in cumulative updates starting in October 2022 (and enforced in subsequent updates).
  * **Pre-Staging Conflict**: Historically, administrators mitigated `ms-DS-MachineAccountQuota = 0` by manually "pre-staging" (pre-creating) computer accounts in Active Directory and delegating join permissions to technicians or deployment scripts.
  * Under KB5020276, the Netjoin protocol strictly blocks joining or reusing an existing computer account UNLESS:
    1. The identity performing the domain join is the original creator/owner of the computer account (`mS-DS-CreatorSID` matches the joiner's SID), OR
    2. The joining identity is a member of `Domain Admins` or `Enterprise Admins` (which violates Tiering principles and introduces severe credential-exposure risks during mass imaging), OR
    3. The computer account is explicitly exempted via Group Policy: `Domain controller: Allow computer account re-use during domain join` (Netjoin allow list).
  * **The Failure Scenario**: If Senior Administrator A pre-stages the computer account in Active Directory, and Technician B (or deployment account `svc-sccm-join`) attempts to join the machine, the join operation will fail with error `0xa8b` (`2699` - `ERROR_DS_UNWILLING_TO_PERFORM` / `NetpCheckIfAccountShouldBeReused failed`).

* **Recommended Mitigation Architecture: Delegated OU Creation Model**:
  * To resolve both the quota limitation and the KB5020276 account reuse restriction without granting excessive domain privileges:
    1. **Dedicated Tier 2 Join Accounts**: Create dedicated, managed service accounts specifically for domain join operations (e.g., `svc-workstation-join`, `svc-server-join`).
    2. **OU-Level Delegation**: Delegate permissions to create and delete computer objects **only** on specific Organizational Units (e.g., `OU=Workstations,DC=domain,DC=local` or `OU=Member Servers,DC=domain,DC=local`).
    3. **Required Permissions**: Using the Active Directory Delegation of Control Wizard or PowerShell, grant the join account the following permissions on the target OU (scope: *This object and all descendant objects*):
       * `Create Computer Objects` and `Delete Computer Objects`
       * `Reset Password` (on descendant Computer objects)
       * `Read and write Account Restrictions` (on descendant Computer objects)
       * `Validated write to DNS host name` (on descendant Computer objects)
       * `Validated write to service principal name` (on descendant Computer objects)
    4. **Operational Benefit**: Because the delegated deployment account creates the computer object directly in the target OU during the automated join sequence, it is recorded as the object's creator/owner (`mS-DS-CreatorSID`). This avoids KB5020276 reuse blocks entirely and confines computer creation rights strictly to authorized OUs.

* **Interaction with Default Container Redirection**:
  * Disabling `ms-DS-MachineAccountQuota` prevents unprivileged creation in the default `CN=Computers` container. However, to guarantee that any new computer objects created by delegated accounts immediately inherit baseline security Group Policy Objects and accidental deletion protections, this control must be paired with [[REQ-OPS-006] Redirect Default Users and Computers Containers](../06-operations-maintenance/redirect-default-containers.md).

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
* **CIS Benchmark**: CIS Microsoft Windows Server 2016 / 2019 / 2022 Benchmark - Section 2.2.4 (Add workstations to domain)
* **Microsoft Security Guidance**: [Active Directory ms-DS-MachineAccountQuota mitigation guidance](https://learn.microsoft.com/en-us/archive/blogs/russellt/the-machineaccountquota-attribute)
* **Microsoft Support (KB5020276)**: [Netjoin: Domain join hardening changes (CVE-2022-37966)](https://support.microsoft.com/en-us/topic/kb5020276-netjoin-domain-join-hardening-changes-cve-2022-37966-9b8a0184-90c0-4e12-ba80-332918804cf7)
* **MITRE ATT&CK**:
  * [Technique T1136.002 - Create Account: Domain Account](https://attack.mitre.org/techniques/T1136/002/)
  * [Technique T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting](https://attack.mitre.org/techniques/T1558/003/)
  * [Technique T1550.002 - Use Alternate Authentication Material: Pass the Ticket](https://attack.mitre.org/techniques/T1550/002/)
  * [Technique T1078.002 - Valid Accounts: Domain Accounts](https://attack.mitre.org/techniques/T1078/002/)
