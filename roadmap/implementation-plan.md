# Implementation Plan and Prioritized Roadmap

This document outlines the prioritized implementation plan for Domain Controllers, Endpoints, and Privileged Access Workstations (PAWs). Hardening a production Active Directory environment requires balancing security posture improvements against operational disruption and engineering effort.

To achieve this, all 600+ technical security controls in this guidebook are organized into five sequential phases based on their real-world impact on preventing compromise, ease of implementation, and potential compatibility impact.

---

## Target Scope

* **Domain Controllers**: High-security Windows Server instances hosting directory services (Tier 0).
* **Endpoints**: Standard member client workstations (Tier 2).
* **Privileged Access Workstations (PAWs)**: High-security, isolated administration workstations (Tier 0).
* **Administrative Architecture**: Directory layout, administrative tiering boundaries, and trusts (Tier 0 to Tier 2).
* **Operations & Maintenance**: Backup, disaster recovery, patch shipping, and continuous monitoring procedures.

---

## Phase 0: Architectural Foundation & Administrative Tiering

Architectural choices must be made and established **before** implementing individual host-level hardening measures. Without a secure administrative tiering structure, hardening client hosts or Domain Controllers is easily bypassed. This phase establishes administrative boundaries and prepares the GPO structure.

### Security Posture Impact
* Establishes the three-tier administrative model (Tier 0, Tier 1, Tier 2) to prevent credential exposure from high-privilege domains to lower-security zones.
* Denies administrative logon rights across boundaries to block lateral movement and credential harvesting.
* Secures AD trust relationships to prevent domain containment breaches.

### Architectural Requirements
* **[REQ-ARCH-001 - Implement Active Directory Administrative Tiering Model](../01-architecture/implement-administrative-tiering-model.md)**: Enforces GPO logon restrictions to isolate administrative tiers.
* **[REQ-ARCH-002 - Restrict Administrative Management Protocols](../01-architecture/restrict-mgmt-protocols.md)**: Secures management access paths.
* **[REQ-ARCH-003 - Audit Privileged Groups](../01-architecture/audit-privileged-groups.md)**: Enforces monitoring and strict controls on Tier 0 group memberships.
* **[REQ-ARCH-004 - Keep Domain and Forest Functional Levels Up-To-Date](../01-architecture/keep-functional-levels-up-to-date.md)**: Ensures modern AD security features are active.
* **[REQ-ARCH-005 - Default Domain and Domain Controllers Policies Management](../01-architecture/default-policies-recommendations.md)**: Standardizes GPO hierarchy and separates default policy links.
* **[REQ-ARCH-006 - Harden Active Directory Domain Trusts](../01-architecture/harden-domain-trusts.md)**: Configures secure trust filters and disables SID history routing where appropriate.
* **[REQ-ARCH-007 - Harden Microsoft Exchange Active Directory Permissions](../01-architecture/harden-exchange-permissions.md)**: Removes WriteDacl and WriteOwner permissions for Exchange groups on the domain root.

### Identities & Services Requirements
* **[REQ-ID-010 - Restrict Schema Administrators Group Membership](../03-identities-services/restrict-schema-admins.md)**: Restricts membership of the Schema Administrators group to minimize administrative privilege footprint.
* **[REQ-ID-011 - Enforce Accidental Deletion Protection on Organizational Units](../03-identities-services/prevent-accidental-deletion-ous.md)**: Enables accidental deletion protection on all active Organizational Units to prevent directory data loss.

### Network & Firewall Requirements
* **[REQ-NET-001 - Configure Active Directory Port Matrix](../04-network-firewall/configure-ad-port-matrix.md)**: Standardizes the AD port matrix firewall rules for domain controllers and member servers.

---

## Phase 1: Critical Risk Reduction & Operational Baselines

This phase targets the elimination of immediately exploitable vulnerability classes, including coercive authentication, protocol relaying, name resolution poisoning, default password reuse, and PKI template vulnerabilities. Crucially, it also implements core backup, logging retention, and comprehensive security audit policies to establish telemetry and visibility before deeper hardening parameters are deployed.

### Security Posture Impact
* Enforces backup and restore procedures to protect against fatal misconfigurations or ransomware.
* Blocks coercion techniques (such as PetitPotam or DFSCoerce) that allow attackers to instantly compromise Domain Controllers from standard domain accounts.
* Neutralizes LLMNR/mDNS spoofing (such as Responder attacks) that capture hashes on local network segments.
* Standardizes naming schemas and establishes foundational ADCS and local administrator password management (LAPS).
* Implements advanced security auditing across all host types to guarantee baseline forensic visibility.

### Operations & Maintenance Requirements
* **[REQ-OPS-001 - Enforce KRBTGT Password Rotation](../06-operations-maintenance/enforce-krbtgt-password-rotation.md)**: Implements standard 2-step rotation of the domain key ticket account.
* **[REQ-OPS-002 - Enable and Configure the Active Directory Recycle Bin](../06-operations-maintenance/enable-recycle-bin.md)**: Enforces forest-wide Recycle Bin for rapid recovery of deleted objects.
* **[REQ-OPS-003 - Establish and Maintain Group Policy ADMX Central Store](../06-operations-maintenance/maintain-gpo-templates.md)**: Prevents version drift across consoles.
* **[REQ-OPS-007 - Mandate Naming Conventions for GPOs, OUs, and User Accounts](../06-operations-maintenance/mandate-naming-conventions.md)**: Enforces GPO/OU prefix metadata supporting GPO auditing.
* **[REQ-OPS-008 - Configure Daily System State Backups](../06-operations-maintenance/configure-system-state-backups.md)**: Implements daily AD System State backup, offline/immutable backup isolation, and quarterly recovery drills.
* **[REQ-OPS-013 - Clean Up Staged Install From Media (IFM) Data](../06-operations-maintenance/cleanup-staged-ifm-files.md)**: Deletes temporary ntds.dit datasets immediately after Domain Controller promotions.

### Domain Controller Requirements
* **[REQ-DC-001 - Disable SMBv1](../02-domain-controllers/disable-smbv1.md)**: Disables legacy, vulnerable file sharing protocol drivers.
* **[REQ-DC-002 - Disable Multicast Name Resolution](../02-domain-controllers/disable-multicast-name-resolution.md)**: Prevents LLMNR/mDNS spoofing on DCs.
* **[REQ-DC-003 - Disable NTLMv1](../02-domain-controllers/disable-ntlmv1.md)**: Mitigates weak cryptographic authentication.
* **[REQ-DC-008 - Disable Print Spooler Service](../02-domain-controllers/disable-print-spooler.md)**: Disables spooler to block PrintNightmare and coercion.
* **[REQ-DC-015 - Migrate SYSVOL Replication to DFSR](../02-domain-controllers/migrate-sysvol-replication-dfsr.md)**: Retires legacy FRS replication.
* **[REQ-DC-016 - Harden adminSDHolder Permissions](../02-domain-controllers/harden-adminsdholder-permissions.md)**: Blocks permission changes to high-privilege templates.
* **[REQ-DC-024 - Configure dSHeuristics Attribute](../02-domain-controllers/configure-dsheuristics.md)**: Restricts anonymous directory access.
* **[REQ-DC-030 - Secure Directory Services Restore Mode (DSRM) and Recovery Parameters](../02-domain-controllers/harden-dsrm-recovery-mode.md)**: Configures DsrmAdminLogonBehavior to restrict network logons.
* **[REQ-DC-031 - Configure NTP Time Synchronization on the PDC Emulator](../02-domain-controllers/configure-pdc-time-sync.md)**: Configures w32time parameters and external time sync on the PDC Emulator.
* **[REQ-DC-160 - Configure Event Log Maximum File Sizes and Retention Policies on Domain Controllers](../02-domain-controllers/configure-event-log-sizes.md)**: Configures maximum log sizes and retention behavior for security and system event logs on Domain Controllers.

#### Advanced Audit Policies (Domain Controllers)
*Submodule Overview: [Configure Advanced Security Audit Policies](../05-logging-monitoring/configure-advanced-audit-policies.md)*

* **[REQ-DC-136 - Audit Policy: Advanced Audit Policy Overrides on Domain Controllers](../02-domain-controllers/audit-policy/configure-dc-audit-audit-override.md)**: Audit Policy: Advanced Audit Policy Overrides on Domain Controllers.
* **[REQ-DC-137 - Audit Policy: Account Logon Auditing on Domain Controllers](../02-domain-controllers/audit-policy/configure-dc-audit-account-logon.md)**: Audits account logon events to capture credential validation and authentication anomalies.
* **[REQ-DC-138 - Audit Policy: Account Management Auditing on Domain Controllers](../02-domain-controllers/audit-policy/configure-dc-audit-account-management.md)**: Audits user, group, and computer account modifications and lifecycle events.
* **[REQ-DC-139 - Audit Policy: Detailed Tracking Auditing on Domain Controllers](../02-domain-controllers/audit-policy/configure-dc-audit-detailed-tracking.md)**: Audits detailed process creation, termination, and execution tracking events.
* **[REQ-DC-140 - Audit Policy: Directory Service Access Auditing on Domain Controllers](../02-domain-controllers/audit-policy/configure-dc-audit-ds-access.md)**: Key security telemetry enabled by these subcategories includes:.
* **[REQ-DC-141 - Audit Policy: Logon and Logoff Auditing on Domain Controllers](../02-domain-controllers/audit-policy/configure-dc-audit-logon-logoff.md)**: Audits user logon, logoff, session locks, and interactive or network authentication attempts.
* **[REQ-DC-142 - Audit Policy: Object Access Auditing on Domain Controllers](../02-domain-controllers/audit-policy/configure-dc-audit-object-access.md)**: Audits access and permission changes on files, shares, registry keys, and directory objects.
* **[REQ-DC-143 - Audit Policy: Policy Change Auditing on Domain Controllers](../02-domain-controllers/audit-policy/configure-dc-audit-policy-change.md)**: Audits changes to audit policies, trust relationships, and user rights assignments.
* **[REQ-DC-144 - Audit Policy: Privilege Use Auditing on Domain Controllers](../02-domain-controllers/audit-policy/configure-dc-audit-privilege-use.md)**: Audits the exercise of sensitive user rights and elevated administrative privileges.
* **[REQ-DC-145 - Audit Policy: System Events Auditing on Domain Controllers](../02-domain-controllers/audit-policy/configure-dc-audit-system-events.md)**: Audits security system state changes, subsystem initialization, and security log clearing.

### Identities & Services Requirements
* **[REQ-ID-002 - Enable Local Administrator Password Solution (LAPS)](../03-identities-services/enable-laps.md)**: Implements Windows LAPS or Classic LAPS to rotate local administrator passwords periodically.
* **[REQ-ID-006 - Rename and Disable Default Administrator and Guest Accounts](../03-identities-services/harden-default-accounts.md)**: Disables the default Guest account and renames the default Administrator account.
* **[REQ-ID-015 - Harden Active Directory Certificate Services (ADCS) and PKI](../03-identities-services/harden-adcs-pki.md)**: Hardens Active Directory Certificate Services (ADCS) and PKI templates against privilege escalation.
* **[REQ-ID-020 - Clean Up Legacy Group Policy Preferences and SYSVOL Passwords](../03-identities-services/cleanup-gpp-sysvol-passwords.md)**: Cleans up GPP credentials and insecure scripts from SYSVOL.

### Logging & Monitoring Requirements
* **[REQ-LOG-001 - Configure Advanced Security Audit Policies](../05-logging-monitoring/configure-advanced-audit-policies.md)**: Configures advanced security audit policies to enable comprehensive event logging.
* **[REQ-LOG-002 - Configure PowerShell and Command-Line Auditing](../05-logging-monitoring/configure-powershell-and-command-line-auditing.md)**: Enforces PowerShell script block and command-line process auditing.

### PAW Requirements
* **[REQ-PAW-003 - Restrict Local Administrators Group for PAWs](../07-paws/restrict-local-administrators.md)**: Removes standard users from local administrators.
* **[REQ-PAW-015 - Configure Secure Printing and Print Spooler Policies for PAWs](../07-paws/configure-printing-and-spooler.md)**: Disables print spooler on administrative hosts.
* **[REQ-PAW-019 - Harden Network Parameters and Disable Legacy Name Resolution](../07-paws/harden-network-and-name-resolution.md)**: Disables LLMNR/mDNS and NetBIOS on PAWs.
* **[REQ-PAW-021 - Disable AutoPlay and AutoRun for PAWs](../07-paws/disable-autoplay-autorun.md)**: Stops auto-execution from removable media.

#### Advanced Audit Policies (PAWs)
*Submodule Overview: [Audit Policy Baseline for PAWs](../07-paws/audit-policy/README.md)*

* **[REQ-PAW-130 - Audit Policy: Advanced Audit Policy Overrides for PAWs](../07-paws/audit-policy/configure-paw-audit-audit-override.md)**: Audit Policy: Advanced Audit Policy Overrides for PAWs.
* **[REQ-PAW-131 - Audit Policy: Account Logon Auditing for PAWs](../07-paws/audit-policy/configure-paw-audit-account-logon.md)**: Audits account logon events to capture credential validation and authentication anomalies.
* **[REQ-PAW-132 - Audit Policy: Account Management Auditing for PAWs](../07-paws/audit-policy/configure-paw-audit-account-management.md)**: Audits user, group, and computer account modifications and lifecycle events.
* **[REQ-PAW-133 - Audit Policy: Detailed Tracking Auditing for PAWs](../07-paws/audit-policy/configure-paw-audit-detailed-tracking.md)**: Audits detailed process creation, termination, and execution tracking events.
* **[REQ-PAW-135 - Audit Policy: Logon and Logoff Auditing for PAWs](../07-paws/audit-policy/configure-paw-audit-logon-logoff.md)**: Audits user logon, logoff, session locks, and interactive or network authentication attempts.
* **[REQ-PAW-136 - Audit Policy: Object Access Auditing for PAWs](../07-paws/audit-policy/configure-paw-audit-object-access.md)**: Audits access and permission changes on files, shares, registry keys, and directory objects.
* **[REQ-PAW-137 - Audit Policy: Policy Change Auditing for PAWs](../07-paws/audit-policy/configure-paw-audit-policy-change.md)**: Audits changes to audit policies, trust relationships, and user rights assignments.
* **[REQ-PAW-138 - Audit Policy: Privilege Use Auditing for PAWs](../07-paws/audit-policy/configure-paw-audit-privilege-use.md)**: Audits the exercise of sensitive user rights and elevated administrative privileges.
* **[REQ-PAW-139 - Audit Policy: System Events Auditing for PAWs](../07-paws/audit-policy/configure-paw-audit-system-events.md)**: Audits security system state changes, subsystem initialization, and security log clearing.

### Endpoint Requirements
* **[REQ-END-001 - Harden Network Parameters and Disable Legacy Name Resolution](../08-endpoints/harden-network-and-name-resolution.md)**: Disables local name resolution protocol spoofing.
* **[REQ-END-003 - Disable AutoPlay and AutoRun](../08-endpoints/disable-autoplay-autorun.md)**: Disables automated optical or flash drive execution.
* **[REQ-END-006 - Restrict Local Administrators Group](../08-endpoints/restrict-local-admins.md)**: Enforces administrative segregation and limits local admin rights.
* **[REQ-END-025 - Configure Secure Printing and Print Spooler Policies](../08-endpoints/configure-printing-and-spooler.md)**: Blocks incoming print spooler calls on client hosts.

#### Advanced Audit Policies (Endpoints)
*Submodule Overview: [Audit Policy Baseline for Endpoints](../08-endpoints/audit-policy/README.md)*

* **[REQ-END-141 - Audit Policy: Advanced Audit Policy Overrides for Endpoints](../08-endpoints/audit-policy/configure-end-audit-audit-override.md)**: Audit Policy: Advanced Audit Policy Overrides for Endpoints.
* **[REQ-END-142 - Audit Policy: Account Logon Auditing for Endpoints](../08-endpoints/audit-policy/configure-end-audit-account-logon.md)**: Audits account logon events to capture credential validation and authentication anomalies.
* **[REQ-END-143 - Audit Policy: Account Management Auditing for Endpoints](../08-endpoints/audit-policy/configure-end-audit-account-management.md)**: Audits user, group, and computer account modifications and lifecycle events.
* **[REQ-END-144 - Audit Policy: Detailed Tracking Auditing for Endpoints](../08-endpoints/audit-policy/configure-end-audit-detailed-tracking.md)**: Audits detailed process creation, termination, and execution tracking events.
* **[REQ-END-146 - Audit Policy: Logon and Logoff Auditing for Endpoints](../08-endpoints/audit-policy/configure-end-audit-logon-logoff.md)**: Audits user logon, logoff, session locks, and interactive or network authentication attempts.
* **[REQ-END-147 - Audit Policy: Object Access Auditing for Endpoints](../08-endpoints/audit-policy/configure-end-audit-object-access.md)**: Audits access and permission changes on files, shares, registry keys, and directory objects.
* **[REQ-END-148 - Audit Policy: Policy Change Auditing for Endpoints](../08-endpoints/audit-policy/configure-end-audit-policy-change.md)**: Audits changes to audit policies, trust relationships, and user rights assignments.
* **[REQ-END-149 - Audit Policy: Privilege Use Auditing for Endpoints](../08-endpoints/audit-policy/configure-end-audit-privilege-use.md)**: Audits the exercise of sensitive user rights and elevated administrative privileges.
* **[REQ-END-150 - Audit Policy: System Events Auditing for Endpoints](../08-endpoints/audit-policy/configure-end-audit-system-events.md)**: Audits security system state changes, subsystem initialization, and security log clearing.

---

## Phase 2: Credential & Session Isolation (High Impact)

This phase focuses on isolating credentials inside memory and network packets to block credential dumping tools (like Mimikatz) and session hijacking. It also integrates isolated update deployment mechanisms, restricts Kerberos delegations, secures network authentication protocols, enforces account lockout policies, and implements robust service account policies.

### Security Posture Impact
* Enforces network cryptographic integrity via SMB signing and LDAP channel binding, stopping man-in-the-middle relays.
* Protects the Local Security Authority Subsystem Service (LSASS) process from debugging and memory reading via LSA Protection, Credential Guard, and ASR.
* Redirects default directory containers to ensure new objects receive security policies automatically.
* Restricts Kerberos delegation and deploys fine-grained password and service account policies.
* Enforces strict account lockout thresholds and password complexity across all tiers.

### Operations & Maintenance Requirements
* **[REQ-OPS-005 - Configure Dedicated WSUS for Tier 0](../06-operations-maintenance/configure-dedicated-tier0-wsus.md)**: Secures dedicated patch servers to prevent cross-tier update spoofing.
* **[REQ-OPS-006 - Redirect Default Users and Computers Containers](../06-operations-maintenance/redirect-default-containers.md)**: Prevents newly joined machines from staying in unmanaged default OUs.
* **[REQ-OPS-009 - Implement Offline Patch Management via WSUS](../06-operations-maintenance/implement-offline-patch-management.md)**: Implements offline WSUS metadata imports/exports (sneakernet transport).
* **[REQ-OPS-012 - Implement Automated Inactive Computer and User Account Cleanup](../06-operations-maintenance/decommission-inactive-accounts.md)**: Disables and moves inactive user (180 days) and computer (90 days) accounts to a stale OU.

### Domain Controller Requirements
* **[REQ-DC-004 - Enforce LDAP Server Signing](../02-domain-controllers/enforce-ldap-signing.md)**: Restricts cleartext un-signed LDAP operations.
* **[REQ-DC-005 - Enforce LDAP Channel Binding](../02-domain-controllers/enforce-ldap-channel-binding.md)**: Enforces channel binding for LDAP over SSL.
* **[REQ-DC-006 - Enable LSA Protection](../02-domain-controllers/enable-lsa-protection.md)**: Enables Protected Process Light (PPL) for LSASS.
* **[REQ-DC-007 - Disable Credential Guard](../02-domain-controllers/disable-credential-guard.md)**: Disables Credential Guard on DCs while maintaining VBS configurations to maintain compatibility.
* **[REQ-DC-009 - Enforce SMB Message Signing](../02-domain-controllers/enforce-smb-signing.md)**: Mandates SMB signing to block NTLM relaying.
* **[REQ-DC-011 - Restrict Remote SAM API Access](../02-domain-controllers/restrict-ntds-sam-api.md)**: Restricts remote account listing.
* **[REQ-DC-019 - Enforce RDP Restricted Admin Mode](../02-domain-controllers/enforce-rdp-restricted-admin.md)**: Stops administrative credential caching during RDP.
* **[REQ-DC-025 - Configure Security Options for Domain Controllers](../02-domain-controllers/configure-security-options.md)**: Locks anonymous pipe access and credential parameters.
* **[REQ-DC-032 - Enable UEFI Secure Boot](../02-domain-controllers/enable-secure-boot.md)**: Requirement to enforce hardware-rooted platform integrity checks, verifying that UEFI Secure Boot is active on Domain Controllers.
* **[REQ-DC-099 - ASR: Block credential stealing from the Windows local security authority subsystem on Domain Controllers](../02-domain-controllers/defender/asr/block-lsass-credential-stealing.md)**: Enforces Attack Surface Reduction (ASR) rule to block credential stealing attempts from LSASS memory on Domain Controllers.
* **[REQ-DC-159 - Disable Windows Script Host and Remap Scripting Extensions on Domain Controllers](../02-domain-controllers/disable-windows-script-host.md)**: Configures Virtualization-Based Security (VBS) on Domain Controllers to provide hardware-isolated security features.

### Identities & Services Requirements
* **[REQ-ID-001 - Enforce Fine-Grained Password Policies](../03-identities-services/enforce-fgpp.md)**: Enforces password complexity, length, and lockout policies using Fine-Grained Password Policies.
* **[REQ-ID-003 - Implement Group Managed Service Accounts (gMSA)](../03-identities-services/harden-service-accounts.md)**: Deploys group Managed Service Accounts (gMSAs) to automate password management for services.
* **[REQ-ID-004 - Restrict Kerberos Delegation](../03-identities-services/restrict-kerberos-delegation.md)**: Restricts Kerberos delegation configurations to prevent delegation and relay-to-delegation attacks.
* **[REQ-ID-005 - Configure and Populate Protected Users Group](../03-identities-services/configure-protected-users-group.md)**: Configures the Protected Users security group to restrict credential caching and weak delegation.
* **[REQ-ID-007 - Restrict Interactive Logons for Service Accounts](../03-identities-services/restrict-service-account-logons.md)**: Blocks interactive and remote logons for service accounts using GPO user rights assignments.
* **[REQ-ID-009 - Enforce Kerberos Pre-Authentication](../03-identities-services/enforce-kerberos-preauthentication.md)**: Configures accounts to mandate Kerberos pre-authentication, mitigating offline AS-REP roasting.
* **[REQ-ID-013 - Clean Up adminCount Attribute Orphans](../03-identities-services/cleanup-admincount-orphans.md)**: Cleans up the adminCount attribute on non-privileged accounts to prevent administrative ACL persistence.
* **[REQ-ID-014 - Renew KDS Root Keys and gMSA Secrets](../03-identities-services/renew-kds-keys-gmsa-secrets.md)**: Automatically renews KDS root keys and gMSA secrets to maintain cryptographic validity.
* **[REQ-ID-018 - Restrict Pre-Windows 2000 Compatible Access Group](../03-identities-services/restrict-pre-windows-2000-compatible-access-group.md)**: Restricts the Pre-Windows 2000 Compatible Access group to block anonymous directory listings.

### Network & Firewall Requirements
* **[REQ-NET-007 - Enforce SMBv3 Security and Digitally Sign/Encrypt Communications](../04-network-firewall/enforce-smbv3-security.md)**: Enforces SMBv3 security parameters, including message signing and encryption.
* **[REQ-NET-009 - Configure Hardened UNC Paths and LDAP Client Signing](../04-network-firewall/configure-hardened-unc-paths.md)**: Hardens UNC paths (UNC Hardening) and mandates LDAP client signing parameters.

### Logging & Monitoring Requirements
* **[REQ-LOG-003 - Deploy and Harden Microsoft Sysmon](../05-logging-monitoring/deploy-and-harden-sysmon.md)**: Deploys and hardens Microsoft Sysmon to detect advanced host-based anomalies.
* **[REQ-LOG-004 - Configure Secure SIEM Log Shipping](../05-logging-monitoring/configure-siem-log-shipping.md)**: Enforces secure, encrypted SIEM log shipping for central log correlation.
* **[REQ-LOG-005 - Configure Kerberoasting Honeypots and SIEM Detection Rules](../05-logging-monitoring/implement-kerberoasting-honeypot.md)**: Configures decoy accounts and SIEM alerts to capture Kerberoasting attacks.
* **[REQ-LOG-006 - Configure SYSVOL Decoy XML Honeypot](../05-logging-monitoring/implement-sysvol-honeypot.md)**: Deploys a decoy GPO XML file with Deny access rules to detect active credential harvesting scans.

### PAW Requirements
* **[REQ-PAW-002 - Enable LSA Protection for PAWs](../07-paws/enable-lsa-protection.md)**: Blocks LSASS memory reading on PAWs.
* **[REQ-PAW-010 - Enable VBS and Credential Guard for PAWs](../07-paws/enable-vbs-credential-guard.md)**: Uses hypervisor isolation to protect administrative tokens.
* **[REQ-PAW-020 - Configure User Account Control Policies for PAWs](../07-paws/configure-uac-policies.md)**: Configures UAC secure prompt restrictions.
* **[REQ-PAW-030 - Enable UEFI Secure Boot for PAWs](../07-paws/enable-secure-boot.md)**: Mandates hardware-rooted platform integrity checks, verifying that UEFI Secure Boot is active on the operating system for PAWs.
* **[REQ-PAW-031 - Enforce Smart Card Logon for PAWs](../07-paws/enforce-smartcard-logon-paws.md)**: Requires hardware-backed administrative logon.
* **[REQ-PAW-079 - ASR: Block credential stealing from the Windows local security authority subsystem for PAWs](../07-paws/defender/asr/block-lsass-credential-stealing.md)**: Enforces Attack Surface Reduction (ASR) rule to block credential stealing attempts from LSASS memory on PAWs.

#### Account and Password Policies (PAWs)
*Submodule Overview: [Account Policies for PAWs](../07-paws/configure-account-policies.md)*

* **[REQ-PAW-152 - Account Policy: Password Policy for PAWs](../07-paws/account-policy/configure-paw-account-password-policy.md)**: Enforces strict password complexity, minimum length, and password history parameters.
* **[REQ-PAW-153 - Account Policy: Account Lockout Policy for PAWs](../07-paws/account-policy/configure-paw-account-lockout-policy.md)**: Configures account lockout threshold, duration, and reset counters to defend against brute-force attacks.
* **[REQ-PAW-154 - Account Policy: Kerberos Policy for PAWs](../07-paws/account-policy/configure-paw-account-kerberos-policy.md)**: Enforces Kerberos ticket lifetime and clock synchronization tolerance parameters.
* **[REQ-PAW-155 - Account Policy: Smart Card Removal Behavior for PAWs](../07-paws/account-policy/configure-paw-account-smart-card-removal.md)**: Configures smart card removal behavior to automatically lock the workstation upon card extraction.
* **[REQ-PAW-156 - Account Policy: Cached Logons and PBKDF2 Iteration Count for PAWs](../07-paws/account-policy/configure-paw-account-cached-logons.md)**: Restricts cached domain logon credentials and enforces elevated PBKDF2 iteration count.
* **[REQ-PAW-157 - Account Policy: Local Accounts and Blank Password Restrictions for PAWs](../07-paws/account-policy/configure-paw-account-local-blank-passwords.md)**: Enforces strict password complexity, minimum length, and password history parameters.
* **[REQ-PAW-158 - Account Policy: NTLM and LAN Manager Authentication Security for PAWs](../07-paws/account-policy/configure-paw-account-ntlm-security.md)**: Account Policy: NTLM and LAN Manager Authentication Security for PAWs.
* **[REQ-PAW-159 - Account Policy: Disable WDigest Credential Caching for PAWs](../07-paws/account-policy/configure-paw-account-wdigest-credentials.md)**: Disables WDigest authentication to prevent plaintext credential caching in LSASS memory.
* **[REQ-PAW-160 - Account Policy: Windows Hello for Business and PIN Complexity for PAWs](../07-paws/account-policy/configure-paw-account-hello-pin.md)**: Modern credential protection relies on hardware-bound asymmetric cryptographic tokens rather than reusable passwords.
* **[REQ-PAW-161 - Account Policy: Consumer Microsoft Account Restrictions for PAWs](../07-paws/account-policy/configure-paw-account-block-msa.md)**: Privileged Access Workstations serve as the dedicated management plane for Active Directory Domain Controllers, Tier 0 PKI, and identity federation infrastructure.
* **[REQ-PAW-162 - Account Policy: Domain Member Secure Channel Security for PAWs](../07-paws/account-policy/configure-paw-account-secure-channel.md)**: The Netlogon Remote Protocol (MS-NRPC) secure channel forms the cryptographic communication link between domain-joined workstations and Active Directory Domain Controllers.
* **[REQ-PAW-163 - Account Policy: SMB Client and Server Security Options for PAWs](../07-paws/account-policy/configure-paw-account-smb-security.md)**: The Server Message Block (SMB) protocol is utilized extensively for administrative file transfers, Group Policy retrieval, and remote management.
* **[REQ-PAW-164 - Account Policy: Anonymous Access and Enumeration Restrictions for PAWs](../07-paws/account-policy/configure-paw-account-anonymous-restrictions.md)**: Account Policy: Anonymous Access and Enumeration Restrictions for PAWs.
* **[REQ-PAW-165 - Account Policy: Interactive Logon Security Options for PAWs](../07-paws/account-policy/configure-paw-account-interactive-logon.md)**: Interactive logon controls establish the initial verification boundary between the physical user, hardware input devices, and the Windows kernel.

### Endpoint Requirements
* **[REQ-END-002 - Configure User Account Control Policies](../08-endpoints/configure-uac-policies.md)**: Restricts local administrator prompt behavior.
* **[REQ-END-009 - Enable UEFI Secure Boot](../08-endpoints/enable-secure-boot.md)**: Mandates hardware-rooted platform integrity checks, verifying that UEFI Secure Boot is active on the operating system.
* **[REQ-END-010 - Enable VBS and Credential Guard](../08-endpoints/enable-vbs-credential-guard.md)**: Isolates LSASS secrets on Tier 2 endpoints.
* **[REQ-END-023 - Enable LSA Protection with UEFI Lock](../08-endpoints/enable-lsa-protection.md)**: Locks LSASS protection with UEFI firmware configuration.
* **[REQ-END-083 - ASR: Block credential stealing from the Windows local security authority subsystem](../08-endpoints/defender/asr/block-lsass-credential-stealing.md)**: Enforces Attack Surface Reduction (ASR) rule to block credential stealing attempts from LSASS memory on Endpoints.

#### Account and Password Policies (Endpoints)
*Submodule Overview: [Account Policies for Endpoints](../08-endpoints/configure-account-policies.md)*

* **[REQ-END-163 - Account Policy: Password Policy for Endpoints](../08-endpoints/account-policy/configure-end-account-password-policy.md)**: Enforces strict password complexity, minimum length, and password history parameters.
* **[REQ-END-164 - Account Policy: Account Lockout Policy for Endpoints](../08-endpoints/account-policy/configure-end-account-lockout-policy.md)**: Configures account lockout threshold, duration, and reset counters to defend against brute-force attacks.
* **[REQ-END-165 - Account Policy: Kerberos Policy for Endpoints](../08-endpoints/account-policy/configure-end-account-kerberos-policy.md)**: Enforces Kerberos ticket lifetime and clock synchronization tolerance parameters.
* **[REQ-END-166 - Account Policy: Smart Card Removal Behavior for Endpoints](../08-endpoints/account-policy/configure-end-account-smart-card-removal.md)**: Configures smart card removal behavior to automatically lock the workstation upon card extraction.
* **[REQ-END-167 - Account Policy: Cached Logons and PBKDF2 Iteration Count for Endpoints](../08-endpoints/account-policy/configure-end-account-cached-logons.md)**: Restricts cached domain logon credentials and enforces elevated PBKDF2 iteration count.
* **[REQ-END-168 - Account Policy: Local Accounts and Blank Password Restrictions for Endpoints](../08-endpoints/account-policy/configure-end-account-local-blank-passwords.md)**: Enforces strict password complexity, minimum length, and password history parameters.
* **[REQ-END-169 - Account Policy: NTLM and LAN Manager Authentication Security for Endpoints](../08-endpoints/account-policy/configure-end-account-ntlm-security.md)**: Account Policy: NTLM and LAN Manager Authentication Security for Endpoints.
* **[REQ-END-170 - Account Policy: Disable WDigest Credential Caching for Endpoints](../08-endpoints/account-policy/configure-end-account-wdigest-credentials.md)**: Disables WDigest authentication to prevent plaintext credential caching in LSASS memory.
* **[REQ-END-171 - Account Policy: Windows Hello for Business and PIN Complexity for Endpoints](../08-endpoints/account-policy/configure-end-account-hello-pin.md)**: Account Policy: Windows Hello for Business and PIN Complexity for Endpoints.
* **[REQ-END-172 - Account Policy: Consumer Microsoft Account Restrictions for Endpoints](../08-endpoints/account-policy/configure-end-account-block-msa.md)**: Account Policy: Consumer Microsoft Account Restrictions for Endpoints.
* **[REQ-END-173 - Account Policy: Domain Member Secure Channel Security for Endpoints](../08-endpoints/account-policy/configure-end-account-secure-channel.md)**: Account Policy: Domain Member Secure Channel Security for Endpoints.
* **[REQ-END-174 - Account Policy: SMB Client and Server Security Options for Endpoints](../08-endpoints/account-policy/configure-end-account-smb-security.md)**: The Server Message Block (SMB) protocol is integral to enterprise file sharing, administrative automation, and printer sharing.
* **[REQ-END-175 - Account Policy: Anonymous Access and Enumeration Restrictions for Endpoints](../08-endpoints/account-policy/configure-end-account-anonymous-restrictions.md)**: Account Policy: Anonymous Access and Enumeration Restrictions for Endpoints.
* **[REQ-END-176 - Account Policy: Interactive Logon Security Options for Endpoints](../08-endpoints/account-policy/configure-end-account-interactive-logon.md)**: Interactive logon configurations govern how users authenticate at the physical console or remote desktop interface.

---

## Phase 3: Tiering & Hardware-Rooted Protections (Strategic)

This phase establishes the physical boundaries, hardware-based trust mechanisms, and deep tiering segmentations that form the foundations of Tier 0 administrative workstations (PAWs), secure Domain Controller hosts, and network isolation.

### Security Posture Impact
* Assures that administrative systems cannot be modified by offline attacks (via BitLocker and firmware locks).
* Ensures the boot sequence is verified from a hardware trust anchor (TPM 2.0, ELAM, Secure Boot revocations).
* Cryptographically isolates tiers on the network using IPsec domain isolation.
* Enforces smart card requirements for administrative accounts.
* Restricts user rights assignments to eliminate privileged token abuses and unauthorized system capabilities.

### Domain Controller Requirements
* **[REQ-DC-010 - Restrict Kerberos Encryption Types](../02-domain-controllers/restrict-kerberos-encryption.md)**: Enforces AES-only encryption for Kerberos.
* **[REQ-DC-017 - Harden Microsoft DNS AD Container Permissions](../02-domain-controllers/harden-dns-container-permissions.md)**: Prevents server-level DNS hijack DLLs.
* **[REQ-DC-018 - Harden Virtualization Hosts for Domain Controllers](../02-domain-controllers/harden-dc-virtualization-hosts.md)**: Places virtualized domain controllers inside a secure Tier 0 host boundary.
* **[REQ-DC-033 - Configure Secure Boot Revocations and Bootloader Updates](../02-domain-controllers/configure-secure-boot-revocations.md)**: Requirement to configure and enforce BlackLotus revocation updates and bootloader integrity verification policy variables in system firmware.
* **[REQ-DC-156 - Configure Early Launch Antimalware (ELAM) Policy on Domain Controllers](../02-domain-controllers/configure-elam.md)**: Configures Early Launch Antimalware (ELAM) policy to ensure boot-start drivers are validated by antimalware before initialization.
* **[REQ-DC-157 - UEFI Firmware Security Hardening on Domain Controllers](../02-domain-controllers/configure-uefi-security.md)**: Enforces UEFI firmware security configurations, administrator passwords, and boot integrity locks on Domain Controllers.
* **[REQ-DC-158 - Harden DMA and Physical Security for Domain Controllers](../02-domain-controllers/harden-dma-and-physical-security.md)**: Hardens DMA peripherals and physical bus access to prevent Direct Memory Access attacks against Domain Controllers.

#### User Rights Assignments (Domain Controllers)
*Submodule Overview: [Configure User Rights Assignments for Domain Controllers](../02-domain-controllers/configure-user-rights-assignments.md)*

* **[REQ-DC-104 - Configure User Rights: Access this computer from the network on Domain Controllers](../02-domain-controllers/user-rights/configure-ura-senetworklogonright.md)**: Restricts the Access this computer from the network user right assignment to authorized administrative principals.
* **[REQ-DC-105 - Configure User Rights: Act as part of the operating system on Domain Controllers](../02-domain-controllers/user-rights/configure-ura-setcbprivilege.md)**: The SeTcbPrivilege identifies its holder as part of the Trusted Computer Base (TCB)—the core inner ring of the operating system.
* **[REQ-DC-106 - Configure User Rights: Add workstations to domain on Domain Controllers](../02-domain-controllers/user-rights/configure-ura-semachineaccountprivilege.md)**: Restricts the Add workstations to domain user right assignment to authorized administrative principals.
* **[REQ-DC-107 - Configure User Rights: Adjust memory quotas for a process on Domain Controllers](../02-domain-controllers/user-rights/configure-ura-seincreasequotaprivilege.md)**: Restricts the Adjust memory quotas user right assignment to authorized administrative principals.
* **[REQ-DC-108 - Configure User Rights: Allow log on locally on Domain Controllers](../02-domain-controllers/user-rights/configure-ura-seinteractivelogonright.md)**: Restricts the Allow log user right assignment to authorized administrative principals.
* **[REQ-DC-109 - Configure User Rights: Allow log on through Remote Desktop Services on Domain Controllers](../02-domain-controllers/user-rights/configure-ura-seremoteinteractivelogonright.md)**: Restricts the Allow log user right assignment to authorized administrative principals.
* **[REQ-DC-110 - Configure User Rights: Back up files and directories on Domain Controllers](../02-domain-controllers/user-rights/configure-ura-sebackupprivilege.md)**: Restricts the Back up files and directories user right assignment to authorized administrative principals.
* **[REQ-DC-111 - Configure User Rights: Bypass traverse checking on Domain Controllers](../02-domain-controllers/user-rights/configure-ura-sechangenotifyprivilege.md)**: Restricts the Bypass traverse checking user right assignment to authorized administrative principals.
* **[REQ-DC-112 - Configure User Rights: Change the system time on Domain Controllers](../02-domain-controllers/user-rights/configure-ura-sesystemtimeprivilege.md)**: The SeSystemtimePrivilege allows a security principal to adjust the internal hardware clock and system time of the computer via Win32 APIs SetSystemTime or SetLocalTime.
* **[REQ-DC-113 - Configure User Rights: Create a pagefile on Domain Controllers](../02-domain-controllers/user-rights/configure-ura-secreatepagefileprivilege.md)**: Restricts the Create a pagefile user right assignment to authorized administrative principals.
* **[REQ-DC-114 - Configure User Rights: Create a token object on Domain Controllers](../02-domain-controllers/user-rights/configure-ura-secreatetokenprivilege.md)**: The SeCreateTokenPrivilege allows a process to invoke the native API NtCreateToken to forge an arbitrary Windows primary or impersonation access token from scratch.
* **[REQ-DC-115 - Configure User Rights: Create permanent shared objects on Domain Controllers](../02-domain-controllers/user-rights/configure-ura-secreatepermanentprivilege.md)**: Restricts the Create permanent shared objects user right assignment to authorized administrative principals.
* **[REQ-DC-116 - Configure User Rights: Debug programs on Domain Controllers](../02-domain-controllers/user-rights/configure-ura-sedebugprivilege.md)**: Restricts the Debug programs user right assignment to authorized administrative principals.
* **[REQ-DC-117 - Configure User Rights: Deny access to this computer from the network on Domain Controllers](../02-domain-controllers/user-rights/configure-ura-sedenynetworklogonright.md)**: The SeDenyNetworkLogonRight explicitly prevents specified security principals from authenticating over network protocols (SMB, RPC, WMI, WinRM, LDAP, etc.
* **[REQ-DC-118 - Configure User Rights: Deny log on as a batch job on Domain Controllers](../02-domain-controllers/user-rights/configure-ura-sedenybatchlogonright.md)**: The SeDenyBatchLogonRight explicitly denies designated security principals the ability to authenticate and run batch or scheduled workloads (Logon Type 4).
* **[REQ-DC-119 - Configure User Rights: Deny log on as a service on Domain Controllers](../02-domain-controllers/user-rights/configure-ura-sedenyservicelogonright.md)**: The SeDenyServiceLogonRight explicitly prevents designated accounts from registering and executing as a Windows service process (Logon Type 5).
* **[REQ-DC-120 - Configure User Rights: Deny log on locally on Domain Controllers](../02-domain-controllers/user-rights/configure-ura-sedenyinteractivelogonright.md)**: Restricts the Deny log user right assignment to authorized administrative principals.
* **[REQ-DC-121 - Configure User Rights: Deny log on through Remote Desktop Services on Domain Controllers](../02-domain-controllers/user-rights/configure-ura-sedenyremoteinteractivelogonright.md)**: The SeDenyRemoteInteractiveLogonRight explicitly denies designated accounts the ability to establish Remote Desktop Protocol (RDP) sessions (Logon Type 10) on the target system.
* **[REQ-DC-122 - Configure User Rights: Enable computer and user accounts to be trusted for delegation on Domain Controllers](../02-domain-controllers/user-rights/configure-ura-seenabledelegationprivilege.md)**: Restricts the Enable computer and user accounts to be trusted user right assignment to authorized administrative principals.
* **[REQ-DC-123 - Configure User Rights: Force shutdown from a remote system on Domain Controllers](../02-domain-controllers/user-rights/configure-ura-seremoteshutdownprivilege.md)**: Restricts the Force shutdown from a remote system user right assignment to authorized administrative principals.
* **[REQ-DC-124 - Configure User Rights: Generate security audits on Domain Controllers](../02-domain-controllers/user-rights/configure-ura-seauditprivilege.md)**: Restricts the Generate security audits user right assignment to authorized administrative principals.
* **[REQ-DC-125 - Configure User Rights: Load and unload device drivers on Domain Controllers](../02-domain-controllers/user-rights/configure-ura-seloaddriverprivilege.md)**: Restricts the Load and unload device drivers user right assignment to authorized administrative principals.
* **[REQ-DC-126 - Configure User Rights: Lock pages in memory on Domain Controllers](../02-domain-controllers/user-rights/configure-ura-selockmemoryprivilege.md)**: Restricts the Lock pages in memory user right assignment to authorized administrative principals.
* **[REQ-DC-127 - Configure User Rights: Log on as a batch job on Domain Controllers](../02-domain-controllers/user-rights/configure-ura-sebatchlogonright.md)**: The SeBatchLogonRight determines which security principals can authenticate and establish non-interactive batch logon sessions (Logon Type 4).
* **[REQ-DC-128 - Configure User Rights: Log on as a service on Domain Controllers](../02-domain-controllers/user-rights/configure-ura-seservicelogonright.md)**: The SeServiceLogonRight determines which security principals are permitted to register and authenticate as background Windows service accounts (Logon Type 5).
* **[REQ-DC-129 - Configure User Rights: Manage auditing and security log on Domain Controllers](../02-domain-controllers/user-rights/configure-ura-sesecurityprivilege.md)**: Restricts the Manage auditing and security log user right assignment to authorized administrative principals.
* **[REQ-DC-130 - Configure User Rights: Modify firmware environment values on Domain Controllers](../02-domain-controllers/user-rights/configure-ura-sesystemenvironmentprivilege.md)**: Restricts the Modify firmware environment values user right assignment to authorized administrative principals.
* **[REQ-DC-131 - Configure User Rights: Profile single process on Domain Controllers](../02-domain-controllers/user-rights/configure-ura-seprofilesingleprocessprivilege.md)**: The SeProfileSingleProcessPrivilege allows a process to monitor and profile the performance and execution metrics of non-system processes using Windows performance sampling APIs.
* **[REQ-DC-132 - Configure User Rights: Restore files and directories on Domain Controllers](../02-domain-controllers/user-rights/configure-ura-serestoreprivilege.md)**: The SeRestorePrivilege grants the caller the capability to bypass all write-access security controls (DACLs) across the entire NTFS filesystem and Windows Registry.
* **[REQ-DC-133 - Configure User Rights: Shut down the system on Domain Controllers](../02-domain-controllers/user-rights/configure-ura-seshutdownprivilege.md)**: Restricts the Shut down the system user right assignment to authorized administrative principals.
* **[REQ-DC-134 - Configure User Rights: Synchronize directory service data on Domain Controllers](../02-domain-controllers/user-rights/configure-ura-sesyncagentprivilege.md)**: The SeSyncAgentPrivilege grants the caller the authority to initiate directory synchronization operations against Active Directory domain partitions.
* **[REQ-DC-135 - Configure User Rights: Take ownership of files or other objects on Domain Controllers](../02-domain-controllers/user-rights/configure-ura-setakeownershipprivilege.md)**: Restricts the Take ownership of files or other objects user right assignment to authorized administrative principals.

### Identities & Services Requirements
* **[REQ-ID-008 - Enforce User and Service Account Kerberos Encryption (AES-Only)](../03-identities-services/enforce-user-aes-encryption.md)**: Restricts user and service account Kerberos encryption to AES-only, disabling weak DES/RC4.
* **[REQ-ID-012 - Configure Active Directory Authentication Silos and Policies](../03-identities-services/configure-authentication-silos.md)**: Establishes Authentication Silos and Policies to isolate Tier 0 administrative account sessions.
* **[REQ-ID-016 - Configure Logon Screen and Credentials Delegation](../03-identities-services/configure-credential-delegation.md)**: Disables credential delegation and configures logon screen security parameters.
* **[REQ-ID-019 - Enforce Smart Card Authentication for Privileged Users](../03-identities-services/enforce-smartcard-privileged-users.md)**: Mandates smart card logon requirements for administrative accounts to enforce hardware-based MFA.

### Network & Firewall Requirements
* **[REQ-NET-003 - Configure Workstation and Server Isolation](../04-network-firewall/configure-workstation-isolation.md)**: Segregates workstations and member servers to prevent peer-to-peer lateral movement.
* **[REQ-NET-004 - Configure IPsec Domain Isolation](../04-network-firewall/configure-ipsec-domain-isolation.md)**: Enforces IPsec-based domain isolation to cryptographically segment administrative tiers.
* **[REQ-NET-005 - Harden IPsec Cryptographic Configurations](../04-network-firewall/harden-ipsec-cryptography.md)**: Hardens IPsec cryptographic algorithms and parameters to ensure network integrity.

### PAW Requirements
* **[REQ-PAW-004 - Enforce BitLocker with TPM and Startup PIN for PAWs](../07-paws/enable-bitlocker.md)**: Demands BitLocker with a pre-boot startup PIN.
* **[REQ-PAW-005 - UEFI Firmware Security Hardening](../07-paws/configure-uefi-security.md)**: Implements strong UEFI passwords and locks the boot order.
* **[REQ-PAW-006 - Enable Hardware Virtualization and DMA Protection](../07-paws/enable-hardware-virtualization-and-dma-protection.md)**: Configures IOMMU and virtualization flags.
* **[REQ-PAW-011 - Harden DMA and Physical Security for PAWs](../07-paws/harden-dma-and-physical-security.md)**: Blocks sleep states and limits external bus operations.
* **[REQ-PAW-014 - Configure Early Launch Antimalware (ELAM) Policy for PAWs](../07-paws/configure-elam.md)**: Validates boot driver signatures.
* **[REQ-PAW-022 - Disable Incoming Remote Desktop Access for PAWs](../07-paws/restrict-rdp-access.md)**: Blocks remote lateral logins to administrative devices.
* **[REQ-PAW-035 - Configure Secure Boot Revocations and Bootloader Updates for PAWs](../07-paws/configure-secure-boot-revocations.md)**: Configures and enforces BlackLotus revocation updates and bootloader integrity verification policy variables in system firmware for PAWs.

#### User Rights Assignments (PAWs)
*Submodule Overview: [Configure User Rights Assignments for PAWs](../07-paws/configure-user-rights-assignments.md)*

* **[REQ-PAW-092 - Configure User Rights: Access Credential Manager as a trusted caller for PAWs](../07-paws/user-rights/configure-ura-setrustedcredmanaccessprivilege.md)**: The SeTrustedCredManAccessPrivilege allows a process to access the Windows Credential Manager as a trusted caller via internal Credential Manager APIs.
* **[REQ-PAW-093 - Configure User Rights: Access this computer from the network for PAWs](../07-paws/user-rights/configure-ura-senetworklogonright.md)**: Restricts the Access this computer from the network user right assignment to authorized administrative principals.
* **[REQ-PAW-094 - Configure User Rights: Act as part of the operating system for PAWs](../07-paws/user-rights/configure-ura-setcbprivilege.md)**: The SeTcbPrivilege identifies its holder as part of the Trusted Computer Base (TCB)—the core inner ring of the operating system.
* **[REQ-PAW-095 - Configure User Rights: Allow log on locally for PAWs](../07-paws/user-rights/configure-ura-seinteractivelogonright.md)**: Restricts the Allow log user right assignment to authorized administrative principals.
* **[REQ-PAW-096 - Configure User Rights: Back up files and directories for PAWs](../07-paws/user-rights/configure-ura-sebackupprivilege.md)**: Restricts the Back up files and directories user right assignment to authorized administrative principals.
* **[REQ-PAW-097 - Configure User Rights: Create a pagefile for PAWs](../07-paws/user-rights/configure-ura-secreatepagefileprivilege.md)**: Restricts the Create a pagefile user right assignment to authorized administrative principals.
* **[REQ-PAW-098 - Configure User Rights: Create a token object for PAWs](../07-paws/user-rights/configure-ura-secreatetokenprivilege.md)**: The SeCreateTokenPrivilege allows a process to invoke the native API NtCreateToken to forge an arbitrary Windows primary or impersonation access token from scratch.
* **[REQ-PAW-099 - Configure User Rights: Create global objects for PAWs](../07-paws/user-rights/configure-ura-secreateglobalprivilege.md)**: Restricts the Create global objects user right assignment to authorized administrative principals.
* **[REQ-PAW-100 - Configure User Rights: Create permanent shared objects for PAWs](../07-paws/user-rights/configure-ura-secreatepermanentprivilege.md)**: Restricts the Create permanent shared objects user right assignment to authorized administrative principals.
* **[REQ-PAW-101 - Configure User Rights: Debug programs for PAWs](../07-paws/user-rights/configure-ura-sedebugprivilege.md)**: Restricts the Debug programs user right assignment to authorized administrative principals.
* **[REQ-PAW-102 - Configure User Rights: Enable computer and user accounts to be trusted for delegation for PAWs](../07-paws/user-rights/configure-ura-seenabledelegationprivilege.md)**: Restricts the Enable computer and user accounts to be trusted user right assignment to authorized administrative principals.
* **[REQ-PAW-103 - Configure User Rights: Force shutdown from a remote system for PAWs](../07-paws/user-rights/configure-ura-seremoteshutdownprivilege.md)**: Restricts the Force shutdown from a remote system user right assignment to authorized administrative principals.
* **[REQ-PAW-104 - Configure User Rights: Impersonate a client after authentication for PAWs](../07-paws/user-rights/configure-ura-seimpersonateprivilege.md)**: Restricts the Impersonate a client after authentication user right assignment to authorized administrative principals.
* **[REQ-PAW-105 - Configure User Rights: Load and unload device drivers for PAWs](../07-paws/user-rights/configure-ura-seloaddriverprivilege.md)**: Restricts the Load and unload device drivers user right assignment to authorized administrative principals.
* **[REQ-PAW-106 - Configure User Rights: Lock pages in memory for PAWs](../07-paws/user-rights/configure-ura-selockmemoryprivilege.md)**: Restricts the Lock pages in memory user right assignment to authorized administrative principals.
* **[REQ-PAW-107 - Configure User Rights: Manage auditing and security log for PAWs](../07-paws/user-rights/configure-ura-sesecurityprivilege.md)**: Restricts the Manage auditing and security log user right assignment to authorized administrative principals.
* **[REQ-PAW-108 - Configure User Rights: Modify firmware environment values for PAWs](../07-paws/user-rights/configure-ura-sesystemenvironmentprivilege.md)**: Restricts the Modify firmware environment values user right assignment to authorized administrative principals.
* **[REQ-PAW-109 - Configure User Rights: Perform volume maintenance tasks for PAWs](../07-paws/user-rights/configure-ura-semanagevolumeprivilege.md)**: Restricts the Perform volume maintenance tasks user right assignment to authorized administrative principals.
* **[REQ-PAW-110 - Configure User Rights: Profile single process for PAWs](../07-paws/user-rights/configure-ura-seprofilesingleprocessprivilege.md)**: The SeProfileSingleProcessPrivilege allows a process to monitor and profile the performance and execution metrics of non-system processes using Windows performance sampling APIs.
* **[REQ-PAW-111 - Configure User Rights: Restore files and directories for PAWs](../07-paws/user-rights/configure-ura-serestoreprivilege.md)**: The SeRestorePrivilege grants the caller the capability to bypass all write-access security controls (DACLs) across the entire NTFS filesystem and Windows Registry.
* **[REQ-PAW-112 - Configure User Rights: Take ownership of files or other objects for PAWs](../07-paws/user-rights/configure-ura-setakeownershipprivilege.md)**: Restricts the Take ownership of files or other objects user right assignment to authorized administrative principals.
* **[REQ-PAW-113 - Configure User Rights: Deny access to this computer from the network for PAWs](../07-paws/user-rights/configure-ura-sedenynetworklogonright.md)**: The SeDenyNetworkLogonRight explicitly prevents specified security principals from authenticating over network protocols (SMB, RPC, WMI, WinRM, LDAP, etc.
* **[REQ-PAW-114 - Configure User Rights: Deny log on through Remote Desktop Services for PAWs](../07-paws/user-rights/configure-ura-sedenyremoteinteractivelogonright.md)**: The SeDenyRemoteInteractiveLogonRight explicitly denies designated accounts the ability to establish Remote Desktop Protocol (RDP) sessions (Logon Type 10) on the target system.

### Endpoint Requirements
* **[REQ-END-005 - Restrict Remote Desktop Access](../08-endpoints/restrict-rdp-access.md)**: Prevents incoming RDP connections.
* **[REQ-END-012 - Enable BitLocker and Network Unlock](../08-endpoints/enable-bitlocker.md)**: Protects client data storage using BitLocker.
* **[REQ-END-013 - UEFI Firmware Security Hardening](../08-endpoints/configure-uefi-security.md)**: Secures UEFI parameters on client workstations.
* **[REQ-END-014 - Enable Hardware Virtualization and DMA Protection](../08-endpoints/enable-hardware-virtualization-and-dma-protection.md)**: Enables hardware VBS requisites.
* **[REQ-END-017 - Harden DMA and Physical Security](../08-endpoints/harden-dma-and-physical-security.md)**: Disables client standby states and limits DMA peripherals.
* **[REQ-END-028 - Configure Early Launch Antimalware (ELAM) Policy](../08-endpoints/configure-elam.md)**: Verifies driver startup list.
* **[REQ-END-035 - Configure Secure Boot Revocations and Bootloader Updates](../08-endpoints/configure-secure-boot-revocations.md)**: Configures and enforces BlackLotus revocation updates and bootloader integrity verification policy variables in system firmware.

#### User Rights Assignments (Endpoints)
*Submodule Overview: [Configure User Rights Assignments for Endpoints](../08-endpoints/configure-user-rights-assignments.md)*

* **[REQ-END-096 - Configure User Rights: Access Credential Manager as a trusted caller](../08-endpoints/user-rights/configure-ura-setrustedcredmanaccessprivilege.md)**: The SeTrustedCredManAccessPrivilege allows a process to access the Windows Credential Manager as a trusted caller via internal Credential Manager APIs.
* **[REQ-END-097 - Configure User Rights: Access this computer from the network](../08-endpoints/user-rights/configure-ura-senetworklogonright.md)**: Restricts the Access this computer from the network user right assignment to authorized administrative principals.
* **[REQ-END-098 - Configure User Rights: Act as part of the operating system](../08-endpoints/user-rights/configure-ura-setcbprivilege.md)**: The SeTcbPrivilege identifies its holder as part of the Trusted Computer Base (TCB)—the core inner ring of the operating system.
* **[REQ-END-099 - Configure User Rights: Allow log on locally](../08-endpoints/user-rights/configure-ura-seinteractivelogonright.md)**: Restricts the Allow log user right assignment to authorized administrative principals.
* **[REQ-END-100 - Configure User Rights: Back up files and directories](../08-endpoints/user-rights/configure-ura-sebackupprivilege.md)**: Restricts the Back up files and directories user right assignment to authorized administrative principals.
* **[REQ-END-101 - Configure User Rights: Change the system time](../08-endpoints/user-rights/configure-ura-sesystemtimeprivilege.md)**: The SeSystemtimePrivilege allows a security principal to adjust the internal hardware clock and system time of the computer via Win32 APIs SetSystemTime or SetLocalTime.
* **[REQ-END-102 - Configure User Rights: Change the time zone](../08-endpoints/user-rights/configure-ura-setimezoneprivilege.md)**: The SeTimeZonePrivilege controls the capability to change the system local time zone setting via SetTimeZoneInformation.
* **[REQ-END-103 - Configure User Rights: Create a pagefile](../08-endpoints/user-rights/configure-ura-secreatepagefileprivilege.md)**: Restricts the Create a pagefile user right assignment to authorized administrative principals.
* **[REQ-END-104 - Configure User Rights: Create a token object](../08-endpoints/user-rights/configure-ura-secreatetokenprivilege.md)**: The SeCreateTokenPrivilege allows a process to invoke the native API NtCreateToken to forge an arbitrary Windows primary or impersonation access token from scratch.
* **[REQ-END-105 - Configure User Rights: Create global objects](../08-endpoints/user-rights/configure-ura-secreateglobalprivilege.md)**: Restricts the Create global objects user right assignment to authorized administrative principals.
* **[REQ-END-106 - Configure User Rights: Create permanent shared objects](../08-endpoints/user-rights/configure-ura-secreatepermanentprivilege.md)**: Restricts the Create permanent shared objects user right assignment to authorized administrative principals.
* **[REQ-END-107 - Configure User Rights: Create symbolic links](../08-endpoints/user-rights/configure-ura-secreatesymboliclinkprivilege.md)**: The SeCreateSymbolicLinkPrivilege controls the ability to create filesystem symbolic links (symlinks) via CreateSymbolicLink or mklink.
* **[REQ-END-108 - Configure User Rights: Debug programs](../08-endpoints/user-rights/configure-ura-sedebugprivilege.md)**: Restricts the Debug programs user right assignment to authorized administrative principals.
* **[REQ-END-109 - Configure User Rights: Enable computer and user accounts to be trusted for delegation](../08-endpoints/user-rights/configure-ura-seenabledelegationprivilege.md)**: Restricts the Enable computer and user accounts to be trusted user right assignment to authorized administrative principals.
* **[REQ-END-110 - Configure User Rights: Force shutdown from a remote system](../08-endpoints/user-rights/configure-ura-seremoteshutdownprivilege.md)**: Restricts the Force shutdown from a remote system user right assignment to authorized administrative principals.
* **[REQ-END-111 - Configure User Rights: Impersonate a client after authentication](../08-endpoints/user-rights/configure-ura-seimpersonateprivilege.md)**: Restricts the Impersonate a client after authentication user right assignment to authorized administrative principals.
* **[REQ-END-112 - Configure User Rights: Increase scheduling priority](../08-endpoints/user-rights/configure-ura-seincreasebasepriorityprivilege.md)**: The SeIncreaseBasePriorityPrivilege allows a process to raise the execution priority class of a process or thread via SetPriorityClass to REALTIME_PRIORITY_CLASS.
* **[REQ-END-113 - Configure User Rights: Load and unload device drivers](../08-endpoints/user-rights/configure-ura-seloaddriverprivilege.md)**: Restricts the Load and unload device drivers user right assignment to authorized administrative principals.
* **[REQ-END-114 - Configure User Rights: Lock pages in memory](../08-endpoints/user-rights/configure-ura-selockmemoryprivilege.md)**: Restricts the Lock pages in memory user right assignment to authorized administrative principals.
* **[REQ-END-115 - Configure User Rights: Manage auditing and security log](../08-endpoints/user-rights/configure-ura-sesecurityprivilege.md)**: Restricts the Manage auditing and security log user right assignment to authorized administrative principals.
* **[REQ-END-116 - Configure User Rights: Modify firmware environment values](../08-endpoints/user-rights/configure-ura-sesystemenvironmentprivilege.md)**: Restricts the Modify firmware environment values user right assignment to authorized administrative principals.
* **[REQ-END-117 - Configure User Rights: Perform volume maintenance tasks](../08-endpoints/user-rights/configure-ura-semanagevolumeprivilege.md)**: Restricts the Perform volume maintenance tasks user right assignment to authorized administrative principals.
* **[REQ-END-118 - Configure User Rights: Profile single process](../08-endpoints/user-rights/configure-ura-seprofilesingleprocessprivilege.md)**: The SeProfileSingleProcessPrivilege allows a process to monitor and profile the performance and execution metrics of non-system processes using Windows performance sampling APIs.
* **[REQ-END-119 - Configure User Rights: Profile system performance](../08-endpoints/user-rights/configure-ura-sesystemprofileprivilege.md)**: Restricts the Profile system performance user right assignment to authorized administrative principals.
* **[REQ-END-120 - Configure User Rights: Replace a process level token](../08-endpoints/user-rights/configure-ura-seassignprimarytokenprivilege.md)**: Restricts the Replace a process level token user right assignment to authorized administrative principals.
* **[REQ-END-121 - Configure User Rights: Restore files and directories](../08-endpoints/user-rights/configure-ura-serestoreprivilege.md)**: The SeRestorePrivilege grants the caller the capability to bypass all write-access security controls (DACLs) across the entire NTFS filesystem and Windows Registry.
* **[REQ-END-122 - Configure User Rights: Take ownership of files or other objects](../08-endpoints/user-rights/configure-ura-setakeownershipprivilege.md)**: Restricts the Take ownership of files or other objects user right assignment to authorized administrative principals.
* **[REQ-END-123 - Configure User Rights: Modify an object label](../08-endpoints/user-rights/configure-ura-serelabelprivilege.md)**: The SeRelabelPrivilege controls the ability to modify the Mandatory Integrity Control (MIC) label of securable objects via SetKernelObjectSecurity or SetNamedSecurityInfo.
* **[REQ-END-124 - Configure User Rights: Deny access to this computer from the network](../08-endpoints/user-rights/configure-ura-sedenynetworklogonright.md)**: The SeDenyNetworkLogonRight explicitly prevents specified security principals from authenticating over network protocols (SMB, RPC, WMI, WinRM, LDAP, etc.
* **[REQ-END-125 - Configure User Rights: Deny log on through Remote Desktop Services](../08-endpoints/user-rights/configure-ura-sedenyremoteinteractivelogonright.md)**: The SeDenyRemoteInteractiveLogonRight explicitly denies designated accounts the ability to establish Remote Desktop Protocol (RDP) sessions (Logon Type 10) on the target system.

---

## Phase 4: Advanced Restrictions & Fine-Tuning (Continuous Hardening)

This phase introduces strict operational controls, software restrictions (AppLocker/WDAC), Windows Defender baseline and Attack Surface Reduction (ASR) rules, system services minimization, user profile hardening, and administrative templates. Additionally, continuous offline assessment loops are established to audit security controls on an ongoing basis.

### Security Posture Impact
* Prevents the execution of unauthorized binaries, scripts, or malicious installers via application blocklists/allowlists.
* Restricts system executables (`svchost.exe`) from loading arbitrary non-Microsoft binaries.
* Enforces comprehensive Microsoft Defender Antivirus settings and Attack Surface Reduction rules.
* Disables non-essential background system services across all operating system profiles.
* Audits Active Directory configurations monthly via offline scanners.

### Operations & Maintenance Requirements
* **[REQ-OPS-004 - Implement Third-Party and Custom GPO Templates for COTS Hardening](../06-operations-maintenance/use-third-party-templates.md)**: Standardizes security settings for custom application baselines.
* **[REQ-OPS-010 - Establish Continuous Security Assessments](../06-operations-maintenance/establish-continuous-security-assessments.md)**: Integrates monthly PingCastle scans, quarterly BloodHound analyses, and semi-annual offline database checks.
* **[REQ-OPS-011 - Enable Detailed BSOD Stop Parameters for Crash Control](../06-operations-maintenance/enable-detailed-bsod-parameters.md)**: Enables detailed crash diagnostics for air-gapped system recovery.

### Domain Controller Requirements
* **[REQ-DC-013 - Enable Kerberos Armoring](../02-domain-controllers/enable-kerberos-armoring.md)**: Protects pre-authentication traffic using FAST.
* **[REQ-DC-014 - Restrict NTLM](../02-domain-controllers/restrict-ntlm.md)**: Restricts NTLM protocol fallback domain-wide.
* **[REQ-DC-021 - Configure AppLocker Policies on Domain Controllers](../02-domain-controllers/configure-applocker-policies.md)**: Controls binary execution on DCs.
* **[REQ-DC-022 - Enable WDAC Driver Blocklist](../02-domain-controllers/enable-wdac-driver-blocklist.md)**: Blocks known vulnerable drivers.
* **[REQ-DC-027 - Configure Telemetry, Diagnostics and Privacy Options for Domain Controllers](../02-domain-controllers/configure-telemetry-privacy.md)**: Limits diagnostics collection.
* **[REQ-DC-028 - Configure Untrusted Font Blocking for Domain Controllers](../02-domain-controllers/configure-untrusted-font-blocking.md)**: Protects kernel font parser.
* **[REQ-DC-029 - Configure svchost.exe Mitigation Options](../02-domain-controllers/configure-svchost-mitigation.md)**: Limits svchost sub-process execution.
* **[REQ-DC-034 - Configure Windows Defender Application Control](../02-domain-controllers/configure-wdac.md)**: Deploys code integrity rules.

#### System Services Hardening (Domain Controllers)
*Submodule Overview: [Disable Unnecessary Services on Domain Controllers](../02-domain-controllers/disable-unnecessary-services.md)*

* **[REQ-DC-035 - Disable Xbox Live Auth Manager on Domain Controllers (XblAuthManager)](../02-domain-controllers/services/disable-xblauthmanager.md)**: Disables the XblAuthManager service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-DC-036 - Disable Xbox Live Game Save on Domain Controllers (XblGameSave)](../02-domain-controllers/services/disable-xblgamesave.md)**: Disables the XblGameSave service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-DC-037 - Disable ActiveX Installer (AxInstSV) on Domain Controllers (AxInstSV)](../02-domain-controllers/services/disable-axinstsv.md)**: Disables the AxInstSV service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-DC-038 - Disable Bluetooth Support Service on Domain Controllers (bthserv)](../02-domain-controllers/services/disable-bthserv.md)**: Disables the bthserv service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-DC-039 - Disable Connected Devices Platform User Service on Domain Controllers (CDPUserSvc)](../02-domain-controllers/services/disable-cdpusersvc.md)**: Disables the CDPUserSvc service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-DC-040 - Disable Contact Data on Domain Controllers (PimIndexMaintenanceSvc)](../02-domain-controllers/services/disable-pimindexmaintenancesvc.md)**: Disables the PimIndexMaintenanceSvc service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-DC-041 - Disable WAP Push Message Routing Service on Domain Controllers (dmwappushservice)](../02-domain-controllers/services/disable-dmwappushservice.md)**: Disables the dmwappushservice service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-DC-042 - Disable Downloaded Maps Manager on Domain Controllers (MapsBroker)](../02-domain-controllers/services/disable-mapsbroker.md)**: Disables the MapsBroker service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-DC-043 - Disable Geolocation Service on Domain Controllers (lfsvc)](../02-domain-controllers/services/disable-lfsvc.md)**: Disables the lfsvc service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-DC-044 - Disable Internet Connection Sharing (ICS) on Domain Controllers (SharedAccess)](../02-domain-controllers/services/disable-sharedaccess.md)**: Disables the ICS service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-DC-045 - Disable Link-Layer Topology Discovery Mapper on Domain Controllers (lltdsvc)](../02-domain-controllers/services/disable-lltdsvc.md)**: Disables the lltdsvc service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-DC-046 - Disable Microsoft Account Sign-in Assistant on Domain Controllers (wlidsvc)](../02-domain-controllers/services/disable-wlidsvc.md)**: Disables the wlidsvc service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-DC-047 - Disable Microsoft Passport on Domain Controllers (NgcSvc)](../02-domain-controllers/services/disable-ngcsvc.md)**: Disables the NgcSvc service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-DC-048 - Disable Microsoft Passport Container on Domain Controllers (NgcCtnrSvc)](../02-domain-controllers/services/disable-ngcctnrsvc.md)**: Disables the NgcCtnrSvc service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-DC-049 - Disable Network Connection Broker on Domain Controllers (NcbService)](../02-domain-controllers/services/disable-ncbservice.md)**: Disables the NcbService service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-DC-050 - Disable Phone Service on Domain Controllers (PhoneSvc)](../02-domain-controllers/services/disable-phonesvc.md)**: Disables the PhoneSvc service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-DC-051 - Disable Printer Extensions and Notifications on Domain Controllers (PrintNotify)](../02-domain-controllers/services/disable-printnotify.md)**: Disables the PrintNotify service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-DC-052 - Disable Program Compatibility Assistant Service on Domain Controllers (PcaSvc)](../02-domain-controllers/services/disable-pcasvc.md)**: Disables the PcaSvc service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-DC-053 - Disable Quality Windows Audio Video Experience on Domain Controllers (QWAVE)](../02-domain-controllers/services/disable-qwave.md)**: Disables the QWAVE service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-DC-054 - Disable Radio Management Service on Domain Controllers (RmSvc)](../02-domain-controllers/services/disable-rmsvc.md)**: Disables the RmSvc service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-DC-055 - Disable Sensor Data Service on Domain Controllers (SensorDataService)](../02-domain-controllers/services/disable-sensordataservice.md)**: Disables the SensorDataService service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-DC-056 - Disable Sensor Monitoring Service on Domain Controllers (SensrSvc)](../02-domain-controllers/services/disable-sensrsvc.md)**: Disables the SensrSvc service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-DC-057 - Disable Sensor Service on Domain Controllers (SensorService)](../02-domain-controllers/services/disable-sensorservice.md)**: Disables the SensorService service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-DC-058 - Disable Shell Hardware Detection on Domain Controllers (ShellHWDetection)](../02-domain-controllers/services/disable-shellhwdetection.md)**: Disables the ShellHWDetection service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-DC-059 - Disable Smart Card Device Enumeration Service on Domain Controllers (ScDeviceEnum)](../02-domain-controllers/services/disable-scdeviceenum.md)**: Disables the ScDeviceEnum service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-DC-060 - Disable SSDP Discovery on Domain Controllers (SSDPSRV)](../02-domain-controllers/services/disable-ssdpsrv.md)**: Disables the SSDPSRV service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-DC-061 - Disable Still Image Acquisition Events on Domain Controllers (WiaRpc)](../02-domain-controllers/services/disable-wiarpc.md)**: Disables the WiaRpc service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-DC-062 - Disable Sync Host on Domain Controllers (OneSyncSvc)](../02-domain-controllers/services/disable-onesyncsvc.md)**: Disables the OneSyncSvc service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-DC-063 - Disable UPnP Device Host on Domain Controllers (upnphost)](../02-domain-controllers/services/disable-upnphost.md)**: Disables the upnphost service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-DC-064 - Disable User Data Access on Domain Controllers (UserDataSvc)](../02-domain-controllers/services/disable-userdatasvc.md)**: Disables the UserDataSvc service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-DC-065 - Disable User Data Storage on Domain Controllers (UnistoreSvc)](../02-domain-controllers/services/disable-unistoresvc.md)**: Disables the UnistoreSvc service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-DC-066 - Disable WalletService on Domain Controllers (WalletService)](../02-domain-controllers/services/disable-walletservice.md)**: Disables the WalletService service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-DC-067 - Disable Windows Audio on Domain Controllers (Audiosrv)](../02-domain-controllers/services/disable-audiosrv.md)**: Disables the Audiosrv service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-DC-068 - Disable Windows Audio Endpoint Builder on Domain Controllers (AudioEndpointBuilder)](../02-domain-controllers/services/disable-audioendpointbuilder.md)**: Disables the AudioEndpointBuilder service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-DC-069 - Disable Windows Camera Frame Server on Domain Controllers (FrameServer)](../02-domain-controllers/services/disable-frameserver.md)**: Disables the FrameServer service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-DC-070 - Disable Windows Image Acquisition (WIA) on Domain Controllers (stisvc)](../02-domain-controllers/services/disable-stisvc.md)**: Disables the WIA service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-DC-071 - Disable Windows Insider Service on Domain Controllers (wisvc)](../02-domain-controllers/services/disable-wisvc.md)**: Disables the wisvc service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-DC-072 - Disable Windows Mobile Hotspot Service on Domain Controllers (icssvc)](../02-domain-controllers/services/disable-icssvc.md)**: Disables the icssvc service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-DC-073 - Disable Windows Push Notifications System Service on Domain Controllers (WpnService)](../02-domain-controllers/services/disable-wpnservice.md)**: Disables the WpnService service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-DC-074 - Disable Windows Push Notifications User Service on Domain Controllers (WpnUserService)](../02-domain-controllers/services/disable-wpnuserservice.md)**: Disables the WpnUserService service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-DC-146 - Disable WebClient Service (WebClient)](../02-domain-controllers/services/disable-webclient.md)**: Disables the WebClient service to reduce background attack surface and eliminate non-essential system functions.

#### Windows Defender Antivirus Baseline (Domain Controllers)
*Submodule Overview: [Windows Defender Antivirus Domain Controller Baseline and Exploit Guard](../02-domain-controllers/defender-antivirus.md)*

* **[REQ-DC-075 - Disable Real-Time Monitoring and Behavior Monitoring Override on Domain Controllers](../02-domain-controllers/defender/disable-real-time-monitoring-and-behavior-monitoring-override.md)**: Real-time scanning, behavior monitoring, and script checking are the core dynamic defense mechanisms of Windows Defender.
* **[REQ-DC-076 - Configure Potentially Unwanted Applications (PUA) Protection on Domain Controllers](../02-domain-controllers/defender/configure-potentially-unwanted-applications-pua-protection.md)**: Potentially Unwanted Applications (PUA) include adware, torrent clients, cryptominers, and system optimizers that increase risk and resource consumption.
* **[REQ-DC-077 - Prevent Local List Merging and Exclusions Configuration on Domain Controllers](../02-domain-controllers/defender/prevent-local-list-merging-and-exclusions-configuration.md)**: If local administrators or compromised administrative accounts can modify Defender exclusions or merge local lists, they can authorize malicious folders or tools.
* **[REQ-DC-078 - Configure Auto Exclusions Configuration on Domain Controllers](../02-domain-controllers/defender/configure-auto-exclusions-configuration.md)**: Auto Exclusions automatically configure exclusions for known safe system folders or server roles to reduce performance overhead.
* **[REQ-DC-079 - Prevent MAPS Local Setting Override on Domain Controllers](../02-domain-controllers/defender/prevent-maps-local-setting-override.md)**: Configures Microsoft Defender Antivirus settings to enhance real-time endpoint protection.
* **[REQ-DC-080 - Enable EDR in Block Mode on Domain Controllers](../02-domain-controllers/defender/enable-edr-in-block-mode.md)**: Configures Microsoft Defender Antivirus settings to enhance real-time endpoint protection.
* **[REQ-DC-081 - Allow Network Protection on Windows Server on Domain Controllers](../02-domain-controllers/defender/allow-network-protection-on-windows-server.md)**: Network Protection blocks processes from accessing malicious domains, phishing sites, and host IP ranges.
* **[REQ-DC-082 - Enable File Hash Computation on Domain Controllers](../02-domain-controllers/defender/enable-file-hash-computation.md)**: Computing cryptographic file hashes allows Defender to pass hashes of scanned files to cloud and SIEM Domain Controllers.
* **[REQ-DC-083 - Configure Network Inspection System (NIS) settings on Domain Controllers](../02-domain-controllers/defender/configure-network-inspection-system-nis-settings.md)**: The Network Inspection System (NIS) inspects network traffic patterns for known exploits.
* **[REQ-DC-084 - Configure OOBE Real-Time Protection and Security Intelligence on Domain Controllers](../02-domain-controllers/defender/configure-oobe-real-time-protection-and-security-intelligence.md)**: Configures Microsoft Defender Antivirus settings to enhance real-time endpoint protection.
* **[REQ-DC-085 - Enable Dynamic Signature Dropped Event Reporting on Domain Controllers](../02-domain-controllers/defender/enable-dynamic-signature-dropped-event-reporting.md)**: Enabling this log report generation triggers explicit events when a dynamic scan ruleset signature is dropped.
* **[REQ-DC-086 - Configure Quick Scan and Scanning Exclusions on Domain Controllers](../02-domain-controllers/defender/configure-quick-scan-and-scanning-exclusions.md)**: Malware frequently tries to establish persistence in excluded directories or inside packed/compressed executables.
* **[REQ-DC-087 - Configure Scheduled Scan Parameters on Domain Controllers](../02-domain-controllers/defender/configure-scheduled-scan-parameters.md)**: Configures Microsoft Defender Antivirus settings to enhance real-time endpoint protection.
* **[REQ-DC-088 - Configure Security Intelligence Update Schedule on Domain Controllers](../02-domain-controllers/defender/configure-security-intelligence-update-schedule.md)**: Antivirus signatures must remain fresh to block the latest published threats.
* **[REQ-DC-090 - Configure Threat Severity Default Quarantine Actions on Domain Controllers](../02-domain-controllers/defender/configure-threat-severity-default-quarantine-actions.md)**: By default, Defender may prompt users or take actions (like clean/ignore) that leave malware remnants on the filesystem.
* **[REQ-DC-091 - Configure Family Options UI Lockdown on Domain Controllers](../02-domain-controllers/defender/configure-family-options-ui-lockdown.md)**: Locking down non-essential components of the Windows Security Center interface prevents users from tampering with parental or diagnostic UI controls on enterprise assets.
* **[REQ-DC-092 - Configure Tamper Protection on Domain Controllers](../02-domain-controllers/defender/configure-tamper-protection.md)**: Configures Microsoft Defender Antivirus settings to enhance real-time endpoint protection.
* **[REQ-DC-093 - Configure Sandbox Execution Environment on Domain Controllers](../02-domain-controllers/defender/configure-sandbox-execution-environment.md)**: Forcing the Windows Defender scanning service (MsMpEng.exe) to run in a restricted AppContainer sandbox prevents privilege escalation.
* **[REQ-DC-094 - Configure AMSI Authenticode Signature Verification on Domain Controllers](../02-domain-controllers/defender/configure-amsi-authenticode-signature-verification.md)**: Enforcing signature checks on registered Antimalware Scan Interface (AMSI) providers blocks attackers from registering unsigned rogue AMSI provider DLLs to bypass script analysis.
* **[REQ-DC-095 - Disable Generic Reports on Domain Controllers](../02-domain-controllers/defender/disable-generic-reports.md)**: Configures Microsoft Defender Antivirus settings to enhance real-time endpoint protection.
* **[REQ-DC-096 - Configure Behavioral Network Brute Force Protection Aggressiveness on Domain Controllers](../02-domain-controllers/defender/configure-brute-force-protection.md)**: Active Directory Domain Controllers are prime targets for automated password brute-forcing and Kerberos pre-authentication spraying attacks.
* **[REQ-DC-097 - Configure Behavioral Network Remote Encryption Protection Aggressiveness on Domain Controllers](../02-domain-controllers/defender/configure-remote-encryption-protection.md)**: Ransomware groups target SYSVOL and SYSVOL shares on Domain Controllers to deploy encrypted templates or payloads.

#### Attack Surface Reduction Rules (Domain Controllers)
* **[REQ-DC-098 - ASR: Block abuse of exploited vulnerable signed drivers on Domain Controllers](../02-domain-controllers/defender/asr/block-vulnerable-signed-drivers.md)**: Prevents an application from writing a vulnerable signed driver to disk.
* **[REQ-DC-100 - ASR: Block execution of potentially obfuscated scripts on Domain Controllers](../02-domain-controllers/defender/asr/block-obfuscated-scripts.md)**: Blocks execution of obfuscated or encrypted scripts (such as PowerShell, VBScript, or JavaScript).
* **[REQ-DC-101 - ASR: Block persistence through WMI event subscription on Domain Controllers](../02-domain-controllers/defender/asr/block-wmi-event-subscription-persistence.md)**: Blocks threat actors from achieving system persistence by registering permanent Windows Management Instrumentation (WMI) event subscriptions.
* **[REQ-DC-102 - ASR: Block process creations originating from PSExec and WMI commands on Domain Controllers](../02-domain-controllers/defender/asr/block-psexec-wmi-process-creations.md)**: Blocks processes created via WMI commands or PSExec remote execution utilities.
* **[REQ-DC-103 - ASR: Use advanced protection against ransomware on Domain Controllers](../02-domain-controllers/defender/asr/use-advanced-protection-against-ransomware.md)**: Enforces Attack Surface Reduction (ASR) rule to mitigate exploit vectors.

#### TCP/IP Network Parameter Hardening (Domain Controllers)
*Submodule Overview: [Configure TCP/IP and Network Parameter Hardening for Domain Controllers](../02-domain-controllers/harden-network-parameters.md)*

* **[REQ-DC-147 - Configure TCP/IP KeepAliveTime on Domain Controllers](../02-domain-controllers/network/configure-tcpip-keepalivetime.md)**: The KeepAliveTime parameter controls how often TCP attempts to verify that an idle connection is still intact by sending a keep-alive packet.
* **[REQ-DC-148 - Disable TCP/IP Router Discovery on Domain Controllers](../02-domain-controllers/network/disable-tcpip-router-discovery.md)**: On Active Directory Domain Controllers, dynamic router discovery presents a severe attack surface:.
* **[REQ-DC-149 - Configure TCP Max Data Retransmissions on Domain Controllers](../02-domain-controllers/network/configure-tcpip-max-data-retransmissions.md)**: The TcpMaxDataRetransmissions parameter determines the number of times TCP will retransmit an individual data segment (non-connect segment) before aborting the connection.
* **[REQ-DC-150 - Disable Default IPv6 DNS Servers on Domain Controllers](../02-domain-controllers/network/disable-ipv6-default-dns-servers.md)**: In an Active Directory environment:.
* **[REQ-DC-151 - Disable Link-Layer Topology Discovery Mapper I/O Driver on Domain Controllers](../02-domain-controllers/network/disable-lltd-mapper-io-driver.md)**: On Tier 0 Domain Controllers:.
* **[REQ-DC-152 - Disable Link-Layer Topology Discovery Responder Driver on Domain Controllers](../02-domain-controllers/network/disable-lltd-responder-driver.md)**: On Tier 0 Domain Controllers:.
* **[REQ-DC-153 - Disable Microsoft Peer-to-Peer Networking Services on Domain Controllers](../02-domain-controllers/network/disable-peernet.md)**: Microsoft Peer-to-Peer Networking Services comprise technologies such as the Peer Name Resolution Protocol (PNRP), Peer Graphing, and Grouping.
* **[REQ-DC-154 - Disable Windows Connect Now Wireless Settings Configuration on Domain Controllers](../02-domain-controllers/network/disable-wcn-wireless-configuration.md)**: On Active Directory Domain Controllers:.
* **[REQ-DC-155 - Prohibit Access to Windows Connect Now Wizards on Domain Controllers](../02-domain-controllers/network/prohibit-wcn-wizards.md)**: On Tier 0 Domain Controllers:.

### Identities & Services Requirements
* **[REQ-ID-017 - Disable Machine Account Quota](../03-identities-services/disable-machine-account-quota.md)**: Reduces the Machine Account Quota (ms-DS-MachineAccountQuota) to 0 to prevent unauthorized machine domain joins.

### Network & Firewall Requirements
* **[REQ-NET-002 - Restrict RPC Dynamic Ports](../04-network-firewall/restrict-rpc-dynamic-ports.md)**: Limits RPC dynamic ports to restrict the active network service attack surface.
* **[REQ-NET-006 - Harden TLS Protocols, Cipher Suites, and Elliptic Curves](../04-network-firewall/harden-tls-configuration.md)**: Disables weak TLS protocols and configures secure cipher suites for system-wide channels.
* **[REQ-NET-008 - Configure Firewall Logging and Operational Settings](../04-network-firewall/configure-firewall-logging.md)**: Configures Windows Defender Firewall logging parameters to maintain full network audit records.
* **[REQ-NET-010 - Harden WinRM Service and Restrict Remote RPC Clients](../04-network-firewall/harden-winrm-service.md)**: Restricts WinRM remote management and limits remote RPC client connections.
* **[REQ-NET-011 - Configure WMI Static Port and Service Hardening](../04-network-firewall/configure-wmi-static-port.md)**: Restricts WMI service connections to a dedicated static network port.
* **[REQ-NET-012 - Configure RPC Filters for Named Pipes](../04-network-firewall/configure-rpc-named-pipe-filters.md)**: Restricts remote RPC named pipe connections to standard system pipes.
* **[REQ-NET-013 - Block Management Traffic Between Domain Controllers](../04-network-firewall/block-intra-dc-management.md)**: Restricts network management traffic between Domain Controllers to prevent intra-tier attacks.

### PAW Requirements
* **[REQ-PAW-001 - Configure AppLocker Policies for PAWs](../07-paws/configure-applocker-policies.md)**: Allow-lists administration utilities.
* **[REQ-PAW-007 - Disable Windows Platform Binary Table (WPBT)](../07-paws/disable-wpbt.md)**: Protects kernel boot from firmware binary injection.
* **[REQ-PAW-012 - Enable WDAC Driver Blocklist](../07-paws/enable-wdac-driver-blocklist.md)**: Restricts bypass drivers on PAWs.
* **[REQ-PAW-016 - Configure Untrusted Font Blocking for PAWs](../07-paws/configure-untrusted-font-blocking.md)**: Font isolation on administration hosts.
* **[REQ-PAW-017 - Configure svchost.exe Mitigation Options for PAWs](../07-paws/configure-svchost-mitigation.md)**: Enforces Microsoft signature check on svchost.
* **[REQ-PAW-018 - Enable Kernel-Mode Hardware-Enforced Stack Protection for PAWs](../07-paws/enable-kernel-shadow-stacks.md)**: Enforces hardware-backed ROP mitigation.
* **[REQ-PAW-023 - WSUS Client Configuration for PAWs](../07-paws/wsus-client-config.md)**: Directs updates to local WSUS servers.
* **[REQ-PAW-025 - Configure Exploit Protection Profile for PAWs](../07-paws/configure-exploit-protection.md)**: System-wide DEP and ASLR configurations.
* **[REQ-PAW-026 - Restrict Safe Mode Access to Administrators on PAWs](../07-paws/disable-safe-mode-for-standard-users.md)**: Disables standard user access in Safe Mode.
* **[REQ-PAW-027 - Configure Windows Defender Firewall and Block LOLBins for PAWs](../07-paws/configure-windows-firewall.md)**: Firewalls and LOLBin traffic limits.
* **[REQ-PAW-032 - Disable Unused Windows Features and PowerShell 2.0 Engine](../07-paws/disable-unused-features.md)**: Disables legacy .NET 3.5, PowerShell 2.0, SMBv1, and unused platform features.
* **[REQ-PAW-033 - Configure Microsoft Office Security and Block OLE Packages](../07-paws/configure-office-security.md)**: Blocks VBA macros in external files and Outlook OLE packages.
* **[REQ-PAW-034 - Disable Windows Script Host and Remap Scripting Extensions](../07-paws/disable-windows-script-host.md)**: Disables WSH execution and maps extension defaults to Notepad.
* **[REQ-PAW-036 - Configure Windows Defender Application Control](../07-paws/configure-wdac.md)**: Deploys code integrity rules.
* **[REQ-PAW-167 - Enable Kerberos Armoring for PAWs](../07-paws/enable-kerberos-armoring.md)**: Enforces Kerberos Armoring (FAST) on PAWs to protect Kerberos pre-authentication exchanges.

#### System Services Hardening (PAWs)
*Submodule Overview: [Disable Unnecessary System Services for PAWs](../07-paws/disable-unnecessary-system-services.md)*

* **[REQ-PAW-037 - Disable Computer Browser Service for PAWs (Browser)](../07-paws/services/disable-browser.md)**: Disables the Browser service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-PAW-038 - Disable Infrared Monitor Service for PAWs (irmon)](../07-paws/services/disable-irmon.md)**: Disables the irmon service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-PAW-039 - Disable Internet Connection Sharing (ICS) Service for PAWs (SharedAccess)](../07-paws/services/disable-sharedaccess.md)**: Disables the ICS service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-PAW-040 - Disable LxssManager Service for PAWs (LxssManager)](../07-paws/services/disable-lxssmanager.md)**: Disables the LxssManager service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-PAW-041 - Disable Microsoft FTP Service for PAWs (FTPSVC)](../07-paws/services/disable-ftpsvc.md)**: Disables the FTPSVC service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-PAW-042 - Disable OpenSSH SSH Server Service for PAWs (sshd)](../07-paws/services/disable-sshd.md)**: Disables the sshd service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-PAW-043 - Disable Remote Procedure Call (RPC) Locator Service for PAWs (RpcLocator)](../07-paws/services/disable-rpclocator.md)**: Disables the RPC service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-PAW-044 - Disable Routing and Remote Access Service for PAWs (RemoteAccess)](../07-paws/services/disable-remoteaccess.md)**: Disables the RemoteAccess service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-PAW-045 - Disable Simple TCP/IP Services for PAWs (simptcp)](../07-paws/services/disable-simptcp.md)**: Disables the simptcp service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-PAW-046 - Disable Special Administration Console Helper Service for PAWs (sacsvr)](../07-paws/services/disable-sacsvr.md)**: Disables the sacsvr service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-PAW-047 - Disable SSDP Discovery Service for PAWs (SSDPSRV)](../07-paws/services/disable-ssdpsrv.md)**: Disables the SSDPSRV service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-PAW-048 - Disable UPnP Device Host Service for PAWs (upnphost)](../07-paws/services/disable-upnphost.md)**: Disables the upnphost service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-PAW-049 - Disable Web Management Service for PAWs (WMSvc)](../07-paws/services/disable-wmsvc.md)**: Disables the WMSvc service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-PAW-050 - Disable Windows Media Player Network Sharing Service for PAWs (WMPNetworkSvc)](../07-paws/services/disable-wmpnetworksvc.md)**: Disables the WMPNetworkSvc service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-PAW-051 - Disable Windows Mobile Hotspot Service for PAWs (icssvc)](../07-paws/services/disable-icssvc.md)**: Disables the icssvc service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-PAW-052 - Disable World Wide Web Publishing Service for PAWs (W3SVC)](../07-paws/services/disable-w3svc.md)**: Disables the W3SVC service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-PAW-053 - Disable Xbox Accessory Management Service for PAWs (XboxGipSvc)](../07-paws/services/disable-xboxgipsvc.md)**: Disables the XboxGipSvc service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-PAW-054 - Disable Xbox Live Auth Manager for PAWs (XblAuthManager)](../07-paws/services/disable-xblauthmanager.md)**: Disables the XblAuthManager service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-PAW-055 - Disable Xbox Live Game Save Service for PAWs (XblGameSave)](../07-paws/services/disable-xblgamesave.md)**: Disables the XblGameSave service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-PAW-056 - Disable Xbox Live Networking Service for PAWs (XboxNetApiSvc)](../07-paws/services/disable-xboxnetapisvc.md)**: Disables the XboxNetApiSvc service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-PAW-166 - Disable WebClient Service for PAWs (WebClient)](../07-paws/services/disable-webclient.md)**: Disables the WebClient service to reduce background attack surface and eliminate non-essential system functions.

#### Windows Defender Antivirus Baseline (PAWs)
*Submodule Overview: [Windows Defender Antivirus PAW Baseline and Exploit Guard](../07-paws/defender-antivirus.md)*

* **[REQ-PAW-057 - Disable Real-Time Monitoring and Behavior Monitoring Override for PAWs](../07-paws/defender/disable-real-time-monitoring-and-behavior-monitoring-override.md)**: Real-time scanning, behavior monitoring, and script checking are the core dynamic defense mechanisms of Windows Defender.
* **[REQ-PAW-058 - Configure Potentially Unwanted Applications (PUA) Protection for PAWs](../07-paws/defender/configure-potentially-unwanted-applications-pua-protection.md)**: Potentially Unwanted Applications (PUA) include adware, torrent clients, cryptominers, and system optimizers that increase risk and resource consumption.
* **[REQ-PAW-059 - Prevent Local List Merging and Exclusions Configuration for PAWs](../07-paws/defender/prevent-local-list-merging-and-exclusions-configuration.md)**: If local administrators or compromised administrative accounts can modify Defender exclusions or merge local lists, they can authorize malicious folders or tools.
* **[REQ-PAW-060 - Configure Auto Exclusions Configuration for PAWs](../07-paws/defender/configure-auto-exclusions-configuration.md)**: Auto Exclusions automatically configure exclusions for known safe system folders or server roles to reduce performance overhead.
* **[REQ-PAW-061 - Enable EDR in Block Mode for PAWs](../07-paws/defender/enable-edr-in-block-mode.md)**: Configures Microsoft Defender Antivirus settings to enhance real-time endpoint protection.
* **[REQ-PAW-062 - Allow Network Protection on Windows Server for PAWs](../07-paws/defender/allow-network-protection-on-windows-server.md)**: Network Protection blocks processes from accessing malicious domains, phishing sites, and host IP ranges.
* **[REQ-PAW-063 - Enable File Hash Computation for PAWs](../07-paws/defender/enable-file-hash-computation.md)**: Computing cryptographic file hashes allows Defender to pass hashes of scanned files to cloud and SIEM PAW platforms.
* **[REQ-PAW-064 - Configure Network Inspection System (NIS) settings for PAWs](../07-paws/defender/configure-network-inspection-system-nis-settings.md)**: The Network Inspection System (NIS) inspects network traffic patterns for known exploits.
* **[REQ-PAW-065 - Configure OOBE Real-Time Protection and Security Intelligence for PAWs](../07-paws/defender/configure-oobe-real-time-protection-and-security-intelligence.md)**: Configures Microsoft Defender Antivirus settings to enhance real-time endpoint protection.
* **[REQ-PAW-066 - Enable Dynamic Signature Dropped Event Reporting for PAWs](../07-paws/defender/enable-dynamic-signature-dropped-event-reporting.md)**: Enabling this log report generation triggers explicit events when a dynamic scan ruleset signature is dropped.
* **[REQ-PAW-067 - Configure Quick Scan and Scanning Exclusions for PAWs](../07-paws/defender/configure-quick-scan-and-scanning-exclusions.md)**: Malware frequently tries to establish persistence in excluded directories or inside packed/compressed executables.
* **[REQ-PAW-068 - Configure Scheduled Scan Parameters for PAWs](../07-paws/defender/configure-scheduled-scan-parameters.md)**: Configures Microsoft Defender Antivirus settings to enhance real-time endpoint protection.
* **[REQ-PAW-069 - Configure Security Intelligence Update Schedule for PAWs](../07-paws/defender/configure-security-intelligence-update-schedule.md)**: Antivirus signatures must remain fresh to block the latest published threats.
* **[REQ-PAW-071 - Configure Threat Severity Default Quarantine Actions for PAWs](../07-paws/defender/configure-threat-severity-default-quarantine-actions.md)**: By default, Defender may prompt users or take actions (like clean/ignore) that leave malware remnants on the filesystem.
* **[REQ-PAW-072 - Configure Family Options UI Lockdown for PAWs](../07-paws/defender/configure-family-options-ui-lockdown.md)**: Locking down non-essential components of the Windows Security Center interface prevents users from tampering with parental or diagnostic UI controls on enterprise assets.
* **[REQ-PAW-073 - Configure Tamper Protection for PAWs](../07-paws/defender/configure-tamper-protection.md)**: Configures Microsoft Defender Antivirus settings to enhance real-time endpoint protection.
* **[REQ-PAW-074 - Configure Sandbox Execution Environment for PAWs](../07-paws/defender/configure-sandbox-execution-environment.md)**: Forcing the Windows Defender scanning service (MsMpEng.exe) to run in a restricted AppContainer sandbox prevents privilege escalation.
* **[REQ-PAW-075 - Configure AMSI Authenticode Signature Verification for PAWs](../07-paws/defender/configure-amsi-authenticode-signature-verification.md)**: Enforcing signature checks on registered Antimalware Scan Interface (AMSI) providers blocks attackers from registering unsigned rogue AMSI provider DLLs to bypass script analysis.
* **[REQ-PAW-192 - Configure Remote Encryption Protection Mode for PAWs](../07-paws/defender/configure-remote-encryption-protection.md)**: Privileged Access Workstations (PAWs) must maintain the highest standard of endpoint protection against ransomware and lateral movement attempts.

#### Attack Surface Reduction Rules (PAWs)
* **[REQ-PAW-076 - ASR: Block abuse of exploited vulnerable signed drivers for PAWs](../07-paws/defender/asr/block-vulnerable-signed-drivers.md)**: Prevents an application from writing a vulnerable signed driver to disk.
* **[REQ-PAW-077 - ASR: Block Adobe Reader from creating child processes for PAWs](../07-paws/defender/asr/block-adobe-reader-child-processes.md)**: Prevents Adobe Reader from launching any child processes.
* **[REQ-PAW-078 - ASR: Block all Office applications from creating child processes for PAWs](../07-paws/defender/asr/block-office-child-processes.md)**: Blocks Microsoft Office applications (Word, Excel, PowerPoint) from creating child processes.
* **[REQ-PAW-080 - ASR: Block executable content from email client and webmail for PAWs](../07-paws/defender/asr/block-email-executable-content.md)**: Prevents executable files (such as .exe, .com, .scr, .vbs, .js, or .pif) from launching directly from email clients (like Outlook) or webmail accessed via browser sessions.
* **[REQ-PAW-081 - ASR: Block executable files from running unless they meet a prevalence, age, or trusted list criterion for PAWs](../07-paws/defender/asr/block-low-prevalence-executable-files.md)**: Blocks execution of unrecognized, newly compiled, or low-prevalence executable files.
* **[REQ-PAW-082 - ASR: Block execution of potentially obfuscated scripts for PAWs](../07-paws/defender/asr/block-obfuscated-scripts.md)**: Blocks execution of obfuscated or encrypted scripts (such as PowerShell, VBScript, or JavaScript).
* **[REQ-PAW-083 - ASR: Block JavaScript or VBScript from launching downloaded executable content for PAWs](../07-paws/defender/asr/block-script-launching-downloaded-content.md)**: Prevents JavaScript or VBScript running locally from launching executable binaries that were downloaded from the internet.
* **[REQ-PAW-084 - ASR: Block Office applications from creating executable content for PAWs](../07-paws/defender/asr/block-office-executable-content-creation.md)**: Prevents Microsoft Office applications (Word, Excel, PowerPoint) from creating or writing executable files (e.g., .exe, .dll, .scr) to the local filesystem.
* **[REQ-PAW-085 - ASR: Block Office applications from injecting code into other processes for PAWs](../07-paws/defender/asr/block-office-code-injection.md)**: Blocks Microsoft Office applications from writing code or injecting threads directly into external processes.
* **[REQ-PAW-086 - ASR: Block Office communication application from creating child processes for PAWs](../07-paws/defender/asr/block-office-communication-child-processes.md)**: Blocks Microsoft Outlook or other Office communication applications (e.g., Teams, Skype) from creating child processes.
* **[REQ-PAW-087 - ASR: Block persistence through WMI event subscription for PAWs](../07-paws/defender/asr/block-wmi-event-subscription-persistence.md)**: Blocks threat actors from achieving system persistence by registering permanent Windows Management Instrumentation (WMI) event subscriptions.
* **[REQ-PAW-088 - ASR: Block process creations originating from PSExec and WMI commands for PAWs](../07-paws/defender/asr/block-psexec-wmi-process-creations.md)**: Blocks processes created via WMI commands or PSExec remote execution utilities.
* **[REQ-PAW-089 - ASR: Block untrusted and unsigned processes that run from USB for PAWs](../07-paws/defender/asr/block-unsigned-processes-running-from-usb.md)**: Blocks the execution of unsigned or untrusted processes on removable storage devices (USB drives, external SSDs).
* **[REQ-PAW-090 - ASR: Block Win32 API calls from Office macros for PAWs](../07-paws/defender/asr/block-win32-api-calls-from-office-macros.md)**: Blocks VBA macros inside Microsoft Office documents from invoking Win32 API calls.
* **[REQ-PAW-091 - ASR: Use advanced protection against ransomware for PAWs](../07-paws/defender/asr/use-advanced-protection-against-ransomware.md)**: Enforces Attack Surface Reduction (ASR) rule to mitigate exploit vectors.

#### User Profile Restrictions (PAWs)
*Submodule Overview: [Configure User Profile Restrictions for PAWs](../07-paws/configure-user-profile-restrictions.md)*

* **[REQ-PAW-115 - User Profile: Toast Notifications Lock Screen Restrictions for PAWs](../07-paws/user-profile/configure-up-toast-notifications.md)**: Privileged Access Workstations (PAWs) operate in high-security operations centers (SOC/NOC) or dedicated administrative enclaves.
* **[REQ-PAW-116 - User Profile: Spotlight and Consumer Features Restrictions for PAWs](../07-paws/user-profile/configure-up-spotlight-consumer.md)**: Privileged Access Workstations (PAWs) operate in dedicated management enclaves with restricted internet egress.
* **[REQ-PAW-117 - User Profile: Windows Copilot Restrictions for PAWs](../07-paws/user-profile/configure-up-windows-copilot.md)**: Restricts user profile and interactive shell features to harden the desktop environment.
* **[REQ-PAW-118 - User Profile: In-Place Sharing Restrictions for PAWs](../07-paws/user-profile/configure-up-inplace-sharing.md)**: Privileged Access Workstations (PAWs) are dedicated exclusively to directory administration, identity synchronization, and domain-level maintenance.
* **[REQ-PAW-119 - User Profile: Shell RunAs User Suppression for PAWs](../07-paws/user-profile/configure-up-runas-suppression.md)**: Privileged Access Workstations (PAWs) operate under strict dedicated role segregation.
* **[REQ-PAW-120 - User Profile: Personalization and Privacy Restrictions for PAWs](../07-paws/user-profile/configure-up-personalization-privacy.md)**: Privileged Access Workstations (PAWs) serve as the trusted execution environment for managing Active Directory Domain Services, forest trusts, and cryptographic root keys.
* **[REQ-PAW-121 - User Profile: Group Policy Registry Policy Processing Behaviors for PAWs](../07-paws/user-profile/configure-up-gp-processing.md)**: Privileged Access Workstations (PAWs) enforce the most stringent security configurations across the enterprise to safeguard Tier 0 identity assets.
* **[REQ-PAW-122 - User Profile: Telemetry and Inventory Collection Restrictions for PAWs](../07-paws/user-profile/configure-up-telemetry-inventory.md)**: Restricts user profile and interactive shell features to harden the desktop environment.
* **[REQ-PAW-123 - User Profile: Explorer Security and Memory Protections for PAWs](../07-paws/user-profile/configure-up-explorer-security.md)**: Restricts user profile and interactive shell features to harden the desktop environment.
* **[REQ-PAW-124 - User Profile: Internet Explorer Options and Feeds Restrictions for PAWs](../07-paws/user-profile/configure-up-ie-security.md)**: Restricts user profile and interactive shell features to harden the desktop environment.
* **[REQ-PAW-125 - User Profile: Interactive Logon Warning Banners for PAWs](../07-paws/user-profile/configure-up-logon-banners.md)**: Restricts user profile and interactive shell features to harden the desktop environment.
* **[REQ-PAW-126 - User Profile: Interactive Logon Inactivity Timeout for PAWs](../07-paws/user-profile/configure-up-inactivity-timeout.md)**: In-memory Kerberos Ticket Granting Tickets (TGTs) belonging to Domain Admins, Enterprise Admins, or Schema Admins.
* **[REQ-PAW-127 - User Profile: Windows Installer Hardening for PAWs](../07-paws/user-profile/configure-up-installer-hardening.md)**: Privileged Access Workstations (PAWs) serve as the dedicated management boundary for Tier 0 Active Directory assets.
* **[REQ-PAW-128 - User Profile: Secondary Logon Service Lockdown for PAWs](../07-paws/user-profile/configure-up-seclogon-service.md)**: Restricts user profile and interactive shell features to harden the desktop environment.
* **[REQ-PAW-140 - User Profile: Structured Exception Handling Overwrite Protection (SEHOP) for PAWs](../07-paws/user-profile/configure-paw-up-sehop.md)**: Configures maximum event log sizes and retention parameters to prevent log overwrite during security incidents on PAWs.
* **[REQ-PAW-141 - User Profile: Directory Protection Mode for PAWs](../07-paws/user-profile/configure-paw-up-protection-mode.md)**: Restricts user profile and interactive shell features to harden the desktop environment.
* **[REQ-PAW-142 - User Profile: Address Space Layout Randomization (ASLR) Image Relocation for PAWs](../07-paws/user-profile/configure-paw-up-aslr-relocation.md)**: Restricts user profile and interactive shell features to harden the desktop environment.
* **[REQ-PAW-143 - User Profile: Speculative Execution Mitigations (Spectre/Meltdown) for PAWs](../07-paws/user-profile/configure-paw-up-speculative-mitigations.md)**: Restricts user profile and interactive shell features to harden the desktop environment.
* **[REQ-PAW-144 - User Profile: Authenticode Signature Certificate Padding Check for PAWs](../07-paws/user-profile/configure-paw-up-cert-padding.md)**: Restricts user profile and interactive shell features to harden the desktop environment.
* **[REQ-PAW-145 - User Profile: Command Processor Batch File Locking for PAWs](../07-paws/user-profile/configure-paw-up-lock-batch-files.md)**: Privileged Access Workstations (PAWs) are dedicated exclusively to directory administration, identity synchronization, and domain-level maintenance.
* **[REQ-PAW-146 - User Profile: Time-Travel Debugging (TTD) Recording Policy for PAWs](../07-paws/user-profile/configure-paw-up-ttd-recording.md)**: Restricts user profile and interactive shell features to harden the desktop environment.
* **[REQ-PAW-147 - User Profile: Trusted Root Store Protected Roots Certificate Restriction for PAWs](../07-paws/user-profile/configure-paw-up-protected-roots.md)**: On Privileged Access Workstations (PAWs), cryptographic trust validation is paramount.
* **[REQ-PAW-148 - User Profile: Disabling Injection of AppInit DLLs for PAWs](../07-paws/user-profile/configure-paw-up-appinit-dlls.md)**: Restricts user profile and interactive shell features to harden the desktop environment.
* **[REQ-PAW-149 - User Profile: Preservation of Attachment Zone Information for PAWs](../07-paws/user-profile/configure-paw-up-attachment-zone.md)**: Privileged Access Workstations (PAWs) are strictly isolated systems dedicated to managing Tier 0 assets.
* **[REQ-PAW-150 - User Profile: Disable Windows Game DVR for PAWs](../07-paws/user-profile/configure-paw-up-game-dvr.md)**: Restricts user profile and interactive shell features to harden the desktop environment.
* **[REQ-PAW-151 - User Profile: Restrict Windows Ink Workspace on Lock Screen for PAWs](../07-paws/user-profile/configure-paw-up-ink-workspace.md)**: Privileged Access Workstations (PAWs) serve as the dedicated management boundary for Active Directory forest infrastructure.

#### System Administrative Templates (PAWs)
*Submodule Overview: [Configure System Administrative Templates for PAWs](../07-paws/configure-system-administrative-templates.md)*

* **[REQ-PAW-168 - Administrative Templates: Disable SMBv1 Protocol Components for PAWs](../07-paws/admin-templates/configure-paw-at-smbv1.md)**: Privileged Access Workstations (PAWs) serve as the sensitive administrative bridge between Tier 0 operators and Tier 0 Active Directory Domain Controllers.
* **[REQ-PAW-169 - Administrative Templates: Configure NetBT Node Type and Name Release for PAWs](../07-paws/admin-templates/configure-paw-at-netbt-nodetype.md)**: Privileged Access Workstations (PAWs) are high-value targets operating within dedicated administrative management zones.
* **[REQ-PAW-170 - Administrative Templates: MSS IP Source Routing and ICMP Redirects for PAWs](../07-paws/admin-templates/configure-paw-at-mss-ip-source-routing.md)**: Configures administrative template security policy to enforce baseline system hardening.
* **[REQ-PAW-171 - Administrative Templates: MSS System and Session Security Protections for PAWs](../07-paws/admin-templates/configure-paw-at-mss-system-protections.md)**: Configures administrative template security policy to enforce baseline system hardening.
* **[REQ-PAW-172 - Administrative Templates: Prevent Device Metadata Retrieval from Network for PAWs](../07-paws/admin-templates/configure-paw-at-device-metadata.md)**: Configures administrative template security policy to enforce baseline system hardening.
* **[REQ-PAW-173 - Administrative Templates: Enforce Group Policy Background Processing for PAWs](../07-paws/admin-templates/configure-paw-at-gp-processing.md)**: Privileged Access Workstations (PAWs) are high-security administrative bastion hosts dedicated exclusively to Tier 0 directory services management.
* **[REQ-PAW-174 - Administrative Templates: Disable Cross-Device Experiences for PAWs](../07-paws/admin-templates/configure-paw-at-cross-device-experiences.md)**: Configures administrative template security policy to enforce baseline system hardening.
* **[REQ-PAW-175 - Administrative Templates: Restrict Internet Communication and Web Downloads for PAWs](../07-paws/admin-templates/configure-paw-at-internet-communication.md)**: Configures administrative template security policy to enforce baseline system hardening.
* **[REQ-PAW-176 - Administrative Templates: Block Custom SSPs and APs from Loading into LSASS for PAWs](../07-paws/admin-templates/configure-paw-at-lsa-custom-ssps.md)**: Configures administrative template security policy to enforce baseline system hardening.
* **[REQ-PAW-177 - Administrative Templates: Logon Display and Credential Restrictions for PAWs](../07-paws/admin-templates/configure-paw-at-logon-display-options.md)**: Privileged Access Workstations (PAWs) serve as the dedicated management perimeter for Active Directory Domain Controllers and enterprise tier-0 administrative roles.
* **[REQ-PAW-178 - Administrative Templates: Disable Connected Standby Network Connectivity for PAWs](../07-paws/admin-templates/configure-paw-at-power-connected-standby.md)**: Privileged Access Workstations (PAWs) are high-assurance hardware platforms dedicated exclusively to Tier 0 directory administration.
* **[REQ-PAW-179 - Administrative Templates: Disable Remote Assistance for PAWs](../07-paws/admin-templates/configure-paw-at-remote-assistance.md)**: Configures administrative template security policy to enforce baseline system hardening.
* **[REQ-PAW-180 - Administrative Templates: Enable RPC Endpoint Mapper Client Authentication for PAWs](../07-paws/admin-templates/configure-paw-at-rpc-endpoint-mapper-auth.md)**: Configures administrative template security policy to enforce baseline system hardening.
* **[REQ-PAW-181 - Administrative Templates: Configure Windows Time Service NTP Client and Server for PAWs](../07-paws/admin-templates/configure-paw-at-w32time-ntp-client.md)**: Privileged Access Workstations (PAWs) perform high-consequence administrative operations across Tier 0 infrastructure.
* **[REQ-PAW-182 - Administrative Templates: App Package Deployment Restrictions for PAWs](../07-paws/admin-templates/configure-paw-at-appx-deployment-restrictions.md)**: Privileged Access Workstations (PAWs) are dedicated exclusively to directory administration and Tier 0 infrastructure management.
* **[REQ-PAW-183 - Administrative Templates: Configure Biometrics Enhanced Anti-Spoofing for PAWs](../07-paws/admin-templates/configure-paw-at-biometrics-anti-spoofing.md)**: Privileged Access Workstations (PAWs) serve as the highest-trust endpoints within an Active Directory enterprise architecture.
* **[REQ-PAW-184 - Administrative Templates: Disable Cloud Consumer Account State Content for PAWs](../07-paws/admin-templates/configure-paw-at-cloud-consumer-content.md)**: Privileged Access Workstations (PAWs) are dedicated, single-purpose endpoints reserved exclusively for Tier 0 Active Directory and infrastructure administration.
* **[REQ-PAW-185 - Administrative Templates: Require PIN for Connect Wireless Pairing for PAWs](../07-paws/admin-templates/configure-paw-at-connect-pin-pairing.md)**: Privileged Access Workstations (PAWs) operate within dedicated administrative perimeters for Tier 0 Active Directory management.
* **[REQ-PAW-186 - Administrative Templates: Credential User Interface Security Protections for PAWs](../07-paws/admin-templates/configure-paw-at-credui-protections.md)**: Privileged Access Workstations (PAWs) are dedicated exclusively to high-privilege Tier 0 Active Directory management tasks.
* **[REQ-PAW-187 - Administrative Templates: Diagnostic Data Collection and Preview Builds Restrictions for PAWs](../07-paws/admin-templates/configure-paw-at-data-collection-preview-builds.md)**: Configures administrative template security policy to enforce baseline system hardening.
* **[REQ-PAW-188 - Administrative Templates: App Installer Protocol and Execution Controls for PAWs](../07-paws/admin-templates/configure-paw-at-app-installer-controls.md)**: Privileged Access Workstations (PAWs) serve as the dedicated platform for Tier 0 Active Directory operations.
* **[REQ-PAW-189 - Administrative Templates: Event Log Maximum File Sizes and Retention Policies for PAWs](../07-paws/admin-templates/configure-paw-at-event-log-sizes.md)**: Configures administrative template security policy to enforce baseline system hardening.
* **[REQ-PAW-190 - Administrative Templates: File Explorer Mark of the Web and Shell Protocol Security for PAWs](../07-paws/admin-templates/configure-paw-at-file-explorer-motw.md)**: Privileged Access Workstations (PAWs) represent Tier 0 administrative boundaries.
* **[REQ-PAW-191 - Administrative Templates: Internet Explorer 11 and Web Feeds Retirement Controls for PAWs](../07-paws/admin-templates/configure-paw-at-internet-explorer-retirement.md)**: Privileged Access Workstations (PAWs) are hardened environments dedicated to Tier 0 infrastructure management.
* **[REQ-PAW-193 - Administrative Templates: Windows Search and Cortana Privacy Restrictions for PAWs](../07-paws/admin-templates/configure-paw-at-search-cortana-restrictions.md)**: Privileged Access Workstations (PAWs) are dedicated exclusively to Tier 0 Active Directory and core infrastructure administration.
* **[REQ-PAW-194 - Administrative Templates: Windows Store Updates and OS Upgrade Restrictions for PAWs](../07-paws/admin-templates/configure-paw-at-windows-store-restrictions.md)**: Privileged Access Workstations (PAWs) execute mission-critical directory administration tools.
* **[REQ-PAW-195 - Administrative Templates: Disable Windows Widgets and News Feed for PAWs](../07-paws/admin-templates/configure-paw-at-windows-widgets-dsh.md)**: Privileged Access Workstations (PAWs) provide the highest level of security isolation for Tier 0 Active Directory administration.
* **[REQ-PAW-196 - Administrative Templates: Disable Windows Automatic Restart Sign-On (ARSO) for PAWs](../07-paws/admin-templates/configure-paw-at-automatic-restart-signon.md)**: Configures administrative template security policy to enforce baseline system hardening.
* **[REQ-PAW-197 - Administrative Templates: Windows Sandbox Clipboard and Network Isolation for PAWs](../07-paws/admin-templates/configure-paw-at-windows-sandbox-isolation.md)**: Privileged Access Workstations (PAWs) manage the enterprise's most sensitive Tier 0 identity boundaries.
* **[REQ-PAW-198 - Administrative Templates: Windows Update Deferral and Automatic Installation Policies for PAWs](../07-paws/admin-templates/configure-paw-at-windows-update-policies.md)**: Privileged Access Workstations (PAWs) host the most sensitive interactive sessions and management credentials across the entire enterprise directory structure.

### Endpoint Requirements
* **[REQ-END-004 - Block Removable Storage](../08-endpoints/block-removable-storage.md)**: Prevents data exfiltration and USB storage execution.
* **[REQ-END-008 - WSUS Client Configuration](../08-endpoints/wsus-client-config.md)**: Updates from local offline servers only.
* **[REQ-END-011 - Configure Windows Defender Application Control](../08-endpoints/configure-wdac.md)**: Deploys code integrity rules.
* **[REQ-END-015 - Disable Windows Platform Binary Table (WPBT)](../08-endpoints/disable-wpbt.md)**: Mitigates firmware-based binary insertion.
* **[REQ-END-020 - Configure Exploit Protection Profile](../08-endpoints/configure-exploit-protection.md)**: Memory protection profiles on client endpoints.
* **[REQ-END-021 - Restrict Safe Mode Access to Administrators](../08-endpoints/disable-safe-mode-for-standard-users.md)**: Denies standard user Safe Mode login.
* **[REQ-END-022 - Configure Windows Defender Firewall and Block LOLBins](../08-endpoints/configure-windows-firewall.md)**: Firewalls and outbound execution blocks.
* **[REQ-END-027 - Configure AppLocker Policies](../08-endpoints/configure-applocker-policies.md)**: Software execution restrictions on clients.
* **[REQ-END-029 - Configure Untrusted Font Blocking](../08-endpoints/configure-untrusted-font-blocking.md)**: Disables third-party font libraries.
* **[REQ-END-030 - Configure svchost.exe Mitigation Options](../08-endpoints/configure-svchost-mitigation.md)**: Restricts binary loading to Microsoft-signed code.
* **[REQ-END-031 - Enable Kernel-Mode Hardware-Enforced Stack Protection](../08-endpoints/enable-kernel-shadow-stacks.md)**: Mitigates Return-Oriented Programming (ROP) exploits.
* **[REQ-END-032 - Disable Unused Windows Features and PowerShell 2.0 Engine](../08-endpoints/disable-unused-features.md)**: Disables legacy .NET 3.5, PowerShell 2.0, SMBv1, and unused optional features.
* **[REQ-END-033 - Configure Microsoft Office Security and Block OLE Packages](../08-endpoints/configure-office-security.md)**: Blocks VBA macros in external files and Outlook OLE packages.
* **[REQ-END-034 - Disable Windows Script Host and Remap Scripting Extensions](../08-endpoints/disable-windows-script-host.md)**: Disables WSH execution and maps extension defaults to Notepad.
* **[REQ-END-036 - Enable WDAC Driver Blocklist](../08-endpoints/enable-wdac-driver-blocklist.md)**: Blocks known vulnerable drivers on Endpoints.
* **[REQ-END-178 - Enable Kerberos Armoring for Endpoints](../08-endpoints/enable-kerberos-armoring.md)**: Enforces Kerberos Armoring (FAST) on Endpoints to protect Kerberos pre-authentication exchanges.

#### System Services Hardening (Endpoints)
*Submodule Overview: [Disable Unnecessary System Services for Endpoints](../08-endpoints/disable-unnecessary-system-services.md)*

* **[REQ-END-037 - Disable Computer Browser Service (Browser)](../08-endpoints/services/disable-browser.md)**: Disables the Browser service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-END-038 - Disable Infrared Monitor Service (irmon)](../08-endpoints/services/disable-irmon.md)**: Disables the irmon service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-END-039 - Disable Internet Connection Sharing (ICS) Service (SharedAccess)](../08-endpoints/services/disable-sharedaccess.md)**: Disables the ICS service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-END-040 - Disable LxssManager Service (LxssManager)](../08-endpoints/services/disable-lxssmanager.md)**: Disables the LxssManager service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-END-041 - Disable Microsoft FTP Service (FTPSVC)](../08-endpoints/services/disable-ftpsvc.md)**: Disables the FTPSVC service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-END-042 - Disable OpenSSH SSH Server Service (sshd)](../08-endpoints/services/disable-sshd.md)**: Disables the sshd service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-END-043 - Disable Remote Procedure Call (RPC) Locator Service (RpcLocator)](../08-endpoints/services/disable-rpclocator.md)**: Disables the RPC service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-END-044 - Disable Routing and Remote Access Service (RemoteAccess)](../08-endpoints/services/disable-remoteaccess.md)**: Disables the RemoteAccess service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-END-045 - Disable Simple TCP/IP Services (simptcp)](../08-endpoints/services/disable-simptcp.md)**: Disables the simptcp service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-END-046 - Disable Special Administration Console Helper Service (sacsvr)](../08-endpoints/services/disable-sacsvr.md)**: Disables the sacsvr service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-END-047 - Disable SSDP Discovery Service (SSDPSRV)](../08-endpoints/services/disable-ssdpsrv.md)**: Disables the SSDPSRV service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-END-048 - Disable UPnP Device Host Service (upnphost)](../08-endpoints/services/disable-upnphost.md)**: Disables the upnphost service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-END-049 - Disable Web Management Service (WMSvc)](../08-endpoints/services/disable-wmsvc.md)**: Disables the WMSvc service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-END-050 - Disable Windows Media Player Network Sharing Service (WMPNetworkSvc)](../08-endpoints/services/disable-wmpnetworksvc.md)**: Disables the WMPNetworkSvc service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-END-051 - Disable Windows Mobile Hotspot Service (icssvc)](../08-endpoints/services/disable-icssvc.md)**: Disables the icssvc service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-END-052 - Disable World Wide Web Publishing Service (W3SVC)](../08-endpoints/services/disable-w3svc.md)**: Disables the W3SVC service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-END-053 - Disable Xbox Accessory Management Service (XboxGipSvc)](../08-endpoints/services/disable-xboxgipsvc.md)**: Disables the XboxGipSvc service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-END-054 - Disable Xbox Live Auth Manager (XblAuthManager)](../08-endpoints/services/disable-xblauthmanager.md)**: Disables the XblAuthManager service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-END-055 - Disable Xbox Live Game Save Service (XblGameSave)](../08-endpoints/services/disable-xblgamesave.md)**: Disables the XblGameSave service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-END-056 - Disable Xbox Live Networking Service (XboxNetApiSvc)](../08-endpoints/services/disable-xboxnetapisvc.md)**: Disables the XboxNetApiSvc service to reduce background attack surface and eliminate non-essential system functions.
* **[REQ-END-177 - Disable WebClient Service (WebClient)](../08-endpoints/services/disable-webclient.md)**: Disables the WebClient service to reduce background attack surface and eliminate non-essential system functions.

#### Windows Defender Antivirus Baseline (Endpoints)
*Submodule Overview: [Windows Defender Antivirus Baseline and Exploit Guard](../08-endpoints/defender-antivirus.md)*

* **[REQ-END-057 - Disable Real-Time Monitoring and Behavior Monitoring Override](../08-endpoints/defender/disable-real-time-monitoring-and-behavior-monitoring-override.md)**: Real-time scanning, behavior monitoring, and script checking are the core dynamic defense mechanisms of Windows Defender.
* **[REQ-END-058 - Configure Potentially Unwanted Applications (PUA) Protection](../08-endpoints/defender/configure-potentially-unwanted-applications-pua-protection.md)**: Potentially Unwanted Applications (PUA) include adware, torrent clients, cryptominers, and system optimizers that increase risk and resource consumption.
* **[REQ-END-059 - Prevent Local List Merging and Exclusions Configuration](../08-endpoints/defender/prevent-local-list-merging-and-exclusions-configuration.md)**: If local administrators or compromised administrative accounts can modify Defender exclusions or merge local lists, they can authorize malicious folders or tools.
* **[REQ-END-060 - Configure Auto Exclusions Configuration](../08-endpoints/defender/configure-auto-exclusions-configuration.md)**: Auto Exclusions automatically configure exclusions for known safe system folders or server roles to reduce performance overhead.
* **[REQ-END-061 - Prevent MAPS Local Setting Override](../08-endpoints/defender/prevent-maps-local-setting-override.md)**: Configures Microsoft Defender Antivirus settings to enhance real-time endpoint protection.
* **[REQ-END-062 - Enable EDR in Block Mode](../08-endpoints/defender/enable-edr-in-block-mode.md)**: Configures Microsoft Defender Antivirus settings to enhance real-time endpoint protection.
* **[REQ-END-063 - Allow Network Protection on Windows Server](../08-endpoints/defender/allow-network-protection-on-windows-server.md)**: Network Protection blocks processes from accessing malicious domains, phishing sites, and host IP ranges.
* **[REQ-END-064 - Enable File Hash Computation](../08-endpoints/defender/enable-file-hash-computation.md)**: Computing cryptographic file hashes allows Defender to pass hashes of scanned files to cloud and SIEM endpoints.
* **[REQ-END-065 - Configure Network Inspection System (NIS) settings](../08-endpoints/defender/configure-network-inspection-system-nis-settings.md)**: The Network Inspection System (NIS) inspects network traffic patterns for known exploits.
* **[REQ-END-066 - Configure OOBE Real-Time Protection and Security Intelligence](../08-endpoints/defender/configure-oobe-real-time-protection-and-security-intelligence.md)**: Configures Microsoft Defender Antivirus settings to enhance real-time endpoint protection.
* **[REQ-END-067 - Enable Dynamic Signature Dropped Event Reporting](../08-endpoints/defender/enable-dynamic-signature-dropped-event-reporting.md)**: Enabling this log report generation triggers explicit events when a dynamic scan ruleset signature is dropped.
* **[REQ-END-068 - Configure Quick Scan and Scanning Exclusions](../08-endpoints/defender/configure-quick-scan-and-scanning-exclusions.md)**: Malware frequently tries to establish persistence in excluded directories or inside packed/compressed executables.
* **[REQ-END-069 - Configure Scheduled Scan Parameters](../08-endpoints/defender/configure-scheduled-scan-parameters.md)**: Configures Microsoft Defender Antivirus settings to enhance real-time endpoint protection.
* **[REQ-END-070 - Configure Security Intelligence Update Schedule](../08-endpoints/defender/configure-security-intelligence-update-schedule.md)**: Antivirus signatures must remain fresh to block the latest published threats.
* **[REQ-END-072 - Configure Threat Severity Default Quarantine Actions](../08-endpoints/defender/configure-threat-severity-default-quarantine-actions.md)**: By default, Defender may prompt users or take actions (like clean/ignore) that leave malware remnants on the filesystem.
* **[REQ-END-073 - Configure Family Options UI Lockdown](../08-endpoints/defender/configure-family-options-ui-lockdown.md)**: Locking down non-essential components of the Windows Security Center interface prevents users from tampering with parental or diagnostic UI controls on enterprise assets.
* **[REQ-END-074 - Configure Tamper Protection](../08-endpoints/defender/configure-tamper-protection.md)**: Configures Microsoft Defender Antivirus settings to enhance real-time endpoint protection.
* **[REQ-END-075 - Configure Sandbox Execution Environment](../08-endpoints/defender/configure-sandbox-execution-environment.md)**: Forcing the Windows Defender scanning service (MsMpEng.exe) to run in a restricted AppContainer sandbox prevents privilege escalation.
* **[REQ-END-076 - Configure AMSI Authenticode Signature Verification](../08-endpoints/defender/configure-amsi-authenticode-signature-verification.md)**: Enforcing signature checks on registered Antimalware Scan Interface (AMSI) providers blocks attackers from registering unsigned rogue AMSI provider DLLs to bypass script analysis.
* **[REQ-END-077 - Configure File Explorer SmartScreen](../08-endpoints/defender/configure-file-explorer-smartscreen.md)**: Windows Defender SmartScreen protects users from running unrecognized or potentially malicious applications downloaded from the internet.
* **[REQ-END-078 - Disable OneDrive File Sync](../08-endpoints/defender/disable-onedrive-file-sync.md)**: Configures Microsoft Defender Antivirus settings to enhance real-time endpoint protection.
* **[REQ-END-079 - Enforce Antivirus Scan on Opening Attachments](../08-endpoints/defender/enforce-antivirus-scan-on-opening-attachments.md)**: Forcing the Attachment Manager to notify the registered antivirus product when a user opens files downloaded from the web or email clients prevents initial access vectors.
* **[REQ-END-203 - Configure Remote Encryption Protection Mode](../08-endpoints/defender/configure-remote-encryption-protection.md)**: Remote Encryption Protection actively detects and terminates network ransomware attempting to encrypt files over SMB shares.

#### Attack Surface Reduction Rules (Endpoints)
* **[REQ-END-080 - ASR: Block abuse of exploited vulnerable signed drivers](../08-endpoints/defender/asr/block-vulnerable-signed-drivers.md)**: Prevents an application from writing a vulnerable signed driver to disk.
* **[REQ-END-081 - ASR: Block Adobe Reader from creating child processes](../08-endpoints/defender/asr/block-adobe-reader-child-processes.md)**: Prevents Adobe Reader from launching any child processes.
* **[REQ-END-082 - ASR: Block all Office applications from creating child processes](../08-endpoints/defender/asr/block-office-child-processes.md)**: Blocks Microsoft Office applications (Word, Excel, PowerPoint) from creating child processes.
* **[REQ-END-084 - ASR: Block executable content from email client and webmail](../08-endpoints/defender/asr/block-email-executable-content.md)**: Prevents executable files (such as .exe, .com, .scr, .vbs, .js, or .pif) from launching directly from email clients (like Outlook) or webmail accessed via browser sessions.
* **[REQ-END-085 - ASR: Block executable files from running unless they meet a prevalence, age, or trusted list criterion](../08-endpoints/defender/asr/block-low-prevalence-executable-files.md)**: Blocks execution of unrecognized, newly compiled, or low-prevalence executable files.
* **[REQ-END-086 - ASR: Block execution of potentially obfuscated scripts](../08-endpoints/defender/asr/block-obfuscated-scripts.md)**: Blocks execution of obfuscated or encrypted scripts (such as PowerShell, VBScript, or JavaScript).
* **[REQ-END-087 - ASR: Block JavaScript or VBScript from launching downloaded executable content](../08-endpoints/defender/asr/block-script-launching-downloaded-content.md)**: Prevents JavaScript or VBScript running locally from launching executable binaries that were downloaded from the internet.
* **[REQ-END-088 - ASR: Block Office applications from creating executable content](../08-endpoints/defender/asr/block-office-executable-content-creation.md)**: Prevents Microsoft Office applications (Word, Excel, PowerPoint) from creating or writing executable files (e.g., .exe, .dll, .scr) to the local filesystem.
* **[REQ-END-089 - ASR: Block Office applications from injecting code into other processes](../08-endpoints/defender/asr/block-office-code-injection.md)**: Blocks Microsoft Office applications from writing code or injecting threads directly into external processes.
* **[REQ-END-090 - ASR: Block Office communication application from creating child processes](../08-endpoints/defender/asr/block-office-communication-child-processes.md)**: Blocks Microsoft Outlook or other Office communication applications (e.g., Teams, Skype) from creating child processes.
* **[REQ-END-091 - ASR: Block persistence through WMI event subscription](../08-endpoints/defender/asr/block-wmi-event-subscription-persistence.md)**: Blocks threat actors from achieving system persistence by registering permanent Windows Management Instrumentation (WMI) event subscriptions.
* **[REQ-END-092 - ASR: Block process creations originating from PSExec and WMI commands](../08-endpoints/defender/asr/block-psexec-wmi-process-creations.md)**: Blocks processes created via WMI commands or PSExec remote execution utilities.
* **[REQ-END-093 - ASR: Block untrusted and unsigned processes that run from USB](../08-endpoints/defender/asr/block-unsigned-processes-running-from-usb.md)**: Blocks the execution of unsigned or untrusted processes on removable storage devices (USB drives, external SSDs).
* **[REQ-END-094 - ASR: Block Win32 API calls from Office macros](../08-endpoints/defender/asr/block-win32-api-calls-from-office-macros.md)**: Blocks VBA macros inside Microsoft Office documents from invoking Win32 API calls.
* **[REQ-END-095 - ASR: Use advanced protection against ransomware](../08-endpoints/defender/asr/use-advanced-protection-against-ransomware.md)**: Enforces Attack Surface Reduction (ASR) rule to mitigate exploit vectors.

#### User Profile Restrictions (Endpoints)
*Submodule Overview: [Configure User Profile Restrictions for Endpoints](../08-endpoints/configure-user-profile-restrictions.md)*

* **[REQ-END-126 - User Profile: Toast Notifications Lock Screen Restrictions](../08-endpoints/user-profile/configure-up-toast-notifications.md)**: Restricts user profile and interactive shell features to harden the desktop environment.
* **[REQ-END-127 - User Profile: Spotlight and Consumer Features Restrictions](../08-endpoints/user-profile/configure-up-spotlight-consumer.md)**: Restricts user profile and interactive shell features to harden the desktop environment.
* **[REQ-END-128 - User Profile: Windows Copilot Restrictions](../08-endpoints/user-profile/configure-up-windows-copilot.md)**: Windows Copilot is an artificial intelligence assistant deeply integrated into the Windows 11 desktop shell, Edge browser runtime, and search experience.
* **[REQ-END-129 - User Profile: In-Place Sharing Restrictions](../08-endpoints/user-profile/configure-up-inplace-sharing.md)**: In modern versions of Windows, File Explorer incorporates the "In-Place Sharing" framework (also known as the Share Flyout or Share Charm).
* **[REQ-END-130 - User Profile: Shell RunAs User Suppression](../08-endpoints/user-profile/configure-up-runas-suppression.md)**: Restricts user profile and interactive shell features to harden the desktop environment.
* **[REQ-END-131 - User Profile: Personalization and Privacy Restrictions](../08-endpoints/user-profile/configure-up-personalization-privacy.md)**: Restricts user profile and interactive shell features to harden the desktop environment.
* **[REQ-END-132 - User Profile: Group Policy Registry Policy Processing Behaviors](../08-endpoints/user-profile/configure-up-gp-processing.md)**: Group Policy processing in Windows relies on Client-Side Extensions (CSEs).
* **[REQ-END-133 - User Profile: Telemetry and Inventory Collection Restrictions](../08-endpoints/user-profile/configure-up-telemetry-inventory.md)**: Restricts user profile and interactive shell features to harden the desktop environment.
* **[REQ-END-134 - User Profile: Explorer Security and Memory Protections](../08-endpoints/user-profile/configure-up-explorer-security.md)**: Windows File Explorer (explorer.exe) is the primary interactive user shell and file management environment in Windows.
* **[REQ-END-135 - User Profile: Internet Explorer Options and Feeds Restrictions](../08-endpoints/user-profile/configure-up-ie-security.md)**: Because these legacy components remain active in the background, they represent a persistent attack surface if left unconfigured.
* **[REQ-END-136 - User Profile: Interactive Logon Warning Banners](../08-endpoints/user-profile/configure-up-logon-banners.md)**: Interactive logon configurations govern the initial security boundary when an operator or user accesses the Windows console.
* **[REQ-END-137 - User Profile: Interactive Logon Inactivity Timeout](../08-endpoints/user-profile/configure-up-inactivity-timeout.md)**: In enterprise environments, authorized employees and operators frequently leave workstations unattended—to attend meetings, take breaks, or collaborate elsewhere in the facility.
* **[REQ-END-138 - User Profile: Windows Installer Hardening](../08-endpoints/user-profile/configure-up-installer-hardening.md)**: Restricts user profile and interactive shell features to harden the desktop environment.
* **[REQ-END-139 - User Profile: Secondary Logon Service Lockdown](../08-endpoints/user-profile/configure-up-seclogon-service.md)**: Restricts user profile and interactive shell features to harden the desktop environment.
* **[REQ-END-151 - User Profile: Structured Exception Handling Overwrite Protection (SEHOP) for Endpoints](../08-endpoints/user-profile/configure-end-up-sehop.md)**: Configures maximum event log sizes and retention parameters to prevent log overwrite during security incidents on Endpoints.
* **[REQ-END-152 - User Profile: Directory Protection Mode for Endpoints](../08-endpoints/user-profile/configure-end-up-protection-mode.md)**: Restricts user profile and interactive shell features to harden the desktop environment.
* **[REQ-END-153 - User Profile: Address Space Layout Randomization (ASLR) Image Relocation for Endpoints](../08-endpoints/user-profile/configure-end-up-aslr-relocation.md)**: Address Space Layout Randomization (ASLR) is a foundational defense against memory corruption vulnerabilities.
* **[REQ-END-154 - User Profile: Speculative Execution Mitigations (Spectre/Meltdown) for Endpoints](../08-endpoints/user-profile/configure-end-up-speculative-mitigations.md)**: Restricts user profile and interactive shell features to harden the desktop environment.
* **[REQ-END-155 - User Profile: Authenticode Signature Certificate Padding Check for Endpoints](../08-endpoints/user-profile/configure-end-up-cert-padding.md)**: Restricts user profile and interactive shell features to harden the desktop environment.
* **[REQ-END-156 - User Profile: Command Processor Batch File Locking for Endpoints](../08-endpoints/user-profile/configure-end-up-lock-batch-files.md)**: The Windows Command Processor (cmd.exe) is widely utilized for system administration, software installation routines, and scheduled maintenance tasks.
* **[REQ-END-157 - User Profile: Time-Travel Debugging (TTD) Recording Policy for Endpoints](../08-endpoints/user-profile/configure-end-up-ttd-recording.md)**: Restricts user profile and interactive shell features to harden the desktop environment.
* **[REQ-END-158 - User Profile: Trusted Root Store Protected Roots Certificate Restriction for Endpoints](../08-endpoints/user-profile/configure-end-up-protected-roots.md)**: Restricts user profile and interactive shell features to harden the desktop environment.
* **[REQ-END-159 - User Profile: Disabling Injection of AppInit DLLs for Endpoints](../08-endpoints/user-profile/configure-end-up-appinit-dlls.md)**: AppInit_DLLs is a legacy Windows application infrastructure mechanism dating back to Windows NT.
* **[REQ-END-160 - User Profile: Preservation of Attachment Zone Information for Endpoints](../08-endpoints/user-profile/configure-end-up-attachment-zone.md)**: Mark-of-the-Web (MOTW) is a vital Windows defensive mechanism that tags files downloaded from the Internet or untrusted external zones with contextual provenance metadata.
* **[REQ-END-161 - User Profile: Disable Windows Game DVR for Endpoints](../08-endpoints/user-profile/configure-end-up-game-dvr.md)**: Windows Game Recording and Broadcasting (Game DVR) is a consumer-oriented multimedia subsystem built into Windows 10 and 11.
* **[REQ-END-162 - User Profile: Restrict Windows Ink Workspace on Lock Screen for Endpoints](../08-endpoints/user-profile/configure-end-up-ink-workspace.md)**: Restricts user profile and interactive shell features to harden the desktop environment.

#### System Administrative Templates (Endpoints)
*Submodule Overview: [Configure System Administrative Templates for Endpoints](../08-endpoints/configure-system-administrative-templates.md)*

* **[REQ-END-179 - Administrative Templates: Disable SMBv1 Protocol Components](../08-endpoints/admin-templates/configure-end-at-smbv1.md)**: Configures administrative template security policy to enforce baseline system hardening.
* **[REQ-END-180 - Administrative Templates: Configure NetBT Node Type and Name Release](../08-endpoints/admin-templates/configure-end-at-netbt-nodetype.md)**: Configures administrative template security policy to enforce baseline system hardening.
* **[REQ-END-181 - Administrative Templates: MSS IP Source Routing and ICMP Redirects](../08-endpoints/admin-templates/configure-end-at-mss-ip-source-routing.md)**: Configures administrative template security policy to enforce baseline system hardening.
* **[REQ-END-182 - Administrative Templates: MSS System and Session Security Protections](../08-endpoints/admin-templates/configure-end-at-mss-system-protections.md)**: The Microsoft Solutions for Security (MSS) baseline settings provide low-level kernel, session manager, and authentication subsystem protections.
* **[REQ-END-183 - Administrative Templates: Prevent Device Metadata Retrieval from Network](../08-endpoints/admin-templates/configure-end-at-device-metadata.md)**: Configures administrative template security policy to enforce baseline system hardening.
* **[REQ-END-184 - Administrative Templates: Enforce Group Policy Background Processing](../08-endpoints/admin-templates/configure-end-at-gp-processing.md)**: The Windows Group Policy service (gpsvc) manages operating system and security configurations through Client-Side Extensions (CSEs).
* **[REQ-END-185 - Administrative Templates: Disable Cross-Device Experiences](../08-endpoints/admin-templates/configure-end-at-cross-device-experiences.md)**: Configures administrative template security policy to enforce baseline system hardening.
* **[REQ-END-186 - Administrative Templates: Restrict Internet Communication and Web Downloads](../08-endpoints/admin-templates/configure-end-at-internet-communication.md)**: Configures administrative template security policy to enforce baseline system hardening.
* **[REQ-END-187 - Administrative Templates: Block Custom SSPs and APs from Loading into LSASS](../08-endpoints/admin-templates/configure-end-at-lsa-custom-ssps.md)**: Configures administrative template security policy to enforce baseline system hardening.
* **[REQ-END-188 - Administrative Templates: Logon Display and Credential Restrictions](../08-endpoints/admin-templates/configure-end-at-logon-display-options.md)**: The Windows logon desktop and lock screen represent the physical perimeter of the operating system.
* **[REQ-END-189 - Administrative Templates: Disable Connected Standby Network Connectivity](../08-endpoints/admin-templates/configure-end-at-power-connected-standby.md)**: Modern Standby (S0 Low Power Idle) replaced legacy ACPI S3 (Suspend-to-RAM) sleep states in modern enterprise laptops and convertibles.
* **[REQ-END-190 - Administrative Templates: Disable Remote Assistance](../08-endpoints/admin-templates/configure-end-at-remote-assistance.md)**: Windows Remote Assistance (msra.exe) allows support personnel to view or remotely control an active user's desktop session across a network.
* **[REQ-END-191 - Administrative Templates: Enable RPC Endpoint Mapper Client Authentication](../08-endpoints/admin-templates/configure-end-at-rpc-endpoint-mapper-auth.md)**: The Remote Procedure Call (RPC) subsystem is fundamental to Windows inter-process communication and remote management.
* **[REQ-END-192 - Administrative Templates: Configure Windows Time Service NTP Client and Server](../08-endpoints/admin-templates/configure-end-at-w32time-ntp-client.md)**: The Windows Time Service (W32Time) is a core architectural component of Windows security, providing synchronization across domain members, member servers, and directory nodes.
* **[REQ-END-193 - Administrative Templates: App Package Deployment Restrictions](../08-endpoints/admin-templates/configure-end-at-appx-deployment-restrictions.md)**: Modern Windows application packaging architectures (AppX and MSIX) allow software components to be registered and executed within user profile spaces.
* **[REQ-END-194 - Administrative Templates: Configure Biometrics Enhanced Anti-Spoofing](../08-endpoints/admin-templates/configure-end-at-biometrics-anti-spoofing.md)**: Windows Hello facial recognition provides convenient, passwordless authentication using biometric verification.
* **[REQ-END-195 - Administrative Templates: Disable Cloud Consumer Account State Content](../08-endpoints/admin-templates/configure-end-at-cloud-consumer-content.md)**: Modern editions of Windows integrate consumer-focused features into the desktop shell and operating system menus.
* **[REQ-END-196 - Administrative Templates: Require PIN for Connect Wireless Pairing](../08-endpoints/admin-templates/configure-end-at-connect-pin-pairing.md)**: The Windows Connect application enables endpoints to function as wireless display receivers using the Miracast standard over Wi-Fi Direct (IEEE 802.11 P2P).
* **[REQ-END-197 - Administrative Templates: Credential User Interface Security Protections](../08-endpoints/admin-templates/configure-end-at-credui-protections.md)**: The Windows Credential User Interface (CredUI) handles password collection dialogs and User Account Control (UAC) elevation prompts.
* **[REQ-END-198 - Administrative Templates: Diagnostic Data Collection and Preview Builds Restrictions](../08-endpoints/admin-templates/configure-end-at-data-collection-preview-builds.md)**: The Windows Diagnostic Data Collection infrastructure collects system health, performance metrics, crash dumps, and telemetry data for transmission to Microsoft cloud services.
* **[REQ-END-199 - Administrative Templates: App Installer Protocol and Execution Controls](../08-endpoints/admin-templates/configure-end-at-app-installer-controls.md)**: The Windows App Installer (AppInstaller.exe) provides deployment capabilities for MSIX, AppX, and .appinstaller manifest packages.
* **[REQ-END-200 - Administrative Templates: Event Log Maximum File Sizes and Retention Policies](../08-endpoints/admin-templates/configure-end-at-event-log-sizes.md)**: Configures administrative template security policy to enforce baseline system hardening.
* **[REQ-END-201 - Administrative Templates: File Explorer Mark of the Web and Shell Protocol Security](../08-endpoints/admin-templates/configure-end-at-file-explorer-motw.md)**: The Windows Attachment Manager and File Explorer utilize the Mark of the Web (MotW) as a core security boundary.
* **[REQ-END-202 - Administrative Templates: Internet Explorer 11 and Web Feeds Retirement Controls](../08-endpoints/admin-templates/configure-end-at-internet-explorer-retirement.md)**: Internet Explorer 11 reached official end-of-life and retirement on modern Windows platforms.
* **[REQ-END-204 - Administrative Templates: Windows Search and Cortana Privacy Restrictions](../08-endpoints/admin-templates/configure-end-at-search-cortana-restrictions.md)**: The Windows Search and Cortana infrastructure provides desktop indexing, voice recognition, and location-aware query capabilities.
* **[REQ-END-205 - Administrative Templates: Windows Store Updates and OS Upgrade Restrictions](../08-endpoints/admin-templates/configure-end-at-windows-store-restrictions.md)**: Configures administrative template security policy to enforce baseline system hardening.
* **[REQ-END-206 - Administrative Templates: Disable Windows Widgets and News Feed](../08-endpoints/admin-templates/configure-end-at-windows-widgets-dsh.md)**: Windows Widgets (in Windows 11) and the earlier News and Interests feature (in Windows 10) integrate dynamic cloud-delivered content directly into the Windows desktop taskbar.
* **[REQ-END-207 - Administrative Templates: Disable Windows Automatic Restart Sign-On (ARSO)](../08-endpoints/admin-templates/configure-end-at-automatic-restart-signon.md)**: Automatic Restart Sign-On (ARSO) is a Windows convenience feature designed to streamline post-update maintenance.
* **[REQ-END-208 - Administrative Templates: Windows Sandbox Clipboard and Network Isolation](../08-endpoints/admin-templates/configure-end-at-windows-sandbox-isolation.md)**: Windows Sandbox provides a disposable, containerized desktop environment based on Hyper-V virtualization technology.
* **[REQ-END-209 - Administrative Templates: Windows Update Deferral and Automatic Installation Policies](../08-endpoints/admin-templates/configure-end-at-windows-update-policies.md)**: Configures administrative template security policy to enforce baseline system hardening.

---

## Maintenance and Extension of the Implementation Plan

When a new technical hardening requirement is added to this guidebook, this implementation plan must be updated to maintain synchronization. Follow this process to integrate new requirements:

### 1. Security Impact & Disruption Assessment
Evaluate the new control against the following criteria to determine its priority phase:

* **Phase 0 (Architectural Foundation & Tiering)**:
  * Does the control establish global directories structures, trusts boundaries, or Tier restrictions?
* **Phase 1 (Immediate / Low Disruption or Critical Risk)**:
  * Does the control mitigate an actively exploited vulnerability class (such as coercion or name spoofing)?
  * Is it an operational or security auditing baseline needed for visibility?
  * Can it be applied with near-zero likelihood of breaking legacy systems or applications?
* **Phase 2 (Credential & Session Isolation)**:
  * Does the control isolate credential storage (LSASS), enforce account lockout thresholds, or protect authentication exchanges over the network?
* **Phase 3 (Tiering & Hardware-Rooted Protections)**:
  * Does the control require hardware features (TPM, UEFI, BitLocker, IOMMU, ELAM), enforce user rights assignments, or establish critical tiering boundaries?
* **Phase 4 (Advanced Restrictions & Fine-Tuning)**:
  * Does the control involve strict application blocklisting/allowlisting (AppLocker/WDAC), disabling services, user profile lockdown, administrative templates, or fine-tuning diagnostic parameters that require extensive verification?

### 2. Document Integration
* Open `roadmap/implementation-plan.md`.
* Locate the chosen phase section.
* Identify the correct target scope subsection (Architectural, Operations, Domain Controller, PAW, or Endpoint).
* Insert the new requirement. Ensure it is sorted in alphanumeric order by its Requirement ID.
* Use the relative markdown link syntax:
  `* **[REQ-XXX-### - Requirement Title] (../module-dir/file-name.md)**: Brief explanation. (Note: remove the space between the bracket and parenthesis in your actual implementation).`

### 3. Verify Links and Guidebook Build
After editing, run the automated verification script from a PowerShell console to ensure links resolve properly:
```powershell
.\Verify-ADHardeningDocs.ps1
```

Once verification passes, run the compilation script to update the unified guidebook file:
```powershell
py scripts/compile_docs.py
```
