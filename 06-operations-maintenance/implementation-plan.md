# Implementation Plan and Prioritized Roadmap

This document outlines the prioritized implementation plan for Domain Controllers, Endpoints, and Privileged Access Workstations (PAWs). Hardening a production Active Directory environment requires balancing security posture improvements against operational disruption and engineering effort.

To achieve this, the security controls in this guidebook are organized into five sequential phases based on their real-world impact on preventing compromise, ease of implementation, and potential compatibility impact. 

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
* **[REQ-ARCH-001 - Restrict Tier Logons](../01-architecture/restrict-tier-logons.md)**: Enforces GPO logon restrictions to isolate administrative tiers.
* **[REQ-ARCH-002 - Restrict Administrative Management Protocols](../01-architecture/restrict-mgmt-protocols.md)**: Secures management access paths.
* **[REQ-ARCH-003 - Audit Privileged Groups](../01-architecture/audit-privileged-groups.md)**: Enforces monitoring and strict controls on Tier 0 group memberships.
* **[REQ-ARCH-004 - Keep Domain and Forest Functional Levels Up-To-Date](../01-architecture/keep-functional-levels-up-to-date.md)**: Ensures modern AD security features are active.
* **[REQ-ARCH-005 - Default Domain and Domain Controllers Policies Management](../01-architecture/default-policies-recommendations.md)**: Standardizes GPO hierarchy and separates default policy links.
* **[REQ-ARCH-006 - Harden Active Directory Domain Trusts](../01-architecture/harden-domain-trusts.md)**: Configures secure trust filters and disables SID history routing where appropriate.

---

## Phase 1: Critical Risk Reduction & Operational Baselines

This phase targets the elimination of immediately exploitable vulnerability classes, including coercive authentication, protocol relaying, name resolution poisoning, and default password reuse. Crucially, it also implements the core backup baselines to ensure a recovery path exists before deeper hardening parameters are deployed.

### Security Posture Impact
* Enforces backup and restore procedures to protect against fatal misconfigurations or ransomware.
* Blocks coercion techniques (such as PetitPotam or DFSCoerce) that allow attackers to instantly compromise Domain Controllers from standard domain accounts.
* Neutralizes LLMNR/mDNS spoofing (such as Responder attacks) that capture hashes on local network segments.
* Standardizes naming schemas to ensure structured GPO audit capabilities.

### Operations & Maintenance Requirements
* **[Secure Operations and Maintenance Baseline (Backup & DR Sections)](ops-and-maintenance.md)**: Implements daily AD System State backup, offline/immutable backup isolation, and quarterly recovery drills.
* **[REQ-OPS-002 - Enable and Configure the Active Directory Recycle Bin](enable-recycle-bin.md)**: Enforces forest-wide Recycle Bin for rapid recovery of deleted objects.
* **[REQ-OPS-003 - Establish and Maintain Group Policy ADMX Central Store](maintain-gpo-templates.md)**: Prevents version drift across consoles.
* **[REQ-OPS-007 - Mandate Naming Conventions for GPOs, OUs, and User Accounts](mandate-naming-conventions.md)**: Enforces GPO/OU prefix metadata supporting GPO auditing.

### Domain Controller Requirements
* **[REQ-DC-001 - Disable SMBv1](../02-domain-controllers/disable-smbv1.md)**: Disables legacy, vulnerable file sharing protocol drivers.
* **[REQ-DC-002 - Disable Multicast Name Resolution](../02-domain-controllers/disable-multicast-name-resolution.md)**: Prevents LLMNR/mDNS spoofing on DCs.
* **[REQ-DC-003 - Disable NTLMv1](../02-domain-controllers/disable-ntlmv1.md)**: Mitigates weak cryptographic authentication.
* **[REQ-DC-008 - Disable Print Spooler Service](../02-domain-controllers/disable-print-spooler.md)**: Disables spooler to block PrintNightmare and coercion.
* **[REQ-DC-015 - Migrate SYSVOL Replication to DFSR](../02-domain-controllers/migrate-sysvol-replication-dfsr.md)**: Retires legacy FRS replication.
* **[REQ-DC-024 - Configure dSHeuristics](../02-domain-controllers/configure-dsheuristics.md)**: Restricts anonymous directory access.

### PAW Requirements
* **[REQ-PAW-003 - Restrict Local Administrators Group for PAWs](../07-paws/restrict-local-administrators.md)**: Removes standard users from local administrators.
* **[REQ-PAW-015 - Configure Secure Printing and Print Spooler Policies for PAWs](../07-paws/configure-printing-and-spooler.md)**: Disables print spooler on administrative hosts.
* **[REQ-PAW-019 - Harden Network Parameters and Disable Legacy Name Resolution](../07-paws/harden-network-and-name-resolution.md)**: Disables LLMNR/mDNS and NetBIOS on PAWs.
* **[REQ-PAW-021 - Disable AutoPlay and AutoRun for PAWs](../07-paws/disable-autoplay-autorun.md)**: Stops auto-execution from removable media.

### Endpoint Requirements
* **[REQ-END-001 - Harden Network Parameters and Disable Legacy Name Resolution](../08-endpoints/harden-network-and-name-resolution.md)**: Disables local name resolution protocol spoofing.
* **[REQ-END-003 - Disable AutoPlay and AutoRun](../08-endpoints/disable-autoplay-autorun.md)**: Disables automated optical or flash drive execution.
* **[REQ-END-006 - Restrict Local Administrators Group](../08-endpoints/restrict-local-admins.md)**: Enforces administrative segregation and limits local admin rights.
* **[REQ-END-025 - Configure Secure Printing and Print Spooler Policies](../08-endpoints/configure-printing-and-spooler.md)**: Blocks incoming print spooler calls on client hosts.

---

## Phase 2: Credential & Session Isolation (High Impact)

This phase focuses on isolating credentials inside memory and network packets to block credential dumping tools (like Mimikatz) and session hijacking. It also integrates isolated update deployment mechanisms.

### Security Posture Impact
* Enforces network cryptographic integrity via SMB signing and LDAP channel binding, stopping man-in-the-middle relays.
* Protects the Local Security Authority Subsystem Service (LSASS) process from debugging and memory reading.
* Redirects default directory containers to ensure new objects receive security policies automatically.

### Operations & Maintenance Requirements
* **[Secure Operations and Maintenance Baseline (Offline Patching Sections)](ops-and-maintenance.md)**: Implements offline WSUS metadata imports/exports (sneakernet transport).
* **[REQ-OPS-005 - Configure Dedicated WSUS for Tier 0](configure-dedicated-tier0-wsus.md)**: Secures dedicated patch servers to prevent cross-tier update spoofing.
* **[REQ-OPS-006 - Redirect Default Users and Computers Containers](redirect-default-containers.md)**: Prevents newly joined machines from staying in unmanaged default OUs.

### Domain Controller Requirements
* **[REQ-DC-004 - Enforce LDAP Server Signing](../02-domain-controllers/enforce-ldap-signing.md)**: Restricts cleartext un-signed LDAP operations.
* **[REQ-DC-005 - Enforce LDAP Channel Binding](../02-domain-controllers/enforce-ldap-channel-binding.md)**: Enforces channel binding for LDAP over SSL.
* **[REQ-DC-006 - Enable LSA Protection](../02-domain-controllers/enable-lsa-protection.md)**: Enables Protected Process Light (PPL) for LSASS.
* **[REQ-DC-007 - Disable Credential Guard](../02-domain-controllers/disable-credential-guard.md)**: Disables Credential Guard on DCs while maintaining VBS configurations to maintain compatibility.
* **[REQ-DC-009 - Enforce SMB Message Signing](../02-domain-controllers/enforce-smb-signing.md)**: Mandates SMB signing to block NTLM relaying.
* **[REQ-DC-011 - Restrict Remote SAM API Access](../02-domain-controllers/restrict-ntds-sam-api.md)**: Restricts remote account listing.
* **[REQ-DC-019 - Enforce RDP Restricted Admin Mode](../02-domain-controllers/enforce-rdp-restricted-admin.md)**: Stops administrative credential caching during RDP.
* **[REQ-DC-025 - Configure Security Options for Domain Controllers](../02-domain-controllers/configure-security-options.md)**: Locks anonymous pipe access and credential parameters.

### PAW Requirements
* **[REQ-PAW-002 - Enable LSA Protection for PAWs](../07-paws/enable-lsa-protection.md)**: Blocks LSASS memory reading on PAWs.
* **[REQ-PAW-010 - Enable VBS and Credential Guard for PAWs](../07-paws/enable-vbs-credential-guard.md)**: Uses hypervisor isolation to protect administrative tokens.
* **[REQ-PAW-020 - Configure User Account Control Policies for PAWs](../07-paws/configure-uac-policies.md)**: Configures UAC secure prompt restrictions.
* **[REQ-PAW-031 - Enforce Smart Card Logon for PAWs](../07-paws/enforce-smartcard-logon-paws.md)**: Requires hardware-backed administrative logon.

### Endpoint Requirements
* **[REQ-END-002 - Configure User Account Control Policies](../08-endpoints/configure-uac-policies.md)**: Restricts local administrator prompt behavior.
* **[REQ-END-010 - Enable VBS and Credential Guard](../08-endpoints/enable-vbs-credential-guard.md)**: Isolates LSASS secrets on Tier 2 endpoints.
* **[REQ-END-018 - Configure Account and Password Policies](../08-endpoints/configure-account-policies.md)**: Sets local lockout and complexity guidelines.
* **[REQ-END-023 - Enable LSA Protection with UEFI Lock](../08-endpoints/enable-lsa-protection.md)**: Locks LSASS protection with UEFI firmware configuration.

---

## Phase 3: Tiering & Hardware-Rooted Protections (Strategic)

This phase establishes the physical boundaries and hardware-based trust mechanisms that form the foundations of Tier 0 administrative workstations (PAWs).

### Security Posture Impact
* Assures that administrative systems cannot be modified by offline attacks (via BitLocker and firmware locks).
* Ensures the boot sequence is verified from a hardware trust anchor (TPM 2.0).
* Enforces KRBTGT password rotation to invalidate existing Kerberos tickets.

### Operations & Maintenance Requirements
* **[REQ-OPS-001 - Enforce KRBTGT Password Rotation](enforce-krbtgt-password-rotation.md)**: Implements standard 2-step rotation of the domain key ticket account.

### Domain Controller Requirements
* **[REQ-DC-010 - Restrict Kerberos Encryption Types](../02-domain-controllers/restrict-kerberos-encryption.md)**: Enforces AES-only encryption for Kerberos.
* **[REQ-DC-016 - Harden adminSDHolder Permissions](../02-domain-controllers/harden-adminsdholder-permissions.md)**: Blocks permission changes to high-privilege templates.
* **[REQ-DC-017 - Harden Microsoft DNS AD Container Permissions](../02-domain-controllers/harden-dns-container-permissions.md)**: Prevents server-level DNS hijack DLLs.
* **[REQ-DC-018 - Harden Virtualization Hosts for Domain Controllers](../02-domain-controllers/harden-dc-virtualization-hosts.md)**: Places virtualized domain controllers inside a secure Tier 0 host boundary.
* **[REQ-DC-023 - Configure User Rights Assignments for Domain Controllers](../02-domain-controllers/configure-user-rights-assignments.md)**: Limits operator rights on DCs.

### PAW Requirements
* **[REQ-PAW-004 - Enforce BitLocker with TPM and Startup PIN for PAWs](../07-paws/enable-bitlocker.md)**: Demands BitLocker with a pre-boot startup PIN.
* **[REQ-PAW-005 - UEFI Firmware Security Hardening](../07-paws/configure-uefi-security.md)**: Implements strong UEFI passwords and locks the boot order.
* **[REQ-PAW-006 - Enable Hardware Virtualization and DMA Protection](../07-paws/enable-hardware-virtualization-and-dma-protection.md)**: Configures IOMMU and virtualization flags.
* **[REQ-PAW-009 - Configure User Rights Assignments for PAWs](../07-paws/configure-user-rights-assignments.md)**: Restricts debugging, impersonation, and interactive logins on PAWs.
* **[REQ-PAW-011 - Harden DMA and Physical Security for PAWs](../07-paws/harden-dma-and-physical-security.md)**: Blocks sleep states and limits external bus operations.
* **[REQ-PAW-022 - Disable Incoming Remote Desktop Access for PAWs](../07-paws/restrict-rdp-access.md)**: Blocks remote lateral logins to administrative devices.
* **[REQ-PAW-030 - Enable Secure Boot for PAWs](../07-paws/enable-secure-boot.md)**: Locks the bootloader signatures.

### Endpoint Requirements
* **[REQ-END-005 - Restrict Remote Desktop Access](../08-endpoints/restrict-rdp-access.md)**: Prevents incoming RDP connections.
* **[REQ-END-009 - Enable Secure Boot](../08-endpoints/enable-secure-boot.md)**: Enforces boot-path signature checks.
* **[REQ-END-012 - Enable BitLocker and Network Unlock](../08-endpoints/enable-bitlocker.md)**: Protects client data storage using BitLocker.
* **[REQ-END-013 - UEFI Firmware Security Hardening](../08-endpoints/configure-uefi-security.md)**: Secures UEFI parameters on client workstations.
* **[REQ-END-014 - Enable Hardware Virtualization and DMA Protection](../08-endpoints/enable-hardware-virtualization-and-dma-protection.md)**: Enables hardware VBS requisites.
* **[REQ-END-016 - Configure User Rights Assignments](../08-endpoints/configure-user-rights-assignments.md)**: Disables token impersonation and program debugging for standard users.
* **[REQ-END-017 - Harden DMA and Physical Security](../08-endpoints/harden-dma-and-physical-security.md)**: Disables client standby states and limits DMA peripherals.

---

## Phase 4: Advanced Restrictions & Fine-Tuning (Continuous Hardening)

This phase introduces strict operational controls, software restrictions (AppLocker/WDAC), logging updates, and services minimization. Additionally, continuous offline assessment loops are established to audit security controls on an ongoing basis.

### Security Posture Impact
* Prevents the execution of unauthorized binaries, scripts, or malicious installers via application blocklists/allowlists.
* Restricts system executables (`svchost.exe`) from loading arbitrary non-Microsoft binaries.
* Audits Active Directory configurations monthly via offline scanners.

### Operations & Maintenance Requirements
* **[Secure Operations and Maintenance Baseline (Continuous Assessment)](ops-and-maintenance.md)**: Integrates monthly PingCastle scans, quarterly BloodHound analyses, and semi-annual offline database checks.
* **[REQ-OPS-004 - Implement Third-Party and Custom GPO Templates for COTS Hardening](use-third-party-templates.md)**: Standardizes security settings for custom application baselines.

### Domain Controller Requirements
* **[REQ-DC-012 - Disable Unnecessary Services on Domain Controllers](../02-domain-controllers/disable-unnecessary-services.md)**: Stops non-essential system functions.
* **[REQ-DC-013 - Enable Kerberos Armoring](../02-domain-controllers/enable-kerberos-armoring.md)**: Protects pre-authentication traffic using FAST.
* **[REQ-DC-014 - Restrict NTLM](../02-domain-controllers/restrict-ntlm.md)**: Restricts NTLM protocol fallback domain-wide.
* **[REQ-DC-020 - Windows Defender Antivirus Domain Controller Baseline and Exploit Guard](../02-domain-controllers/defender-antivirus.md)**: Applies real-time scanning and server exclusions.
* **[REQ-DC-021 - Configure AppLocker Policies on Domain Controllers](../02-domain-controllers/configure-applocker-policies.md)**: Controls binary execution on DCs.
* **[REQ-DC-022 - Enable WDAC Driver Blocklist](../02-domain-controllers/enable-wdac-driver-blocklist.md)**: Blocks known vulnerable drivers.
* **[REQ-DC-026 - Configure TCP/IP and Network Parameter Hardening for Domain Controllers](../02-domain-controllers/harden-network-parameters.md)**: Optimizes network protocol parameters.
* **[REQ-DC-027 - Configure Telemetry, Diagnostics and Privacy Options for Domain Controllers](../02-domain-controllers/configure-telemetry-privacy.md)**: Limits diagnostics collection.
* **[REQ-DC-028 - Configure Untrusted Font Blocking for Domain Controllers](../02-domain-controllers/configure-untrusted-font-blocking.md)**: Protects kernel font parser.
* **[REQ-DC-029 - Configure svchost.exe Mitigation Options](../02-domain-controllers/configure-svchost-mitigation.md)**: Limits svchost sub-process execution.

### PAW Requirements
* **[REQ-PAW-001 - Configure AppLocker Policies for PAWs](../07-paws/configure-applocker-policies.md)**: Allow-lists administration utilities.
* **[REQ-PAW-007 - Disable Windows Platform Binary Table (WPBT)](../07-paws/disable-wpbt.md)**: Protects kernel boot from firmware binary injection.
* **[REQ-PAW-008 - Windows Defender Antivirus PAW Baseline and Exploit Guard](../07-paws/defender-antivirus.md)**: Enforces real-time protection and ASR blocks.
* **[REQ-PAW-012 - Enable WDAC Driver Blocklist](../07-paws/enable-wdac-driver-blocklist.md)**: Restricts bypass drivers on PAWs.
* **[REQ-PAW-013 - Configure Account and Password Policies for PAWs](../07-paws/configure-account-policies.md)**: Configures administrative account rules.
* **[REQ-PAW-014 - Configure Early Launch Antimalware (ELAM) Policy for PAWs](../07-paws/configure-elam.md)**: Validates boot driver signatures.
* **[REQ-PAW-016 - Configure Untrusted Font Blocking for PAWs](../07-paws/configure-untrusted-font-blocking.md)**: Font isolation on administration hosts.
* **[REQ-PAW-017 - Configure svchost.exe Mitigation Options for PAWs](../07-paws/configure-svchost-mitigation.md)**: Enforces Microsoft signature check on svchost.
* **[REQ-PAW-018 - Enable Kernel-Mode Hardware-Enforced Stack Protection for PAWs](../07-paws/enable-kernel-shadow-stacks.md)**: Enforces hardware-backed ROP mitigation.
* **[REQ-PAW-023 - WSUS Client Configuration for PAWs](../07-paws/wsus-client-config.md)**: Directs updates to local WSUS servers.
* **[REQ-PAW-024 - Configure User Profile and System Restrictions for PAWs](../07-paws/configure-user-profile-restrictions.md)**: Locks administrative host profiles.
* **[REQ-PAW-025 - Configure Exploit Protection Profile for PAWs](../07-paws/configure-exploit-protection.md)**: System-wide DEP and ASLR configurations.
* **[REQ-PAW-026 - Restrict Safe Mode Access to Administrators on PAWs](../07-paws/disable-safe-mode-for-standard-users.md)**: Disables standard user access in Safe Mode.
* **[REQ-PAW-027 - Configure Windows Defender Firewall and Block LOLBins for PAWs](../07-paws/configure-windows-firewall.md)**: Firewalls and LOLBin traffic limits.
* **[REQ-PAW-028 - Disable Unnecessary System Services for PAWs](../07-paws/disable-unnecessary-system-services.md)**: Reduces active service footprints.
* **[REQ-PAW-029 - Configure System Administrative Templates for PAWs](../07-paws/configure-system-administrative-templates.md)**: Custom registry rules.

### Endpoint Requirements
* **[REQ-END-004 - Block Removable Storage](../08-endpoints/block-removable-storage.md)**: Prevents data exfiltration and USB storage execution.
* **[REQ-END-007 - Windows Defender Antivirus Baseline and Exploit Guard](../08-endpoints/defender-antivirus.md)**: Baseline real-time monitoring and ASR blocks.
* **[REQ-END-008 - WSUS Client Configuration](../08-endpoints/wsus-client-config.md)**: Updates from local offline servers only.
* **[REQ-END-011 - Configure Windows Defender Application Control](../08-endpoints/configure-wdac.md)**: Deploys code integrity rules.
* **[REQ-END-015 - Disable Windows Platform Binary Table (WPBT)](../08-endpoints/disable-wpbt.md)**: Mitigates firmware-based binary insertion.
* **[REQ-END-019 - Configure User Profile Restrictions](../08-endpoints/configure-user-profile-restrictions.md)**: Restricts HKCU features and notifications.
* **[REQ-END-020 - Configure Exploit Protection Profile](../08-endpoints/configure-exploit-protection.md)**: Memory protection profiles on client endpoints.
* **[REQ-END-021 - Restrict Safe Mode Access to Administrators](../08-endpoints/disable-safe-mode-for-standard-users.md)**: Denies standard user Safe Mode login.
* **[REQ-END-022 - Configure Windows Defender Firewall and Block LOLBins](../08-endpoints/configure-windows-firewall.md)**: Firewalls and outbound execution blocks.
* **[REQ-END-024 - Disable Unnecessary System Services](../08-endpoints/disable-unnecessary-system-services.md)**: Minimizes active service list on endpoints.
* **[REQ-END-026 - Configure System Administrative Templates](../08-endpoints/configure-system-administrative-templates.md)**: Client registry parameter sets.
* **[REQ-END-027 - Configure AppLocker Policies](../08-endpoints/configure-applocker-policies.md)**: Software execution restrictions on clients.
* **[REQ-END-028 - Configure Early Launch Antimalware (ELAM) Policy](../08-endpoints/configure-elam.md)**: Verifies driver startup list.
* **[REQ-END-029 - Configure Untrusted Font Blocking](../08-endpoints/configure-untrusted-font-blocking.md)**: Disables third-party font libraries.
* **[REQ-END-030 - Configure svchost.exe Mitigation Options](../08-endpoints/configure-svchost-mitigation.md)**: Restricts binary loading to Microsoft-signed code.
* **[REQ-END-031 - Enable Kernel-Mode Hardware-Enforced Stack Protection](../08-endpoints/enable-kernel-shadow-stacks.md)**: Mitigates Return-Oriented Programming (ROP) exploits.

---

## Maintenance and Extension of the Implementation Plan

When a new technical hardening requirement is added to this guidebook, this implementation plan must be updated to maintain synchronization. Follow this process to integrate new requirements:

### 1. Security Impact & Disruption Assessment
Evaluate the new control against the following criteria to determine its priority phase:

* **Phase 0 (Architectural Foundation & Tiering)**:
  * Does the control establish global directories structures, trusts boundaries, or Tier restrictions?
* **Phase 1 (Immediate / Low Disruption or Critical Risk)**:
  * Does the control mitigate an actively exploited vulnerability class (such as coercion or name spoofing)?
  * Can it be applied with near-zero likelihood of breaking legacy systems or applications?
* **Phase 2 (Credential & Session Isolation)**:
  * Does the control isolate credential storage (LSASS) or protect authentication exchanges over the network?
* **Phase 3 (Tiering & Hardware-Rooted Protections)**:
  * Does the control require hardware features (TPM, UEFI, BitLocker, IOMMU) or establish critical tiering boundaries?
* **Phase 4 (Advanced Restrictions & Fine-Tuning)**:
  * Does the control involve strict application blocklisting/allowlisting (AppLocker/WDAC), network segmentation, blocking LOLBins, disabling services, or fine-tuning diagnostic parameters that require extensive verification?

### 2. Document Integration
* Open `06-operations-maintenance/implementation-plan.md`.
* Locate the chosen phase section.
* Identify the correct target scope subsection (Architectural, Operations, Domain Controller, PAW, or Endpoint).
* Insert the new requirement. Ensure it is sorted in alphanumeric order by its Requirement ID.
* Use the relative markdown link syntax:
  `* **[REQ-XXX-### - Requirement Title](../<module-dir>/<file-name>.md)**: Brief explanation.`
  *(Note: For files in the same directory, omit the `../<module-dir>/` prefix).*

### 3. Verify Links and Guidebook Build
After editing, run the automated verification script from a PowerShell console to ensure links resolve properly:
```powershell
.\Verify-ADHardeningDocs.ps1
```

Once verification passes, run the compilation script to update the unified guidebook file:
```powershell
python scripts/compile_docs.py
```
