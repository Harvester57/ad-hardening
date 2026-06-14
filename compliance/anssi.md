# ANSSI Active Directory Hardening Compliance Matrix

This document maps the recommendations of the **ANSSI (French National Agency for the Security of Information Systems)** Active Directory Hardening Guide and related secure administration guides to the technical security controls present in this guidebook.

## Mapped ANSSI Recommendations

| ID | Recommendation Description | Category | Status | Mapped Technical Control(s) |
| :--- | :--- | :--- | :--- | :--- |
| **R1** | Define and implement a logical partitioning model (Tiering) | Tiering / Admin Boundaries | **Covered** | [REQ-ARCH-001](../01-architecture/restrict-tier-logons.md), [REQ-ARCH-002](../01-architecture/restrict-mgmt-protocols.md), [REQ-ARCH-003](../01-architecture/audit-privileged-groups.md) |
| **R2** | Limit and control administrative privileges | Account Restrictions | **Covered** | [REQ-ARCH-001](../01-architecture/restrict-tier-logons.md), [REQ-END-006](../08-endpoints/restrict-local-admins.md), [REQ-PAW-003](../07-paws/restrict-local-administrators.md) |
| **R3** | Use dedicated administrative accounts and secure stations | PAW & Admin Accounts | **Covered** | [REQ-ARCH-001](../01-architecture/restrict-tier-logons.md), [REQ-PAW-001](../07-paws/configure-applocker-policies.md), [REQ-PAW-002](../07-paws/enable-lsa-protection.md), [REQ-PAW-003](../07-paws/restrict-local-administrators.md), [REQ-PAW-004](../07-paws/enable-bitlocker.md), [REQ-PAW-005](../07-paws/configure-uefi-security.md), [REQ-PAW-006](../07-paws/enable-hardware-virtualization-and-dma-protection.md), [REQ-PAW-007](../07-paws/disable-wpbt.md), [REQ-PAW-008](../07-paws/defender-antivirus.md), [REQ-PAW-009](../07-paws/configure-user-rights-assignments.md), [REQ-PAW-010](../07-paws/enable-vbs-credential-guard.md), [REQ-PAW-011](../07-paws/harden-dma-and-physical-security.md), [REQ-PAW-012](../07-paws/enable-wdac-driver-blocklist.md), [REQ-PAW-013](../07-paws/configure-account-policies.md) |
| **R4** | Minimize services and software on Domain Controllers | Service Minimization | **Covered** | [REQ-DC-008](../02-domain-controllers/disable-print-spooler.md), [REQ-DC-012](../02-domain-controllers/disable-unnecessary-services.md) |
| **R5** | Keep Forest and Domain functional levels up-to-date | Functional Levels | **Covered** | [REQ-ARCH-004](../01-architecture/keep-functional-levels-up-to-date.md) |
| **R6** | Restrict membership of default administrative groups | Privileged Group Audit | **Covered** | [REQ-ARCH-003](../01-architecture/audit-privileged-groups.md), [REQ-ID-010](../03-identities-services/restrict-schema-admins.md) |
| **R7** | Configure IPsec transport mode for domain isolation | Network Cryptography | **Covered** | [REQ-NET-004](../04-network-firewall/configure-ipsec-domain-isolation.md), [REQ-NET-005](../04-network-firewall/harden-ipsec-cryptography.md) |
| **R8** | Restrict administration protocols to dedicated subnets and jump hosts | Management Ports & Subnets | **Covered** | [REQ-NET-001](../04-network-firewall/configure-ad-port-matrix.md), [REQ-NET-002](../04-network-firewall/restrict-rpc-dynamic-ports.md), [REQ-NET-003](../04-network-firewall/configure-workstation-isolation.md), [REQ-ARCH-002](../01-architecture/restrict-mgmt-protocols.md) |
| **R9** | Deploy Local Administrator Password Solution (LAPS) | Local Admin Passwords | **Covered** | [REQ-ID-002](../03-identities-services/enable-laps.md) |
| **R10** | Restrict authentication delegation and administrative tool execution | AppLocker / Delegation | **Covered** | [REQ-DC-021](../02-domain-controllers/configure-applocker-policies.md), [REQ-PAW-001](../07-paws/configure-applocker-policies.md) |
| **R11** | Enforce NTLM restriction policies | NTLM Restriction | **Covered** | [REQ-DC-014](../02-domain-controllers/restrict-ntlm.md) |
| **R12** | Disable obsolete name resolution protocols (LLMNR/NetBIOS) | Name Resolution | **Covered** | [REQ-DC-002](../02-domain-controllers/disable-multicast-name-resolution.md), [REQ-END-001](../08-endpoints/harden-network-and-name-resolution.md) |
| **R13** | Deprecate legacy protocols and enforce transport security | Obsolete Protocols | **Covered** | [REQ-DC-001](../02-domain-controllers/disable-smbv1.md), [REQ-DC-003](../02-domain-controllers/disable-ntlmv1.md), [REQ-DC-010](../02-domain-controllers/restrict-kerberos-encryption.md) |
| **R14** | Enforce LSA Protection and Credential Guard | Credential Isolation | **Covered** | [REQ-DC-006](../02-domain-controllers/enable-lsa-protection.md), [REQ-DC-007](../02-domain-controllers/enable-credential-guard.md) |
| **R15** | Prohibit unconstrained Kerberos delegation | Kerberos Delegation | **Covered** | [REQ-ID-004](../03-identities-services/restrict-kerberos-delegation.md) |
| **R16** | Restrict constrained Kerberos delegation | Kerberos Delegation | **Covered** | [REQ-ID-004](../03-identities-services/restrict-kerberos-delegation.md) |
| **R17** | Enforce strong Kerberos encryption algorithms (AES-only) | Kerberos Encryption | **Covered** | [REQ-DC-010](../02-domain-controllers/restrict-kerberos-encryption.md), [REQ-ID-008](../03-identities-services/enforce-user-aes-encryption.md) |
| **R18** | Harden TLS protocols, cipher suites, and elliptic curves (Schannel) | TLS / Cryptography | **Covered** | [REQ-NET-006](../04-network-firewall/harden-tls-configuration.md) |
| **R19** | Enforce LDAP server signing and client-side resolution settings | LDAP Security | **Covered** | [REQ-DC-004](../02-domain-controllers/enforce-ldap-signing.md), [REQ-NET-009](../04-network-firewall/configure-hardened-unc-paths.md) |
| **R20** | Enforce LDAP Channel Binding and Kerberos Armoring | LDAP Channel Binding | **Covered** | [REQ-DC-005](../02-domain-controllers/enforce-ldap-channel-binding.md), [REQ-DC-013](../02-domain-controllers/enable-kerberos-armoring.md) |
| **R21** | Disable SMBv1 on all network nodes | SMB Security | **Covered** | [REQ-DC-001](../02-domain-controllers/disable-smbv1.md) |
| **R22** | Enforce SMB signing and encryption | SMB Security | **Covered** | [REQ-DC-009](../02-domain-controllers/enforce-smb-signing.md), [REQ-NET-007](../04-network-firewall/enforce-smbv3-security.md) |
| **R23** | Harden and protect adminSDHolder permissions | adminSDHolder Permissions | **Covered** | [REQ-DC-016](../02-domain-controllers/harden-adminsdholder-permissions.md), [REQ-ID-013](../03-identities-services/cleanup-admincount-orphans.md) |
| **R24** | Harden Active Directory Domain Trusts (SID history/filtering) | Domain Trusts | **Covered** | [REQ-ARCH-006](../01-architecture/harden-domain-trusts.md) |
| **R35** | Implement Group Managed Service Accounts (gMSA) | Service Account Hardening | **Covered** | [REQ-ID-003](../03-identities-services/harden-service-accounts.md), [REQ-ID-014](../03-identities-services/renew-kds-keys-gmsa-secrets.md) |
| **R36** | Harden Active Directory Certificate Services (ADCS) and PKI | ADCS / PKI Hardening | **Covered** | [REQ-ID-015](../03-identities-services/harden-adcs-pki.md) |
| **R37** | Revoke obsolete and insecure certificate templates | ADCS / PKI Hardening | **Covered** | [REQ-ID-015](../03-identities-services/harden-adcs-pki.md) |
| **R47** | Harden virtualization hosts for Domain Controllers | DC Virtualization | **Covered** | [REQ-DC-018](../02-domain-controllers/harden-dc-virtualization-hosts.md) |
| **R48** | Configure advanced security audit policies | Audit Policies | **Covered** | [REQ-LOG-001](../05-logging-monitoring/configure-advanced-audit-policies.md) |
| **R50** | Configure PowerShell and command-line auditing | PowerShell Auditing | **Covered** | [REQ-LOG-002](../05-logging-monitoring/configure-powershell-and-command-line-auditing.md) |
| **R52** | Deploy and harden Sysmon and configure SIEM log shipping | Monitoring & Shipping | **Covered** | [REQ-LOG-003](../05-logging-monitoring/deploy-and-harden-sysmon.md), [REQ-LOG-004](../05-logging-monitoring/configure-siem-log-shipping.md) |
| **R54** | Establish secure Domain Controller backup and disaster recovery | Disaster Recovery | **Covered** | [REQ-OPS-002](../06-operations-maintenance/enable-recycle-bin.md), [ops-and-maintenance.md](../06-operations-maintenance/ops-and-maintenance.md) |
| **R57** | Perform continuous security assessments and privileged group audits | Security Assessments | **Covered** | [REQ-ARCH-003](../01-architecture/audit-privileged-groups.md), [ops-and-maintenance.md](../06-operations-maintenance/ops-and-maintenance.md) |
| **R58** | Deploy and harden Privileged Access Workstations (PAWs) | PAW Deployment | **Covered** | [REQ-PAW-001](../07-paws/configure-applocker-policies.md), [REQ-PAW-004](../07-paws/enable-bitlocker.md), [REQ-PAW-005](../07-paws/configure-uefi-security.md), [REQ-PAW-006](../07-paws/enable-hardware-virtualization-and-dma-protection.md) |
| **R64** | Configure Active Directory Authentication Silos and Policies | Authentication Silos | **Covered** | [REQ-ID-012](../03-identities-services/configure-authentication-silos.md) |
| **R80** | Configure Authentication Policies for administrative groups | Authentication Silos | **Covered** | [REQ-ID-012](../03-identities-services/configure-authentication-silos.md) |

## Administrative / Operational Recommendations (Out of Scope)

The following ANSSI secure administration recommendations relate to organizational policy, administrative processes, physical security, or user training, which are outside the scope of technical GPO or PowerShell controls:

| ID | Recommendation Description | Category | Status | Notes |
| :--- | :--- | :--- | :--- | :--- |
| **R26** | Inform administrators of security policies | Governance | **Not Covered** | Organizational policy / administrative training. |
| **R27** | Maintain an up-to-date registry of administrative actions | Operations | **Not Covered** | Operational procedure / manual record-keeping. |
| **R30** | Periodically audit administration workstations | Operations | **Not Covered** | Process-based vulnerability scans and compliance checks. |
| **R31** | Physically secure administration environments | Physical Security | **Not Covered** | Server room access controls, locked server racks, etc. |
| **R32** | Establish separate domain names for administration zones | Architecture | **Not Covered** | Organizational DNS design recommendation. |