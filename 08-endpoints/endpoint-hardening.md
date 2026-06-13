# Module 8: Endpoint Hardening

This module defines the technical security baselines for standard client workstations (Tier 2 endpoints) operating in isolated, air-gapped domains. 

Standard workstations represent the largest attack surface in the Active Directory enterprise environment. To prevent initial access and lateral movement, the following unitary technical hardening controls must be implemented:

## Technical Hardening Requirements

1. **[REQ-END-001 - Harden Network Parameters and Disable Legacy Name Resolution](harden-network-and-name-resolution.md)**
   Disables Link-Local Multicast Name Resolution (LLMNR), NetBIOS over TCP/IP, and mDNS to prevent local credential harvesting via spoofing and relay attacks.

2. **[REQ-END-002 - Configure User Account Control Policies](configure-uac-policies.md)**
   Enforces maximum UAC security behavior, requiring credential entry on the secure desktop for administrators and automatically denying elevation prompts for standard users.

3. **[REQ-END-003 - Disable AutoPlay and AutoRun](disable-autoplay-autorun.md)**
   Turns off AutoPlay and AutoRun features across all drive types to prevent automatic execution of files and payloads from external media.

4. **[REQ-END-004 - Block Removable Storage](block-removable-storage.md)**
   Blocks read and write access to USB drives and other removable media classes to mitigate data leakage and malware propagation.

5. **[REQ-END-005 - Restrict Remote Desktop Access](restrict-rdp-access.md)**
   Blocks incoming RDP connections to standard workstations by default, or restricts allowed connection sources to authorized administrative subnets with Network Level Authentication (NLA) enabled.

6. **[REQ-END-006 - Restrict Local Administrators Group](restrict-local-admins.md)**
   Locks down local workstation administrative privileges, removing standard domain users and enforcing administrative segregation utilizing LAPS.

7. **[REQ-END-007 - Windows Defender Antivirus Baseline and Exploit Guard](defender-antivirus.md)**
   Configures Windows Defender Antivirus for offline operation, enabling real-time scanning, network inspection, behavioral monitoring, and preventing user modification of security exclusions.

8. **[REQ-END-008 - WSUS Client Configuration](wsus-client-config.md)**
   Enforces update client registry baselines to ensure workstations pull OS patches and security signatures exclusively from the local, offline WSUS server.

9. **[REQ-END-009 - Enable Secure Boot](enable-secure-boot.md)**
   Mandates hardware-rooted platform integrity checks, preventing bootkits, rootkits, and unauthorized bootloader modifications.

10. **[REQ-END-010 - Enable VBS and Credential Guard](enable-vbs-credential-guard.md)**
    Activates Virtualization-Based Security (VBS) and Credential Guard to protect password hashes and Kerberos tickets in an isolated virtual container, mitigating LSASS dumping.

11. **[REQ-END-011 - Configure Windows Defender Application Control](configure-wdac.md)**
    Deploys application control baselines to enforce code integrity policies, restricting the system to run only signed, authorized binaries and scripts.

12. **[REQ-END-012 - Enable BitLocker and Network Unlock](enable-bitlocker.md)**
    Enforces full disk encryption with TPM and enables secure Network Unlock capabilities for standard client workstations.

13. **[REQ-END-013 - UEFI Firmware Security Hardening](configure-uefi-security.md)**
    Enforces password protection, disables Compatibility Support Module (CSM)/Legacy Boot, locks boot order, and configures secure firmware update policies.

14. **[REQ-END-014 - Enable Hardware Virtualization and DMA Protection](enable-hardware-virtualization-and-dma-protection.md)**
    Enables CPU virtualization (VT-x/AMD-V) and IOMMU (VT-d/AMD-Vi) to provide the hardware-rooted platform integrity required for VBS and Kernel DMA protection.

15. **[REQ-END-015 - Disable Windows Platform Binary Table (WPBT)](disable-wpbt.md)**
    Disables execution of binaries supplied by the Windows Platform Binary Table (WPBT) ACPI firmware table to mitigate boot-level security bypasses.

16. **[REQ-END-016 - Configure User Rights Assignments](configure-user-rights-assignments.md)**
    Restricts critical user rights assignments (URAs) such as debugging programs, token impersonation, and local logon permissions on standard client endpoints.

17. **[REQ-END-017 - Harden DMA and Physical Security](harden-dma-and-physical-security.md)**
    Mitigates physical access threat vectors by disabling standby sleep states (S1-S3), disabling external DMA device enumeration under lock, blocking legacy SBP-2 device classes, and denying write access to removable drives without BitLocker protection.

18. **[REQ-END-018 - Configure Account and Password Policies](configure-account-policies.md)**
    Enforces local and domain-wide account settings, including account lockout thresholds, lockout observation windows, smart card removal actions, and disabling reversible password encryption.

19. **[REQ-END-019 - Configure User Profile Restrictions](configure-user-profile-restrictions.md)**
    Locks down user profile registry settings (HKCU) to disable toast notifications on the lock screen and block third-party application suggestions.

20. **[REQ-END-020 - Configure Exploit Protection Profile](configure-exploit-protection.md)**
    Configures and enforces a system-wide Microsoft Defender Exploit Protection profile to apply advanced memory mitigations (DEP, ASLR, CFG, SEHOP, Heap Integrity) on all endpoints.

21. **[REQ-END-021 - Restrict Safe Mode Access to Administrators](disable-safe-mode-for-standard-users.md)**
    Prevents standard (non-administrative) users from logging into the system while in Safe Mode by setting SafeModeBlockNonAdmins to 1.

22. **[REQ-END-022 - Block Outbound Traffic for Known LOLBins](block-lolbins-outbound-traffic.md)**
    Enforces Windows Defender Firewall outbound rules to block known Living Off the Land Binaries (LOLBins) from initiating outgoing network connections.

