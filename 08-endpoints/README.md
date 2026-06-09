# Module 8: Endpoint Hardening

This directory defines the technical security baselines for standard client workstations (Tier 2 endpoints) operating in isolated, air-gapped domains. 

To prevent initial access and lateral movement, the following unitary technical hardening controls must be implemented:

## Technical Hardening Controls

1. **[Disable Legacy Name Resolution](disable-legacy-name-resolution.md)**
   Disables Link-Local Multicast Name Resolution (LLMNR), NetBIOS over TCP/IP, and mDNS to prevent local credential harvesting via spoofing and relay attacks.

2. **[Configure User Account Control (UAC) Policies](configure-uac-policies.md)**
   Enforces maximum UAC security behavior, requiring credential entry on the secure desktop for administrators and automatically denying elevation prompts for standard users.

3. **[Disable AutoPlay and AutoRun](disable-autoplay-autorun.md)**
   Turns off AutoPlay and AutoRun features across all drive types to prevent automatic execution of files and payloads from external media.

4. **[Block Removable Storage](block-removable-storage.md)**
   Blocks read and write access to USB drives and other removable media classes to mitigate data leakage and malware propagation.

5. **[Restrict Remote Desktop (RDP) Access](restrict-rdp-access.md)**
   Blocks incoming RDP connections to standard workstations by default, or restricts allowed connection sources to authorized administrative subnets with Network Level Authentication (NLA) enabled.

6. **[Restrict Local Administrators Group](restrict-local-admins.md)**
   Locks down local workstation administrative privileges, removing standard domain users and enforcing administrative segregation utilizing LAPS.

7. **[Windows Defender Antivirus Offline Baseline](defender-antivirus.md)**
   Configures Windows Defender Antivirus for offline operation, enabling real-time scanning, network inspection, behavioral monitoring, and preventing user modification of security exclusions.

8. **[WSUS Client Configuration](wsus-client-config.md)**
   Enforces update client registry baselines to ensure workstations pull OS patches and security signatures exclusively from the local, offline WSUS server.

9. **[Enable Secure Boot](enable-secure-boot.md)**
   Mandates hardware-rooted platform integrity checks, preventing bootkits, rootkits, and unauthorized bootloader modifications.

10. **[Enable VBS and Credential Guard](enable-vbs-credential-guard.md)**
    Activates Virtualization-Based Security (VBS) and Credential Guard to protect password hashes and Kerberos tickets in an isolated virtual container, mitigating LSASS dumping.

11. **[Configure Windows Defender Application Control](configure-wdac.md)**
    Deploys application control baselines to enforce code integrity policies, restricting the system to run only signed, authorized binaries and scripts.

12. **[Enable BitLocker and Network Unlock](enable-bitlocker.md)**
    Enforces full disk encryption with TPM and enables secure Network Unlock capabilities for standard client workstations.

13. **[UEFI Firmware Security Hardening](configure-uefi-security.md)**
    Enforces password protection, disables Compatibility Support Module (CSM)/Legacy Boot, locks boot order, and configures secure firmware update policies.

14. **[Hardware Virtualization and DMA Protection](enable-hardware-virtualization-and-dma-protection.md)**
    Enables CPU virtualization (VT-x/AMD-V) and IOMMU (VT-d/AMD-Vi) to provide the hardware-rooted platform integrity required for VBS and Kernel DMA protection.
