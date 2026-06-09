# Module 7: Privileged Access Workstations (PAWs) Hardening

This directory contains the physical isolation policies and operating system security configurations required to protect Tier 0 administrative workstations.

## Technical Hardening Controls

1. **[PAW Isolation and Base Hardening](paw-hardening.md)**
   Enforces Credential Guard, Device Guard (HVCI), strict AppLocker application control policies restricting execution to approved administrators, and automated local Administrators group auditing.

2. **[Enable BitLocker for PAWs](enable-bitlocker.md)**
   Configures highly stringent BitLocker policies specifically for PAWs, requiring TPM + pre-boot Startup PIN (no Network Unlock allowed), disabling sleep/standby states (S1-S3) to prevent DMA attacks, enabling Kernel DMA Protection, and enforcing enhanced PIN rules and automatic AD recovery password rotation.

3. **[UEFI Firmware Security Hardening](configure-uefi-security.md)**
   Enforces UEFI firmware locking, setting a strong BIOS administrator password, disabling CSM/Legacy boot, locking the boot order, and protecting against BIOS rollbacks.

4. **[Hardware Virtualization and DMA Protection](enable-hardware-virtualization-and-dma-protection.md)**
   Enables hardware CPU virtualization, IOMMU/DMA protection at the firmware level, and TPM 2.0 to provide the necessary platform integrity foundation for Virtualization-Based Security (VBS).
