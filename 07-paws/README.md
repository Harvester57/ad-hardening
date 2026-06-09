# Module 7: Privileged Access Workstations (PAWs) Hardening

This directory contains the physical isolation policies and operating system security configurations required to protect Tier 0 administrative workstations.

## Technical Hardening Controls

1. **[PAW Isolation and Base Hardening](paw-hardening.md)**
   Enforces Credential Guard, Device Guard (HVCI), strict AppLocker application control policies restricting execution to approved administrators, and automated local Administrators group auditing.

2. **[Enable BitLocker for PAWs](enable-bitlocker.md)**
   Configures highly stringent BitLocker policies specifically for PAWs, requiring TPM + pre-boot Startup PIN (no Network Unlock allowed), disabling sleep/standby states (S1-S3) to prevent DMA attacks, enabling Kernel DMA Protection, and enforcing enhanced PIN rules and automatic AD recovery password rotation.
