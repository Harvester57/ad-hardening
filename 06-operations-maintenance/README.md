# Module 6: Secure Operations & Maintenance

This directory contains operational procedures and configuration baselines for system backups, offline patch distribution, and regular security auditing.

## Technical Hardening Controls

1. **[Secure Operations and Maintenance Baseline](ops-and-maintenance.md)**
   Detailed requirement documenting Active Directory System State Backup and bare-metal restoration workflows, offline WSUS patch synchronization ("sneakernet" imports/exports), and continuous security analysis using offline tools (such as PingCastle and ADRecon).

2. **[Enforce KRBTGT Password Rotation](enforce-krbtgt-password-rotation.md)**
   Enforces and audits periodic rotation of the domain KRBTGT account password to prevent Golden Ticket attacks.

3. **[Enable and Configure Active Directory Recycle Bin](enable-recycle-bin.md)**
   Enables the forest-wide Recycle Bin optional feature to preserve all link-valued attributes and permit rapid recovery of deleted objects.

4. **[Establish and Maintain Group Policy ADMX Central Store](maintain-gpo-templates.md)**
   Centralizes ADMX administrative templates within the SYSVOL share to prevent console drift and version mismatches.

5. **[Implement Third-Party and Custom GPO Templates for COTS Hardening](use-third-party-templates.md)**
   Enforces standardized configuration templates to lock down third-party application configurations (browsers, reader software, security guides).

