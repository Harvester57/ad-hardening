# Module 6: Secure Operations & Maintenance

This directory contains operational procedures and configuration baselines for system backups, offline patch distribution, and regular security auditing.

## Technical Hardening Controls

1. **[Secure Operations and Maintenance Baseline](ops-and-maintenance.md)**
   Detailed requirement documenting Active Directory System State Backup and bare-metal restoration workflows, offline WSUS patch synchronization ("sneakernet" imports/exports), and continuous security analysis using offline tools (such as PingCastle and ADRecon).

2. **[REQ-OPS-001 - Enforce KRBTGT Password Rotation](enforce-krbtgt-password-rotation.md)**
   Enforces and audits periodic rotation of the domain KRBTGT account password to prevent Golden Ticket attacks.

3. **[REQ-OPS-002 - Enable and Configure the Active Directory Recycle Bin](enable-recycle-bin.md)**
   Enables the forest-wide Recycle Bin optional feature to preserve all link-valued attributes and permit rapid recovery of deleted objects.

4. **[REQ-OPS-003 - Establish and Maintain Group Policy ADMX Central Store](maintain-gpo-templates.md)**
   Centralizes ADMX administrative templates within the SYSVOL share to prevent console drift and version mismatches.

5. **[REQ-OPS-004 - Implement Third-Party and Custom GPO Templates for COTS Hardening](use-third-party-templates.md)**
   Enforces standardized configuration templates to lock down third-party application configurations (browsers, reader software, security guides).

6. **[REQ-OPS-005 - Configure Dedicated WSUS for Tier 0](configure-dedicated-tier0-wsus.md)**
   Establishes and secures dedicated WSUS update server endpoints for Tier 0 assets to prevent cross-tier update spoofing.

7. **[REQ-OPS-006 - Redirect Default Users and Computers Containers](redirect-default-containers.md)**
   Redirects newly created user and computer objects to dedicated, deletion-protected Organizational Units (OUs) to enforce policy application.

8. **[REQ-OPS-007 - Mandate Naming Conventions for GPOs, OUs, and User Accounts](mandate-naming-conventions.md)**
   Enforces consistent prefixes and structures for directory objects and mandates a standard GPO description template to support programmatic auditing.
