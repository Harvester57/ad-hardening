# Module 6: Secure Operations & Maintenance

This directory contains operational procedures and configuration baselines for system backups, offline patch distribution, and regular security auditing.

## Technical Hardening Controls

1. **[REQ-OPS-001 - Enforce KRBTGT Password Rotation](enforce-krbtgt-password-rotation.md)**
   Enforces and audits periodic rotation of the domain KRBTGT account password to prevent Golden Ticket attacks.

2. **[REQ-OPS-002 - Enable and Configure the Active Directory Recycle Bin](enable-recycle-bin.md)**
   Enables the forest-wide Recycle Bin optional feature to preserve all link-valued attributes and permit rapid recovery of deleted objects.

3. **[REQ-OPS-003 - Establish and Maintain Group Policy ADMX Central Store](maintain-gpo-templates.md)**
   Centralizes ADMX administrative templates within the SYSVOL share to prevent console drift and version mismatches.

4. **[REQ-OPS-004 - Implement Third-Party and Custom GPO Templates for COTS Hardening](use-third-party-templates.md)**
   Enforces standardized configuration templates to lock down third-party application configurations (browsers, reader software, security guides).

5. **[REQ-OPS-005 - Configure Dedicated WSUS for Tier 0](configure-dedicated-tier0-wsus.md)**
   Establishes and secures dedicated WSUS update server endpoints for Tier 0 assets to prevent cross-tier update spoofing.

6. **[REQ-OPS-006 - Redirect Default Users and Computers Containers](redirect-default-containers.md)**
   Redirects newly created user and computer objects to dedicated, deletion-protected Organizational Units (OUs) to enforce policy application.

7. **[REQ-OPS-007 - Mandate Naming Conventions for GPOs, OUs, and User Accounts](mandate-naming-conventions.md)**
   Enforces consistent prefixes and structures for directory objects and mandates a standard GPO description template to support programmatic auditing.

8. **[REQ-OPS-008 - Configure Daily System State Backups](configure-system-state-backups.md)**
   Enforces daily DC System State backups to secure, offline storage to enable clean bare-metal recovery.

9. **[REQ-OPS-009 - Implement Offline Patch Management via WSUS](implement-offline-patch-management.md)**
   Establishes secure, offline wsusutil metadata import/export processes for air-gapped systems.

10. **[REQ-OPS-010 - Establish Continuous Security Assessments](establish-continuous-security-assessments.md)**
    Implements a scheduled operational program of offline directory reviews using PingCastle, BloodHound/SharpHound, and ORADAD.

11. **[REQ-OPS-011 - Enable Detailed BSOD Stop Parameters for Crash Control](enable-detailed-bsod-parameters.md)**
    Enables detailed crash display screens to facilitate local hardware/system troubleshooting in isolated infrastructures.

12. **[REQ-OPS-012 - Implement Automated Inactive Computer and User Account Cleanup](decommission-inactive-accounts.md)**
    Disables and moves inactive user (180 days) and computer (90 days) accounts to a stale OU.

13. **[REQ-OPS-013 - Clean Up Staged Install From Media (IFM) Data](cleanup-staged-ifm-files.md)**
    Deletes temporary ntds.dit datasets immediately after Domain Controller promotions.

