# Module 6: Secure Operations & Maintenance

This directory contains operational procedures and configuration baselines for system backups, offline patch distribution, and regular security auditing.

## Technical Hardening Controls

1. **[Secure Operations and Maintenance Baseline](ops-and-maintenance.md)**
   Detailed requirement documenting Active Directory System State Backup and bare-metal restoration workflows, offline WSUS patch synchronization ("sneakernet" imports/exports), and continuous security analysis using offline tools (such as PingCastle and ADRecon).

2. **[Enforce KRBTGT Password Rotation](enforce-krbtgt-password-rotation.md)**
   Enforces and audits periodic rotation of the domain KRBTGT account password to prevent Golden Ticket attacks.

