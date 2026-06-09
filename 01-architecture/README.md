# Module 1: Architecture & Administrative Tiering

This directory contains the Active Directory Administrative Tiering Model definitions, theoretical designs, and technical enforcement controls for secure, air-gapped environments.

## Architecture Treatise & Guidelines

* **[Tiering and Architecture Overview](tiering-and-architecture.md)**
  Detailed design treatise covering administrative boundaries (Tier 0, Tier 1, Tier 2), Organizational Unit layout structures, custom naming conventions, credentials hygiene, and management routing from PAWs to DCs via secure jump hosts.

## Technical Hardening Controls

1. **[Restrict Tier Logons](restrict-tier-logons.md)**
   Enforces User Rights Assignment GPOs to block high-privilege administrators (Tier 0/1) from authenticating interactively or via network logon on lower-tier computers (Tier 1/2), preventing credential exposure in LSASS memory.

2. **[Restrict Administrative Management Protocols](restrict-mgmt-protocols.md)**
   Restricts inbound Remote Desktop (RDP) and Windows Remote Management (WinRM) administrative protocols to dedicated, secure administrative subnets and jump hosts.

3. **[Audit Privileged Groups](audit-privileged-groups.md)**
   Implements automated auditing of Tier 0 administrative Active Directory groups to detect nested memberships and unauthorized additions.
