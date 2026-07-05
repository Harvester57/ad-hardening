# Module 1: Architecture & Administrative Tiering

This directory contains the Active Directory Administrative Tiering Model definitions, theoretical designs, and technical enforcement controls for secure, air-gapped environments.

## Architecture Treatise & Guidelines

* **[Tiering and Architecture Overview](tiering-and-architecture.md)**
  Detailed design treatise covering administrative boundaries (Tier 0, Tier 1, Tier 2), Organizational Unit layout structures, custom naming conventions, credentials hygiene, and management routing from PAWs to DCs via secure jump hosts.

## Technical Hardening Controls

1. **[REQ-ARCH-001 - Implement Active Directory Administrative Tiering Model](implement-administrative-tiering-model.md)**
   Enforces User Rights Assignment GPOs to implement the Active Directory administrative tiering model by blocking high-privilege administrators (Tier 0/1) from authenticating interactively or via network logon on lower-tier computers (Tier 1/2), preventing credential exposure in LSASS memory.

2. **[REQ-ARCH-002 - Restrict Administrative Management Protocols](restrict-mgmt-protocols.md)**
   Restricts inbound Remote Desktop (RDP) and Windows Remote Management (WinRM) administrative protocols to dedicated, secure administrative subnets and jump hosts.

3. **[REQ-ARCH-003 - Audit Privileged Groups](audit-privileged-groups.md)**
   Implements automated auditing of Tier 0 administrative Active Directory groups to detect nested memberships and unauthorized additions.

4. **[REQ-ARCH-004 - Keep Domain and Forest Functional Levels Up-To-Date](keep-functional-levels-up-to-date.md)**
   Recommends migrating Domain and Forest Functional Levels to Windows Server 2016 or higher to unlock critical security features like the Protected Users group, gMSAs, and Kerberos Armoring.

5. **[REQ-ARCH-005 - Default Domain and Domain Controllers Policies Management](default-policies-recommendations.md)**
   Provides structural guidelines to separate custom hardening policies into dedicated, modular GPOs rather than directly editing Default Domain/DC policies, protecting the forest baseline.

6. **[REQ-ARCH-006 - Harden Active Directory Domain Trusts](harden-domain-trusts.md)**
   Hardens trust relationships across forest and external boundaries by disabling SID History, enabling Quarantine (SID filtering), enforcing Selective Authentication, and blocking Kerberos TGT Delegation.

7. **[REQ-ARCH-007 - Harden Microsoft Exchange Active Directory Permissions](harden-exchange-permissions.md)**
   Removes WriteDacl and WriteOwner permissions for Exchange groups on the domain root.
