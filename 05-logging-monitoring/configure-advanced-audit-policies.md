# Configure Advanced Security Audit Policies

## Target Scope
* **Applicable Systems**: Domain Controllers, Member Servers, Tier 2 Client Workstations.
* **Operating Systems**: Windows Server 2016 (and above), Windows 10/11 Enterprise.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**: Stored under `Advanced Audit Policy Configuration` and Lsa registry overrides.

---

## Rationale
Standard Windows event logging is basic and fails to capture critical event vectors, leading to visibility gaps during compromises. Enforcing refined subcategory audit policies ensures detailed Success and Failure logs for logon attempts, privilege use, process creations, and registry modifications without overloading log stores.

This module is split into profile-specific advanced audit submodules mapping to each system's security tier.

---

## Modular Profile Audit Policies

### 1. Domain Controller Audit Submodule (Module 2)
The complete set of advanced audit policies for Domain Controllers:
* **[REQ-DC-136 - Audit Policy: Advanced Audit Policy Overrides](../02-domain-controllers/audit-policy/configure-dc-audit-audit-override.md)**
* **[REQ-DC-137 - Audit Policy: Account Logon Auditing](../02-domain-controllers/audit-policy/configure-dc-audit-account-logon.md)**
* **[REQ-DC-138 - Audit Policy: Account Management Auditing](../02-domain-controllers/audit-policy/configure-dc-audit-account-management.md)**
* **[REQ-DC-139 - Audit Policy: Detailed Tracking Auditing](../02-domain-controllers/audit-policy/configure-dc-audit-detailed-tracking.md)**
* **[REQ-DC-140 - Audit Policy: Directory Service Access Auditing](../02-domain-controllers/audit-policy/configure-dc-audit-ds-access.md)**
* **[REQ-DC-141 - Audit Policy: Logon and Logoff Auditing](../02-domain-controllers/audit-policy/configure-dc-audit-logon-logoff.md)**
* **[REQ-DC-142 - Audit Policy: Object Access Auditing](../02-domain-controllers/audit-policy/configure-dc-audit-object-access.md)**
* **[REQ-DC-143 - Audit Policy: Policy Change Auditing](../02-domain-controllers/audit-policy/configure-dc-audit-policy-change.md)**
* **[REQ-DC-144 - Audit Policy: Privilege Use Auditing](../02-domain-controllers/audit-policy/configure-dc-audit-privilege-use.md)**
* **[REQ-DC-145 - Audit Policy: System Events Auditing](../02-domain-controllers/audit-policy/configure-dc-audit-system-events.md)**

### 2. PAW Audit Submodule (Module 7)
The complete set of advanced audit policies for Privileged Access Workstations:
* **[REQ-PAW-130 - Audit Policy: Advanced Audit Policy Overrides for PAWs](../07-paws/audit-policy/configure-paw-audit-audit-override.md)**
* **[REQ-PAW-131 - Audit Policy: Account Logon Auditing for PAWs](../07-paws/audit-policy/configure-paw-audit-account-logon.md)**
* **[REQ-PAW-132 - Audit Policy: Account Management Auditing for PAWs](../07-paws/audit-policy/configure-paw-audit-account-management.md)**
* **[REQ-PAW-133 - Audit Policy: Detailed Tracking Auditing for PAWs](../07-paws/audit-policy/configure-paw-audit-detailed-tracking.md)**
* **[REQ-PAW-134 - Audit Policy: Logon and Logoff Auditing for PAWs](../07-paws/audit-policy/configure-paw-audit-logon-logoff.md)**
* **[REQ-PAW-135 - Audit Policy: Object Access Auditing for PAWs](../07-paws/audit-policy/configure-paw-audit-object-access.md)**
* **[REQ-PAW-136 - Audit Policy: Policy Change Auditing for PAWs](../07-paws/audit-policy/configure-paw-audit-policy-change.md)**
* **[REQ-PAW-137 - Audit Policy: Privilege Use Auditing for PAWs](../07-paws/audit-policy/configure-paw-audit-privilege-use.md)**
* **[REQ-PAW-138 - Audit Policy: System Events Auditing for PAWs](../07-paws/audit-policy/configure-paw-audit-system-events.md)**

### 3. Endpoint Audit Submodule (Module 8)
The complete set of advanced audit policies for Client Workstations:
* **[REQ-END-141 - Audit Policy: Advanced Audit Policy Overrides for Endpoints](../08-endpoints/audit-policy/configure-end-audit-audit-override.md)**
* **[REQ-END-142 - Audit Policy: Account Logon Auditing for Endpoints](../08-endpoints/audit-policy/configure-end-audit-account-logon.md)**
* **[REQ-END-143 - Audit Policy: Account Management Auditing for Endpoints](../08-endpoints/audit-policy/configure-end-audit-account-management.md)**
* **[REQ-END-144 - Audit Policy: Detailed Tracking Auditing for Endpoints](../08-endpoints/audit-policy/configure-end-audit-detailed-tracking.md)**
* **[REQ-END-145 - Audit Policy: Logon and Logoff Auditing for Endpoints](../08-endpoints/audit-policy/configure-end-audit-logon-logoff.md)**
* **[REQ-END-146 - Audit Policy: Object Access Auditing for Endpoints](../08-endpoints/audit-policy/configure-end-audit-object-access.md)**
* **[REQ-END-147 - Audit Policy: Policy Change Auditing for Endpoints](../08-endpoints/audit-policy/configure-end-audit-policy-change.md)**
* **[REQ-END-148 - Audit Policy: Privilege Use Auditing for Endpoints](../08-endpoints/audit-policy/configure-end-audit-privilege-use.md)**
* **[REQ-END-149 - Audit Policy: System Events Auditing for Endpoints](../08-endpoints/audit-policy/configure-end-audit-system-events.md)**

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Recommendation R48
* **CIS Microsoft Windows Benchmarks**: Section 9 and 17
