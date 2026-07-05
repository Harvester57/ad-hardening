# Configure User Profile Restrictions for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration.
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: Medium
* **GPO Paths / Registry Locations**:
  * **GPO Paths**: Multiple policies under Administrative Templates and Security Settings.
  * **Registry Locations**: Stored inside local HKLM and HKCU security hives under custom settings.

---

## Rationale
Enforcing User Profile Restrictions on PAWs prevents information disclosure on locked consoles, blocks advertising or unapproved telemetry/consumer features, and locks down installer paths to guarantee administrative console isolation.

This submodule contains individual requirement rules for each User Profile restriction setting configured on Privileged Access Workstations.

---

## Legacy Impact & Compatibility
* **Minimal Impact**: Operational impact is non-existent because PAW consoles do not host standard user sessions or productivity applications. Custom drivers and management utilities must be pre-approved and signed.

---

## Enforced User Profile Restrictions on PAWs

The following individual User Profile restriction rules must be configured:

1. **[REQ-PAW-115 - User Profile: Toast Notifications Lock Screen Restrictions for PAWs](user-profile/configure-up-toast-notifications.md)**
2. **[REQ-PAW-116 - User Profile: Spotlight and Consumer Features Restrictions for PAWs](user-profile/configure-up-spotlight-consumer.md)**
3. **[REQ-PAW-117 - User Profile: Windows Copilot Restrictions for PAWs](user-profile/configure-up-windows-copilot.md)**
4. **[REQ-PAW-118 - User Profile: In-Place Sharing Restrictions for PAWs](user-profile/configure-up-inplace-sharing.md)**
5. **[REQ-PAW-119 - User Profile: Shell RunAs User Suppression for PAWs](user-profile/configure-up-runas-suppression.md)**
6. **[REQ-PAW-120 - User Profile: Personalization and Privacy Restrictions for PAWs](user-profile/configure-up-personalization-privacy.md)**
7. **[REQ-PAW-121 - User Profile: Group Policy Processing Behaviors for PAWs](user-profile/configure-up-gp-processing.md)**
8. **[REQ-PAW-122 - User Profile: Telemetry and Inventory Collection Restrictions for PAWs](user-profile/configure-up-telemetry-inventory.md)**
9. **[REQ-PAW-123 - User Profile: Explorer Security and Memory Protections for PAWs](user-profile/configure-up-explorer-security.md)**
10. **[REQ-PAW-124 - User Profile: Internet Explorer Options and Feeds Restrictions for PAWs](user-profile/configure-up-ie-security.md)**
11. **[REQ-PAW-125 - User Profile: Interactive Logon Warning Banners for PAWs](user-profile/configure-up-logon-banners.md)**
12. **[REQ-PAW-126 - User Profile: Interactive Logon Inactivity Timeout for PAWs](user-profile/configure-up-inactivity-timeout.md)**
13. **[REQ-PAW-127 - User Profile: Windows Installer Hardening for PAWs](user-profile/configure-up-installer-hardening.md)**
14. **[REQ-PAW-128 - User Profile: Secondary Logon Service Lockdown for PAWs](user-profile/configure-up-seclogon-service.md)**
15. **[REQ-PAW-129 - User Profile: Exploit Guard and Speculative Mitigations for PAWs](user-profile/configure-up-system-mitigations.md)**

---

## Sources & Compliance References
* **CIS Microsoft Windows Benchmark**: PAW workstation restrictions
* **ANSSI Active Directory Hardening Guide**: Workstation baseline guide
