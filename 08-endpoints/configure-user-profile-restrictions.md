# Configure User Profile Restrictions

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional

---

## Implementation Details
* **Priority**: Medium
* **GPO Paths / Registry Locations**:
  * **GPO Paths**: Multiple policies under Administrative Templates and Security Settings.
  * **Registry Locations**: Stored inside local HKLM and HKCU security hives under custom settings.

---

## Rationale
Securing user profile characteristics and administrative explorer behaviors prevents exposure of sensitive information, restricts arbitrary file execution pathways, disables unapproved telemetry/consumer features, and locks down potential privilege escalation points.

This submodule contains individual requirement rules for each User Profile restriction setting configured on standard client workstations.

---

## Legacy Impact & Compatibility
* **User Customization Limits**: Users cannot customize lock screen slideshows, cameras, and Windows consumer feature recommendations. Legacy applications that rely on custom DLL loads via AppInit_DLLs or dynamically self-modifying batch processes may require exclusions or manual policy configurations.

---

## Enforced User Profile Restrictions

The following individual User Profile restriction rules must be configured:

1. **[REQ-END-126 - User Profile: Toast Notifications Lock Screen Restrictions](user-profile/configure-up-toast-notifications.md)**
2. **[REQ-END-127 - User Profile: Spotlight and Consumer Features Restrictions](user-profile/configure-up-spotlight-consumer.md)**
3. **[REQ-END-128 - User Profile: Windows Copilot Restrictions](user-profile/configure-up-windows-copilot.md)**
4. **[REQ-END-129 - User Profile: In-Place Sharing Restrictions](user-profile/configure-up-inplace-sharing.md)**
5. **[REQ-END-130 - User Profile: Shell RunAs User Suppression](user-profile/configure-up-runas-suppression.md)**
6. **[REQ-END-131 - User Profile: Personalization and Privacy Restrictions](user-profile/configure-up-personalization-privacy.md)**
7. **[REQ-END-132 - User Profile: Group Policy Processing Behaviors](user-profile/configure-up-gp-processing.md)**
8. **[REQ-END-133 - User Profile: Telemetry and Inventory Collection Restrictions](user-profile/configure-up-telemetry-inventory.md)**
9. **[REQ-END-134 - User Profile: Explorer Security and Memory Protections](user-profile/configure-up-explorer-security.md)**
10. **[REQ-END-135 - User Profile: Internet Explorer Options and Feeds Restrictions](user-profile/configure-up-ie-security.md)**
11. **[REQ-END-136 - User Profile: Interactive Logon Warning Banners](user-profile/configure-up-logon-banners.md)**
12. **[REQ-END-137 - User Profile: Interactive Logon Inactivity Timeout](user-profile/configure-up-inactivity-timeout.md)**
13. **[REQ-END-138 - User Profile: Windows Installer Hardening](user-profile/configure-up-installer-hardening.md)**
14. **[REQ-END-139 - User Profile: Secondary Logon Service Lockdown](user-profile/configure-up-seclogon-service.md)**
15. **[REQ-END-140 - User Profile: Exploit Guard and Speculative Mitigations](user-profile/configure-up-system-mitigations.md)**

---

## Sources & Compliance References
* **CIS Microsoft Windows 10/11 Benchmark**: Section 18.8 (User Profile Settings)
* **ANSSI Active Directory Hardening Guide**: Client security baselines
