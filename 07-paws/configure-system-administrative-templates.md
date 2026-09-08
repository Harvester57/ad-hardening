# Configure System Administrative Templates for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration.
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Administrative Templates\...`
  * **Registry Location**: Multiple locations under `HKLM\SOFTWARE\Policies` and `HKLM\SYSTEM\CurrentControlSet` (see individual requirements below)

---

## Rationale
Privileged Access Workstations (PAWs) are dedicated exclusively to Tier 0 directory administration and Active Directory forest management. Compromise of a PAW leads directly to total domain compromise. Administrative template configurations on PAWs must enforce an absolute maximum security boundary, disabling non-essential features, legacy protocols, untrusted URI handlers, background telemetry, and unneeded consumer services:

1. **Protocols Hardening**: Disabling legacy SMBv1 components stops known remote code execution flaws, and enforcing NetBT P-node prevents broadcast spoofing and relay attacks.
2. **Data Collection & Telemetry**: Restricting diagnostic log collection, crash dump generation, feedback prompts, and dynamic cloud settings (OneSettings) prevents in-memory credential disclosure and eliminates external telemetry on Tier 0 stations.
3. **App & Installer Restrictions**: Disallowing per-user unsigned app packages, preventing non-admin packaged app installation, and blocking the `ms-appinstaller` protocol handler closes drive-by malware delivery vectors.
4. **Log Retention & Forensic Buffer**: Expanding event log maximum file sizes (Application/Setup/System to 32 MB, Security to 192 MB) guarantees that administrative security events are retained for auditing and forensic investigations.
5. **Session & Credential Security**: Restricting credential display on the lock screen, disabling Automatic Restart Sign-On (ARSO), prohibiting local password reset questions, and blocking cleartext MPR password transfers prevents credential exposure.
6. **Windows Update Management**: Disabling update pauses, managing feature update deferrals, and scheduling daily automatic installations ensures PAWs remain continuously patched against active vulnerabilities.

This parent requirement coordinates the 31 individual unitary hardening requirements defined in the dedicated `admin-templates/` subsection for PAWs.

---

## Legacy Impact & Compatibility
* **SMBv1 Deprecation**: PAWs cannot connect to legacy storage appliances or pre-Windows Server 2008 systems that strictly require SMBv1. Tier 0 administrative management does not require SMBv1.
* **App Installer Protocol**: Web-based "click-to-install" links utilizing `ms-appinstaller://` will not launch automatically. Software must be installed via approved administrative deployment tools.
* **Internet Explorer 11**: Standalone IE11 is disabled and redirects to Microsoft Edge; web browsing on PAWs is strictly prohibited or restricted to approved administrative portals.
* **Logon & Elevation**: Password reveal buttons are hidden and UAC prompts require manual entry of administrative credentials.

---

## Administrative Templates Hardening Requirements for PAWs

The following 31 unitary administrative template hardening controls must be enforced on PAWs:

1. **[REQ-PAW-168 - Administrative Templates: Disable SMBv1 Protocol Components for PAWs](admin-templates/configure-paw-at-smbv1.md)**
2. **[REQ-PAW-169 - Administrative Templates: Configure NetBT Node Type and Name Release for PAWs](admin-templates/configure-paw-at-netbt-nodetype.md)**
3. **[REQ-PAW-170 - Administrative Templates: MSS IP Source Routing and ICMP Redirects for PAWs](admin-templates/configure-paw-at-mss-ip-source-routing.md)**
4. **[REQ-PAW-171 - Administrative Templates: MSS System and Session Security Protections for PAWs](admin-templates/configure-paw-at-mss-system-protections.md)**
5. **[REQ-PAW-172 - Administrative Templates: Prevent Device Metadata Retrieval from Network for PAWs](admin-templates/configure-paw-at-device-metadata.md)**
6. **[REQ-PAW-173 - Administrative Templates: Enforce Group Policy Background Processing for PAWs](admin-templates/configure-paw-at-gp-processing.md)**
7. **[REQ-PAW-174 - Administrative Templates: Disable Cross-Device Experiences for PAWs](admin-templates/configure-paw-at-cross-device-experiences.md)**
8. **[REQ-PAW-175 - Administrative Templates: Restrict Internet Communication and Web Downloads for PAWs](admin-templates/configure-paw-at-internet-communication.md)**
9. **[REQ-PAW-176 - Administrative Templates: Block Custom SSPs and APs from Loading into LSASS for PAWs](admin-templates/configure-paw-at-lsa-custom-ssps.md)**
10. **[REQ-PAW-177 - Administrative Templates: Logon Display and Credential Restrictions for PAWs](admin-templates/configure-paw-at-logon-display-options.md)**
11. **[REQ-PAW-178 - Administrative Templates: Disable Connected Standby Network Connectivity for PAWs](admin-templates/configure-paw-at-power-connected-standby.md)**
12. **[REQ-PAW-179 - Administrative Templates: Disable Remote Assistance for PAWs](admin-templates/configure-paw-at-remote-assistance.md)**
13. **[REQ-PAW-180 - Administrative Templates: Enable RPC Endpoint Mapper Client Authentication for PAWs](admin-templates/configure-paw-at-rpc-endpoint-mapper-auth.md)**
14. **[REQ-PAW-181 - Administrative Templates: Configure Windows Time Service NTP Client and Server for PAWs](admin-templates/configure-paw-at-w32time-ntp-client.md)**
15. **[REQ-PAW-182 - Administrative Templates: App Package Deployment Restrictions for PAWs](admin-templates/configure-paw-at-appx-deployment-restrictions.md)**
16. **[REQ-PAW-183 - Administrative Templates: Configure Biometrics Enhanced Anti-Spoofing for PAWs](admin-templates/configure-paw-at-biometrics-anti-spoofing.md)**
17. **[REQ-PAW-184 - Administrative Templates: Disable Cloud Consumer Account State Content for PAWs](admin-templates/configure-paw-at-cloud-consumer-content.md)**
18. **[REQ-PAW-185 - Administrative Templates: Require PIN for Connect Wireless Pairing for PAWs](admin-templates/configure-paw-at-connect-pin-pairing.md)**
19. **[REQ-PAW-186 - Administrative Templates: Credential User Interface Security Protections for PAWs](admin-templates/configure-paw-at-credui-protections.md)**
20. **[REQ-PAW-187 - Administrative Templates: Diagnostic Data Collection and Preview Builds Restrictions for PAWs](admin-templates/configure-paw-at-data-collection-preview-builds.md)**
21. **[REQ-PAW-188 - Administrative Templates: App Installer Protocol and Execution Controls for PAWs](admin-templates/configure-paw-at-app-installer-controls.md)**
22. **[REQ-PAW-189 - Administrative Templates: Event Log Maximum File Sizes and Retention Policies for PAWs](admin-templates/configure-paw-at-event-log-sizes.md)**
23. **[REQ-PAW-190 - Administrative Templates: File Explorer Mark of the Web and Shell Protocol Security for PAWs](admin-templates/configure-paw-at-file-explorer-motw.md)**
24. **[REQ-PAW-191 - Administrative Templates: Internet Explorer 11 and Web Feeds Retirement Controls for PAWs](admin-templates/configure-paw-at-internet-explorer-retirement.md)**
25. **[REQ-PAW-192 - Administrative Templates: Windows Defender Scan and Exploit Protection Overrides for PAWs](admin-templates/configure-paw-at-defender-protection-options.md)**
26. **[REQ-PAW-193 - Administrative Templates: Windows Search and Cortana Privacy Restrictions for PAWs](admin-templates/configure-paw-at-search-cortana-restrictions.md)**
27. **[REQ-PAW-194 - Administrative Templates: Windows Store Updates and OS Upgrade Restrictions for PAWs](admin-templates/configure-paw-at-windows-store-restrictions.md)**
28. **[REQ-PAW-195 - Administrative Templates: Disable Windows Widgets and News Feed for PAWs](admin-templates/configure-paw-at-windows-widgets-dsh.md)**
29. **[REQ-PAW-196 - Administrative Templates: Disable Windows Automatic Restart Sign-On (ARSO) for PAWs](admin-templates/configure-paw-at-automatic-restart-signon.md)**
30. **[REQ-PAW-197 - Administrative Templates: Windows Sandbox Clipboard and Network Isolation for PAWs](admin-templates/configure-paw-at-windows-sandbox-isolation.md)**
31. **[REQ-PAW-198 - Administrative Templates: Windows Update Deferral and Automatic Installation Policies for PAWs](admin-templates/configure-paw-at-windows-update-policies.md)**

---

## Sources & Compliance References
* **CIS Microsoft Windows Client Benchmark**: Section 18.4 (Network), Section 18.5 (MSS), Section 18.9 (System), and Section 18.10 (Windows Components)
* **ANSSI Active Directory Hardening Guide**: Recommendations for Tier 0 Privileged Access Workstations (PAWs)
* **Microsoft Security Baseline**: Windows Security Baseline for Privileged Access Workstations
