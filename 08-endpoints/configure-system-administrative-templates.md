# Configure System Administrative Templates

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers.
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional, Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Administrative Templates\...`
  * **Registry Location**: Multiple locations under `HKLM\SOFTWARE\Policies` and `HKLM\SYSTEM\CurrentControlSet` (see individual requirements below)

---

## Rationale
Administrative templates govern system-wide capabilities, behaviors, network protocols, diagnostic logging, and component features. Hardening these configurations reduces the attack surface and mitigates critical attack vectors, including credential theft, lateral movement, unauthorized software deployment, and remote exploitation:

1. **Protocols Hardening**: Disabling legacy SMBv1 components stops known remote code execution flaws (e.g., EternalBlue), and enforcing NetBT P-node prevents broadcast spoofing and relay attacks.
2. **Data Collection & Telemetry**: Restricting diagnostic log collection, crash dump generation, feedback prompts, and dynamic cloud settings (OneSettings) prevents in-memory credential disclosure and limits external telemetry.
3. **App & Installer Restrictions**: Disallowing per-user unsigned app packages, preventing non-admin packaged app installation, and blocking the `ms-appinstaller` protocol handler closes primary drive-by malware delivery paths.
4. **Log Retention & Forensic Buffer**: Expanding event log maximum file sizes (Application/System to 128 MB, Setup to 32 MB, Security to 1 GB) guarantees that critical security events are retained for auditing and forensic investigations.
5. **Session & Credential Security**: Restricting credential display on the lock screen, disabling Automatic Restart Sign-On (ARSO), prohibiting local password reset questions, and blocking cleartext MPR password transfers prevents credential exposure.
6. **Windows Update Management**: Disabling update pauses, managing feature update deferrals, and scheduling daily automatic installations ensures workstations remain continuously patched against active vulnerabilities.

This parent requirement coordinates the 30 individual unitary hardening requirements defined in the dedicated `admin-templates/` subsection.

---

## Legacy Impact & Compatibility
* **SMBv1 Deprecation**: Workstations cannot connect to legacy storage appliances or pre-Windows Server 2008 systems that strictly require SMBv1.
* **App Installer Protocol**: Web-based "click-to-install" links utilizing `ms-appinstaller://` will not launch automatically. Software must be installed via approved administrative deployment tools.
* **Internet Explorer 11**: Standalone IE11 is disabled and redirects to Microsoft Edge; legacy intranet sites requiring Trident rendering must be configured through Microsoft Edge IE Mode.
* **Logon & Elevation**: Password reveal buttons are hidden and UAC prompts require manual entry of administrative credentials.

---

## Administrative Templates Hardening Requirements

The following 30 unitary administrative template hardening controls must be enforced:

1. **[REQ-END-179 - Administrative Templates: Disable SMBv1 Protocol Components](admin-templates/configure-end-at-smbv1.md)**
2. **[REQ-END-180 - Administrative Templates: Configure NetBT Node Type and Name Release](admin-templates/configure-end-at-netbt-nodetype.md)**
3. **[REQ-END-181 - Administrative Templates: MSS IP Source Routing and ICMP Redirects](admin-templates/configure-end-at-mss-ip-source-routing.md)**
4. **[REQ-END-182 - Administrative Templates: MSS System and Session Security Protections](admin-templates/configure-end-at-mss-system-protections.md)**
5. **[REQ-END-183 - Administrative Templates: Prevent Device Metadata Retrieval from Network](admin-templates/configure-end-at-device-metadata.md)**
6. **[REQ-END-184 - Administrative Templates: Enforce Group Policy Background Processing](admin-templates/configure-end-at-gp-processing.md)**
7. **[REQ-END-185 - Administrative Templates: Disable Cross-Device Experiences](admin-templates/configure-end-at-cross-device-experiences.md)**
8. **[REQ-END-186 - Administrative Templates: Restrict Internet Communication and Web Downloads](admin-templates/configure-end-at-internet-communication.md)**
9. **[REQ-END-187 - Administrative Templates: Block Custom SSPs and APs from Loading into LSASS](admin-templates/configure-end-at-lsa-custom-ssps.md)**
10. **[REQ-END-188 - Administrative Templates: Logon Display and Credential Restrictions](admin-templates/configure-end-at-logon-display-options.md)**
11. **[REQ-END-189 - Administrative Templates: Disable Connected Standby Network Connectivity](admin-templates/configure-end-at-power-connected-standby.md)**
12. **[REQ-END-190 - Administrative Templates: Disable Remote Assistance](admin-templates/configure-end-at-remote-assistance.md)**
13. **[REQ-END-191 - Administrative Templates: Enable RPC Endpoint Mapper Client Authentication](admin-templates/configure-end-at-rpc-endpoint-mapper-auth.md)**
14. **[REQ-END-192 - Administrative Templates: Configure Windows Time Service NTP Client and Server](admin-templates/configure-end-at-w32time-ntp-client.md)**
15. **[REQ-END-193 - Administrative Templates: App Package Deployment Restrictions](admin-templates/configure-end-at-appx-deployment-restrictions.md)**
16. **[REQ-END-194 - Administrative Templates: Configure Biometrics Enhanced Anti-Spoofing](admin-templates/configure-end-at-biometrics-anti-spoofing.md)**
17. **[REQ-END-195 - Administrative Templates: Disable Cloud Consumer Account State Content](admin-templates/configure-end-at-cloud-consumer-content.md)**
18. **[REQ-END-196 - Administrative Templates: Require PIN for Connect Wireless Pairing](admin-templates/configure-end-at-connect-pin-pairing.md)**
19. **[REQ-END-197 - Administrative Templates: Credential User Interface Security Protections](admin-templates/configure-end-at-credui-protections.md)**
20. **[REQ-END-198 - Administrative Templates: Diagnostic Data Collection and Preview Builds Restrictions](admin-templates/configure-end-at-data-collection-preview-builds.md)**
21. **[REQ-END-199 - Administrative Templates: App Installer Protocol and Execution Controls](admin-templates/configure-end-at-app-installer-controls.md)**
22. **[REQ-END-200 - Administrative Templates: Event Log Maximum File Sizes and Retention Policies](admin-templates/configure-end-at-event-log-sizes.md)**
23. **[REQ-END-201 - Administrative Templates: File Explorer Mark of the Web and Shell Protocol Security](admin-templates/configure-end-at-file-explorer-motw.md)**
24. **[REQ-END-202 - Administrative Templates: Internet Explorer 11 and Web Feeds Retirement Controls](admin-templates/configure-end-at-internet-explorer-retirement.md)**
25. **[REQ-END-204 - Administrative Templates: Windows Search and Cortana Privacy Restrictions](admin-templates/configure-end-at-search-cortana-restrictions.md)**
26. **[REQ-END-205 - Administrative Templates: Windows Store Updates and OS Upgrade Restrictions](admin-templates/configure-end-at-windows-store-restrictions.md)**
27. **[REQ-END-206 - Administrative Templates: Disable Windows Widgets and News Feed](admin-templates/configure-end-at-windows-widgets-dsh.md)**
28. **[REQ-END-207 - Administrative Templates: Disable Windows Automatic Restart Sign-On (ARSO)](admin-templates/configure-end-at-automatic-restart-signon.md)**
29. **[REQ-END-208 - Administrative Templates: Windows Sandbox Clipboard and Network Isolation](admin-templates/configure-end-at-windows-sandbox-isolation.md)**
30. **[REQ-END-209 - Administrative Templates: Windows Update Deferral and Automatic Installation Policies](admin-templates/configure-end-at-windows-update-policies.md)**

---

## Sources & Compliance References
* **CIS Microsoft Windows Client Benchmark**: Section 18.4 (Network), Section 18.5 (MSS), Section 18.9 (System), and Section 18.10 (Windows Components)
* **ANSSI Active Directory Hardening Guide**: Recommendations on protocol minimization, credential isolation, and client baselines
* **Microsoft Security Baseline**: Windows Client Security Baseline recommendations
