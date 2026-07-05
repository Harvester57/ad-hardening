# Windows Defender Antivirus Domain Controller Baseline and Exploit Guard

## Target Scope
* **Applicable Systems**: Domain Controllers.
* **Operating Systems**: Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus

---

## Rationale
Domain Controllers are the most critical assets in an Active Directory environment, containing the Active Directory database (NTDS.dit) and credential material for the entire enterprise. Because Domain Controllers are Tier 0 assets, protective security agents running on them must be hardened to prevent credential access, lateral movement, and tampering.

This submodule contains individual requirement controls for each advanced protective mechanism and configuration parameter within Windows Defender Antivirus for Domain Controllers.

---

## Legacy Impact & Compatibility
* **ASR PSExec and WMI Rule**: Enforcing "Block process creations originating from PSExec and WMI commands" (`d1e49aac-8f56-4280-b9ba-993a6d77406c`) can disrupt enterprise remote administration, monitoring agents, and backup orchestrators. In environments utilizing such orchestrators, this rule should be set to **Audit** mode or configured with explicit process exclusions rather than hard Block mode.
* **Office Application Rules**: Rules targeting Microsoft Office or Adobe applications are documented but will not affect Domain Controllers, as these applications must never be installed on Tier 0 systems.
* **Reboot Requirement**: Activating Sandbox Execution via `MP_FORCE_USE_SANDBOX` requires a reboot of the Domain Controllers to take effect. This should be scheduled during standard maintenance windows.
* **AMSI Provider Signatures**: Any third-party security agents registering as AMSI providers must have a valid, trusted Authenticode signature. Unsigned or self-signed providers will be prevented from loading.

---

## Defender Hardening Requirements for Domain Controllers

The following Defender Antivirus configurations must be enforced on Domain Controllers:

1. **[REQ-DC-075 - Disable Real-Time Monitoring and Behavior Monitoring Override on Domain Controllers](defender/disable-real-time-monitoring-and-behavior-monitoring-override.md)**
2. **[REQ-DC-076 - Configure Potentially Unwanted Applications (PUA) Protection on Domain Controllers](defender/configure-potentially-unwanted-applications-pua-protection.md)**
3. **[REQ-DC-077 - Prevent Local List Merging and Exclusions Configuration on Domain Controllers](defender/prevent-local-list-merging-and-exclusions-configuration.md)**
4. **[REQ-DC-078 - Configure Auto Exclusions Configuration on Domain Controllers](defender/configure-auto-exclusions-configuration.md)**
5. **[REQ-DC-079 - Prevent MAPS Local Setting Override on Domain Controllers](defender/prevent-maps-local-setting-override.md)**
6. **[REQ-DC-080 - Enable EDR in Block Mode on Domain Controllers](defender/enable-edr-in-block-mode.md)**
7. **[REQ-DC-081 - Allow Network Protection on Windows Server on Domain Controllers](defender/allow-network-protection-on-windows-server.md)**
8. **[REQ-DC-082 - Enable File Hash Computation on Domain Controllers](defender/enable-file-hash-computation.md)**
9. **[REQ-DC-083 - Configure Network Inspection System (NIS) settings on Domain Controllers](defender/configure-network-inspection-system-nis-settings.md)**
10. **[REQ-DC-084 - Configure OOBE Real-Time Protection and Security Intelligence on Domain Controllers](defender/configure-oobe-real-time-protection-and-security-intelligence.md)**
11. **[REQ-DC-085 - Enable Dynamic Signature Dropped Event Reporting on Domain Controllers](defender/enable-dynamic-signature-dropped-event-reporting.md)**
12. **[REQ-DC-086 - Disable Generic Reports on Domain Controllers](defender/disable-generic-reports.md)**
13. **[REQ-DC-087 - Configure Behavioral Network Brute Force Protection Aggressiveness on Domain Controllers](defender/configure-brute-force-protection.md)**
14. **[REQ-DC-088 - Configure Behavioral Network Remote Encryption Protection Aggressiveness on Domain Controllers](defender/configure-remote-encryption-protection.md)**
15. **[REQ-DC-089 - Configure Quick Scan and Scanning Exclusions on Domain Controllers](defender/configure-quick-scan-and-scanning-exclusions.md)**
16. **[REQ-DC-090 - Configure Scheduled Scan Parameters on Domain Controllers](defender/configure-scheduled-scan-parameters.md)**
17. **[REQ-DC-091 - Configure Security Intelligence Update Schedule on Domain Controllers](defender/configure-security-intelligence-update-schedule.md)**
18. **[REQ-DC-092 - Configure Attack Surface Reduction Rules on Domain Controllers](defender/configure-attack-surface-reduction-rules.md)**
19. **[REQ-DC-093 - Configure Threat Severity Default Quarantine Actions on Domain Controllers](defender/configure-threat-severity-default-quarantine-actions.md)**
20. **[REQ-DC-094 - Configure Family Options UI Lockdown on Domain Controllers](defender/configure-family-options-ui-lockdown.md)**
21. **[REQ-DC-095 - Configure Tamper Protection on Domain Controllers](defender/configure-tamper-protection.md)**
22. **[REQ-DC-096 - Configure Sandbox Execution Environment on Domain Controllers](defender/configure-sandbox-execution-environment.md)**
23. **[REQ-DC-097 - Configure AMSI Authenticode Signature Verification on Domain Controllers](defender/configure-amsi-authenticode-signature-verification.md)**

---

## Sources & Compliance References
* **CIS Microsoft Windows Server Benchmark**: Section 18.9 (Windows Defender Antivirus configuration parameters)
* **ANSSI Active Directory Hardening Guide**: Protective controls baselines on Domain Controllers
