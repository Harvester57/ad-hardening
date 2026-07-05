# Windows Defender Antivirus Baseline and Exploit Guard

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers.
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional, Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus

---

## Rationale
Windows Defender Antivirus is the primary endpoint protection suite on Windows platforms. To establish a robust defense-in-depth posture against modern endpoint threat vectors, the basic protection must be augmented with Exploit Guard, Tamper Protection, SmartScreen, and process isolation.

This submodule contains individual requirement controls for each advanced protective mechanism and configuration parameter within Windows Defender Antivirus.

---

## Legacy Impact & Compatibility
* **ASR Administrative Impact**: Enabling ASR rules can block legacy administrative scripts or third-party orchestration tools that rely on WMI/PSExec or execute obfuscated administrative wrappers. Extensive audit testing is recommended prior to broad enforcement.
* **Office Application Rules**: Rules related to Microsoft Office (e.g., blocking child processes) apply only to endpoints where productivity suites are installed. They will have no impact on member servers without Office.
* **Sandbox Boot Overhead**: Setting `MP_FORCE_USE_SANDBOX` requires a reboot to initialize the scanning process within the AppContainer sandbox. There is negligible performance overhead once initialized.
* **SmartScreen Impact**: Standard users will be blocked from launching unrecognized software. Support staff must assist with authorizing internal or uncertified custom business applications.
* **AMSI Provider Signatures**: Any third-party antimalware software that registers itself as an AMSI provider must possess a valid, trusted Authenticode signature. Unsigned or self-signed providers will be blocked from loading.

---

## Defender Hardening Requirements

The following Defender Antivirus configurations must be enforced:

1. **[REQ-END-057 - Disable Real-Time Monitoring and Behavior Monitoring Override](defender/disable-real-time-monitoring-and-behavior-monitoring-override.md)**
2. **[REQ-END-058 - Configure Potentially Unwanted Applications (PUA) Protection](defender/configure-potentially-unwanted-applications-pua-protection.md)**
3. **[REQ-END-059 - Prevent Local List Merging and Exclusions Configuration](defender/prevent-local-list-merging-and-exclusions-configuration.md)**
4. **[REQ-END-060 - Configure Auto Exclusions Configuration](defender/configure-auto-exclusions-configuration.md)**
5. **[REQ-END-061 - Prevent MAPS Local Setting Override](defender/prevent-maps-local-setting-override.md)**
6. **[REQ-END-062 - Enable EDR in Block Mode](defender/enable-edr-in-block-mode.md)**
7. **[REQ-END-063 - Allow Network Protection on Windows Server](defender/allow-network-protection-on-windows-server.md)**
8. **[REQ-END-064 - Enable File Hash Computation](defender/enable-file-hash-computation.md)**
9. **[REQ-END-065 - Configure Network Inspection System (NIS) settings](defender/configure-network-inspection-system-nis-settings.md)**
10. **[REQ-END-066 - Configure OOBE Real-Time Protection and Security Intelligence](defender/configure-oobe-real-time-protection-and-security-intelligence.md)**
11. **[REQ-END-067 - Enable Dynamic Signature Dropped Event Reporting](defender/enable-dynamic-signature-dropped-event-reporting.md)**
12. **[REQ-END-068 - Configure Quick Scan and Scanning Exclusions](defender/configure-quick-scan-and-scanning-exclusions.md)**
13. **[REQ-END-069 - Configure Scheduled Scan Parameters](defender/configure-scheduled-scan-parameters.md)**
14. **[REQ-END-070 - Configure Security Intelligence Update Schedule](defender/configure-security-intelligence-update-schedule.md)**
15. **[REQ-END-071 - Configure Attack Surface Reduction Rules](defender/configure-attack-surface-reduction-rules.md)**
16. **[REQ-END-072 - Configure Threat Severity Default Quarantine Actions](defender/configure-threat-severity-default-quarantine-actions.md)**
17. **[REQ-END-073 - Configure Family Options UI Lockdown](defender/configure-family-options-ui-lockdown.md)**
18. **[REQ-END-074 - Configure Tamper Protection](defender/configure-tamper-protection.md)**
19. **[REQ-END-075 - Configure Sandbox Execution Environment](defender/configure-sandbox-execution-environment.md)**
20. **[REQ-END-076 - Configure AMSI Authenticode Signature Verification](defender/configure-amsi-authenticode-signature-verification.md)**
21. **[REQ-END-077 - Configure File Explorer SmartScreen](defender/configure-file-explorer-smartscreen.md)**
22. **[REQ-END-078 - Disable OneDrive File Sync](defender/disable-onedrive-file-sync.md)**
23. **[REQ-END-079 - Enforce Antivirus Scan on Opening Attachments](defender/enforce-antivirus-scan-on-opening-attachments.md)**

---

## Sources & Compliance References
* **CIS Microsoft Windows 10 Benchmark**: Section 18.9 (Windows Defender Antivirus configuration parameters)
* **ANSSI Active Directory Hardening Guide**: Protective controls baselines on client workstations
