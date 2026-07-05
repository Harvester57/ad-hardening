# Windows Defender Antivirus PAW Baseline and Exploit Guard

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration.
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus

---

## Rationale
Privileged Access Workstations (PAWs) represent the highest security boundary on the endpoint layer, serving as isolated systems dedicated solely to Tier 0 directory administration. If a PAW is compromised, the entire AD forest is compromised. Therefore, the built-in antimalware and exploit prevention controls must be hardened to their absolute maximum threshold.

This submodule contains individual requirement controls for each advanced protective mechanism and configuration parameter within Windows Defender Antivirus for PAWs.

---

## Legacy Impact & Compatibility
* **Administrative Operations**: Enabling the WMI/PSExec block rule means administrative scripts must be run locally or orchestrated via secure WinRM endpoints. Traditional PSExec commands from remote management consoles will be blocked, enforcing proper tier-isolated remote administration.
* **Execution Restrictions**: Since productivity suites (e.g., Office, Outlook) are strictly banned from PAWs, ASR rules targeting Microsoft Office applications are enforced as a defensive measure to prevent shadow installations or bypasses.
* **AMSI Provider Signatures**: Any third-party security agents registering as AMSI providers must have a valid, trusted Authenticode signature. Unsigned or self-signed providers will be prevented from loading.

---

## Defender Hardening Requirements for PAWs

The following Defender Antivirus configurations must be enforced on PAWs:

1. **[REQ-PAW-057 - Disable Real-Time Monitoring and Behavior Monitoring Override for PAWs](defender/disable-real-time-monitoring-and-behavior-monitoring-override.md)**
2. **[REQ-PAW-058 - Configure Potentially Unwanted Applications (PUA) Protection for PAWs](defender/configure-potentially-unwanted-applications-pua-protection.md)**
3. **[REQ-PAW-059 - Prevent Local List Merging and Exclusions Configuration for PAWs](defender/prevent-local-list-merging-and-exclusions-configuration.md)**
4. **[REQ-PAW-060 - Configure Auto Exclusions Configuration for PAWs](defender/configure-auto-exclusions-configuration.md)**
5. **[REQ-PAW-061 - Enable EDR in Block Mode for PAWs](defender/enable-edr-in-block-mode.md)**
6. **[REQ-PAW-062 - Allow Network Protection on Windows Server for PAWs](defender/allow-network-protection-on-windows-server.md)**
7. **[REQ-PAW-063 - Enable File Hash Computation for PAWs](defender/enable-file-hash-computation.md)**
8. **[REQ-PAW-064 - Configure Network Inspection System (NIS) settings for PAWs](defender/configure-network-inspection-system-nis-settings.md)**
9. **[REQ-PAW-065 - Configure OOBE Real-Time Protection and Security Intelligence for PAWs](defender/configure-oobe-real-time-protection-and-security-intelligence.md)**
10. **[REQ-PAW-066 - Enable Dynamic Signature Dropped Event Reporting for PAWs](defender/enable-dynamic-signature-dropped-event-reporting.md)**
11. **[REQ-PAW-067 - Configure Quick Scan and Scanning Exclusions for PAWs](defender/configure-quick-scan-and-scanning-exclusions.md)**
12. **[REQ-PAW-068 - Configure Scheduled Scan Parameters for PAWs](defender/configure-scheduled-scan-parameters.md)**
13. **[REQ-PAW-069 - Configure Security Intelligence Update Schedule for PAWs](defender/configure-security-intelligence-update-schedule.md)**
14. **[REQ-PAW-070 - Configure Attack Surface Reduction Rules for PAWs](defender/configure-attack-surface-reduction-rules.md)**
15. **[REQ-PAW-071 - Configure Threat Severity Default Quarantine Actions for PAWs](defender/configure-threat-severity-default-quarantine-actions.md)**
16. **[REQ-PAW-072 - Configure Family Options UI Lockdown for PAWs](defender/configure-family-options-ui-lockdown.md)**
17. **[REQ-PAW-073 - Configure Tamper Protection for PAWs](defender/configure-tamper-protection.md)**
18. **[REQ-PAW-074 - Configure Sandbox Execution Environment for PAWs](defender/configure-sandbox-execution-environment.md)**
19. **[REQ-PAW-075 - Configure AMSI Authenticode Signature Verification for PAWs](defender/configure-amsi-authenticode-signature-verification.md)**

---

## Sources & Compliance References
* **CIS Microsoft Windows 10 Benchmark**: Section 18.9 (Windows Defender Antivirus configuration parameters)
* **ANSSI Active Directory Hardening Guide**: Protective controls baselines on Privileged Access Workstations
