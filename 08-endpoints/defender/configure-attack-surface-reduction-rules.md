# Configure Attack Surface Reduction Rules

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers.
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional, Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\Windows Defender Exploit Guard\Attack Surface Reduction

---

## Rationale
Attack Surface Reduction (ASR) rules targets software behaviors that are frequently abused by malware, such as launching executable files from email attachments, spawning child processes from Office apps or PDF viewers, credential theft from LSASS, and writing unsigned files from USB.

This submodule contains individual requirement rules for each ASR control enforced on standard workstations.

---

## Legacy Impact & Compatibility
* **Detailed Audit Phase**: ASR rules should first be deployed in **Audit** mode to collect telemetry in the Windows Event Logs (Event ID `1121` or `1122`). This allows administrators to configure exclusions before switching to **Block** mode (`1`).
* **Macro/Office Dependencies**: Organizations relying on advanced inter-process Office communication or macros running system API calls will experience disruptions. Software configurations or ASR exclusion groups must be updated.

---

## Enforced Attack Surface Reduction Rules

The following individual ASR rules must be configured in Block mode:

1. **[REQ-END-080 - ASR: Block abuse of exploited vulnerable signed drivers](asr/block-vulnerable-signed-drivers.md)**
2. **[REQ-END-081 - ASR: Block Adobe Reader from creating child processes](asr/block-adobe-reader-child-processes.md)**
3. **[REQ-END-082 - ASR: Block all Office applications from creating child processes](asr/block-office-child-processes.md)**
4. **[REQ-END-083 - ASR: Block credential stealing from the Windows local security authority subsystem](asr/block-lsass-credential-stealing.md)**
5. **[REQ-END-084 - ASR: Block executable content from email client and webmail](asr/block-email-executable-content.md)**
6. **[REQ-END-085 - ASR: Block executable files from running unless they meet a prevalence, age, or trusted list criterion](asr/block-low-prevalence-executable-files.md)**
7. **[REQ-END-086 - ASR: Block execution of potentially obfuscated scripts](asr/block-obfuscated-scripts.md)**
8. **[REQ-END-087 - ASR: Block JavaScript or VBScript from launching downloaded executable content](asr/block-script-launching-downloaded-content.md)**
9. **[REQ-END-088 - ASR: Block Office applications from creating executable content](asr/block-office-executable-content-creation.md)**
10. **[REQ-END-089 - ASR: Block Office applications from injecting code into other processes](asr/block-office-code-injection.md)**
11. **[REQ-END-090 - ASR: Block Office communication application from creating child processes](asr/block-office-communication-child-processes.md)**
12. **[REQ-END-091 - ASR: Block persistence through WMI event subscription](asr/block-wmi-event-subscription-persistence.md)**
13. **[REQ-END-092 - ASR: Block process creations originating from PSExec and WMI commands](asr/block-psexec-wmi-process-creations.md)**
14. **[REQ-END-093 - ASR: Block untrusted and unsigned processes that run from USB](asr/block-unsigned-processes-running-from-usb.md)**
15. **[REQ-END-094 - ASR: Block Win32 API calls from Office macros](asr/block-win32-api-calls-from-office-macros.md)**
16. **[REQ-END-095 - ASR: Use advanced protection against ransomware](asr/use-advanced-protection-against-ransomware.md)**

---

## Sources & Compliance References
* **CIS Microsoft Windows 10 Benchmark**: Section 18.9 (ASR Rules)
* **ANSSI Active Directory Hardening Guide**: Protective controls baselines on client workstations
