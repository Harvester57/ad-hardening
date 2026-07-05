# Configure Attack Surface Reduction Rules for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration.
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\Windows Defender Exploit Guard\Attack Surface Reduction

---

## Rationale
Attack Surface Reduction (ASR) rules are critical for PAWs to enforce administrative isolation. Spawning tools from Office documents, dumping memory from LSASS, or launching WMI/PSExec child commands represent standard post-exploitation vectors.

This submodule contains individual requirement rules for each ASR control enforced on Privileged Access Workstations.

---

## Legacy Impact & Compatibility
* **Strict Block Enforcement**: Unlike standard workstations, all rules are enforced immediately in **Block** mode (`1`) as there should be no productive Office files, macros, or legacy scripts active on directory management consoles.

---

## Enforced Attack Surface Reduction Rules on PAWs

The following individual ASR rules must be configured in Block mode:

1. **[REQ-PAW-076 - ASR: Block abuse of exploited vulnerable signed drivers for PAWs](asr/block-vulnerable-signed-drivers.md)**
2. **[REQ-PAW-077 - ASR: Block Adobe Reader from creating child processes for PAWs](asr/block-adobe-reader-child-processes.md)**
3. **[REQ-PAW-078 - ASR: Block all Office applications from creating child processes for PAWs](asr/block-office-child-processes.md)**
4. **[REQ-PAW-079 - ASR: Block credential stealing from the Windows local security authority subsystem for PAWs](asr/block-lsass-credential-stealing.md)**
5. **[REQ-PAW-080 - ASR: Block executable content from email client and webmail for PAWs](asr/block-email-executable-content.md)**
6. **[REQ-PAW-081 - ASR: Block executable files from running unless they meet a prevalence, age, or trusted list criterion for PAWs](asr/block-low-prevalence-executable-files.md)**
7. **[REQ-PAW-082 - ASR: Block execution of potentially obfuscated scripts for PAWs](asr/block-obfuscated-scripts.md)**
8. **[REQ-PAW-083 - ASR: Block JavaScript or VBScript from launching downloaded executable content for PAWs](asr/block-script-launching-downloaded-content.md)**
9. **[REQ-PAW-084 - ASR: Block Office applications from creating executable content for PAWs](asr/block-office-executable-content-creation.md)**
10. **[REQ-PAW-085 - ASR: Block Office applications from injecting code into other processes for PAWs](asr/block-office-code-injection.md)**
11. **[REQ-PAW-086 - ASR: Block Office communication application from creating child processes for PAWs](asr/block-office-communication-child-processes.md)**
12. **[REQ-PAW-087 - ASR: Block persistence through WMI event subscription for PAWs](asr/block-wmi-event-subscription-persistence.md)**
13. **[REQ-PAW-088 - ASR: Block process creations originating from PSExec and WMI commands for PAWs](asr/block-psexec-wmi-process-creations.md)**
14. **[REQ-PAW-089 - ASR: Block untrusted and unsigned processes that run from USB for PAWs](asr/block-unsigned-processes-running-from-usb.md)**
15. **[REQ-PAW-090 - ASR: Block Win32 API calls from Office macros for PAWs](asr/block-win32-api-calls-from-office-macros.md)**
16. **[REQ-PAW-091 - ASR: Use advanced protection against ransomware for PAWs](asr/use-advanced-protection-against-ransomware.md)**

---

## Sources & Compliance References
* **CIS Microsoft Windows 10 Benchmark**: Section 18.9 (ASR Rules)
* **ANSSI Active Directory Hardening Guide**: Protective controls baselines on Privileged Access Workstations
