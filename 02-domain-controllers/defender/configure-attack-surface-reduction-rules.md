# Configure Attack Surface Reduction Rules on Domain Controllers

## Target Scope
* **Applicable Systems**: Domain Controllers.
* **Operating Systems**: Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\Windows Defender Exploit Guard\Attack Surface Reduction

---

## Rationale
Attack Surface Reduction (ASR) rules block threat behaviors on Domain Controllers, focusing on preventing local credential hijacking from LSASS memory, vulnerable driver execution, and malicious persistence actions (WMI).

This submodule contains individual requirement rules for each ASR control configured on Active Directory Domain Controllers.

---

## Legacy Impact & Compatibility
* **PSExec / WMI Command Block**: Creating processes via remote WMI or PSExec commands is set to **Audit** mode (`2`) rather than Block to prevent breaking automated server monitoring, backup scripts, and administrative replication checks.

---

## Enforced Attack Surface Reduction Rules on Domain Controllers

The following individual ASR rules must be configured:

1. **[REQ-DC-098 - ASR: Block abuse of exploited vulnerable signed drivers on Domain Controllers](asr/block-vulnerable-signed-drivers.md)** (Block)
2. **[REQ-DC-099 - ASR: Block credential stealing from the Windows local security authority subsystem on Domain Controllers](asr/block-lsass-credential-stealing.md)** (Block)
3. **[REQ-DC-100 - ASR: Block execution of potentially obfuscated scripts on Domain Controllers](asr/block-obfuscated-scripts.md)** (Block)
4. **[REQ-DC-101 - ASR: Block persistence through WMI event subscription on Domain Controllers](asr/block-wmi-event-subscription-persistence.md)** (Block)
5. **[REQ-DC-102 - ASR: Block process creations originating from PSExec and WMI commands on Domain Controllers](asr/block-psexec-wmi-process-creations.md)** (Audit)
6. **[REQ-DC-103 - ASR: Use advanced protection against ransomware on Domain Controllers](asr/use-advanced-protection-against-ransomware.md)** (Block)

---

## Sources & Compliance References
* **CIS Microsoft Windows Server Benchmark**: Section 18.9 (ASR Rules)
* **ANSSI Active Directory Hardening Guide**: Protective controls baselines on Domain Controllers
