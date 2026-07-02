# Module 5: Logging, Monitoring & SIEM

This directory contains configuration policies for security log auditing, PowerShell transcription, and host monitoring for detection systems in isolated networks.

1. **[REQ-LOG-001 - Configure Advanced Security Audit Policies](configure-advanced-audit-policies.md)**
   Enforces granular Windows security audit policies (including logons, Kerberos authentication operations, group memberships, policy changes, and process execution) to log critical threat telemetry.

2. **[REQ-LOG-002 - Configure PowerShell and Command-Line Auditing](configure-powershell-and-command-line-auditing.md)**
   Enforces process command-line argument auditing and verbose PowerShell logging (Script Block, Module, and Transcription logging) with a write-only, hardened transcript folder.

3. **[REQ-LOG-003 - Deploy and Harden Microsoft Sysmon](deploy-and-harden-sysmon.md)**
   Deploys Sysmon with a hardened telemetry configuration and configures aggressive service recovery settings to auto-restart the service if stopped by adversaries.

4. **[REQ-LOG-004 - Configure Secure SIEM Log Shipping](configure-siem-log-shipping.md)**
   Configures secured log shipping agents (Winlogbeat and Wazuh) utilizing TLS encryption, authenticated CA checks, local configuration file ACL protections, and buffer queue size limits to prevent local disk space exhaustion.

5. **[REQ-LOG-005 - Configure Kerberoasting Honeypots and SIEM Detection Rules](implement-kerberoasting-honeypot.md)**
   Deploys decoy service accounts in Active Directory to attract Kerberoasting scans and provides high-fidelity SIEM alerting queries.
