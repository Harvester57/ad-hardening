# Active Directory Hardening Guidebook: PowerShell DSC Audit Framework

This directory contains a PowerShell Desired State Configuration (DSC) framework that integrates all the technical audit scripts in the guidebook. It allows administrators to continuously audit, monitor, and report compliance drift across Domain Controllers, Privileged Access Workstations (PAWs), and Client Endpoints.

---

## Technical Overview

The framework operates in **ApplyAndMonitor** mode, which checks the host state against the desired hardening rules without attempting automatic remediation (remediation should be handled separately). If drift occurs, the host is marked as non-compliant, and the exact failing control is reported.

The framework consists of two main scripts:
* **[ADHardeningAudit.ps1](ADHardeningAudit.ps1)**: Defines the primary DSC Configuration block. It lists all active directory status scripts, maps them to profiles, and compiles them using loops to avoid duplication.
* **[Deploy-ADHardeningAudit.ps1](Deploy-ADHardeningAudit.ps1)**: A bootstrap script that handles synchronization of audit scripts, LCM configuration, configuration compilation, and DSC execution.

---

## Profile Breakdown

The DSC configuration uses a tiered system where nodes execute common checks plus profile-specific checks:

### 1. Common Controls Profile
Applies to all systems (Domain Controllers, PAWs, Endpoints). It checks:
* Windows Firewall logging and settings.
* Hardened UNC Paths and SMB Client signing.
* WinRM and RPC service hardening.
* Network and workstation isolation.
* Host security protocols (IPsec, TLS).
* Windows Advanced Audit Policies.
* PowerShell Auditing (script block logging).
* Sysmon and SIEM log shipping configurations.
* WSUS client settings.
* GPO Central Store and Administrative Templates.
* Local account hardening (default accounts, LAPS, logon restrictions).

### 2. Domain Controller Profile
Applies exclusively to Active Directory Domain Controllers. It checks:
* AD Trust and Functional Levels.
* Group Policy Objects (GPO) precedence.
* Directory changes auditing configuration.
* Directory administration groups.
* AdminSDHolder security descriptor permissions.
* AppLocker and Defender status for Domain Controllers.
* LSA Protection and Credential Guard.
* DNS audit configurations.
* Microsoft Vulnerable Driver Blocklist.
* LDAP signing and channel binding.
* NTLMv1 restrictions.
* Kerberos Armoring (FAST) and Encryption type configuration.
* Directory replication health (DFSR) and SYSVOL migration.
* gMSA and KDS configuration.
* KRBTGT password rotation status.
* Active Directory Backup and Recycle Bin status.

### 3. PAW (Privileged Access Workstation) Profile
Applies to high-security administrative workstations. It checks:
* Local hardware security features (TPM, UEFI, DMA protection).
* Credential Guard and LSA Protection.
* AppLocker policies for PAW environments.
* BitLocker encryption status.
* Safe Mode and Local Administrators restrictions.
* User Rights Assignments.

### 4. Endpoint Profile
Applies to standard client workstations. It checks:
* Secure Boot and UEFISecurity.
* Local User Account Control (UAC) settings.
* Outbound firewall blocks for LOLBins.
* Exploit Protection configurations.
* BitLocker and AppLocker endpoint status.
* Removable storage and AutoPlay restrictions.
* Remote Desktop (RDP) restricted administration mode.
* User profile and directory restrictions.

---

## Deployment & Usage

### Prerequisites
* Windows PowerShell 5.1.
* Administrator privileges on the target node.
* A copy of the AD Hardening Guidebook repository.

### Run Compliance Audit (Push Mode)
To synchronize the audit scripts, configure the Local Configuration Manager, and apply the DSC configuration, run the deployment script from an elevated PowerShell prompt:

```powershell
# Run audit for an Endpoint
.\Deploy-ADHardeningAudit.ps1 -Profile Endpoint

# Run audit for a Domain Controller
.\Deploy-ADHardeningAudit.ps1 -Profile DomainController

# Run audit for a PAW
.\Deploy-ADHardeningAudit.ps1 -Profile PAW
```

### Compile Only (Offline Mode)
To compile the node configuration MOF without applying it or modifying the Local Configuration Manager:

```powershell
.\Deploy-ADHardeningAudit.ps1 -Profile DomainController -CompileOnly
```
The compiled MOF configuration file will be generated in `Build\Config\localhost.mof`.

---

## Retrieving Audit Results

### Get Active Configuration Compliance
You can check the last DSC compliance execution status using:

```powershell
Get-DscConfigurationStatus
```
This cmdlet returns details such as whether the host is in the desired state (`InDesiredState` is `$true` or `$false`) and the date/time of the compliance run.

### Get Configuration Details
To list the details and status of all individual controls applied to the host:

```powershell
Get-DscConfiguration
```

### Viewing DSC Logs in Event Viewer
Detailed compliance results, warning logs, and error messages are written directly to the Microsoft Windows DSC Event Logs:
* Open **Event Viewer** (`eventvwr.msc`).
* Navigate to: `Applications and Services Logs` -> `Microsoft` -> `Windows` -> `Desired State Configuration` -> `Operational`.
