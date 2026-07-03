# Active Directory Hardening Guidebook

Welcome to the **Active Directory Hardening Guidebook**. This repository houses a production-grade, offensive-aligned set of hardening requirements and guidelines specifically designed for securing **modern Active Directory (AD) environments** in **air-gapped (offline)** settings.

---

## Core Philosophy & Design

In high-security, isolated environments, traditional cloud-based security feeds and agent-based telemetry may be unavailable or restricted. This guidebook addresses this challenge by providing a self-contained, deterministic hardening framework that:
*   **Enforces Administrative Tiering**: Strictly isolates administrative identities, credentials, and systems to prevent privilege escalation.
*   **Restricts Attack Surface**: Systematically disables legacy protocols, name resolution mechanisms, and vulnerable default options.
*   **Ensures Deterministic Configuration**: Standardizes system baselines using Group Policy Objects (GPOs) and Desired State Configuration (DSC).

---

## Scope & Target Systems

The guidebook covers the following scopes:

| Component | Target Operating System | Placement / Tier |
| :--- | :--- | :--- |
| **Domain Controllers** | Windows Server 2016 and above | Tier 0 (Core Identity) |
| **Privileged Access Workstations (PAWs)** | Windows 10 Enterprise and above | Tier 0/1 (Management Plane) |
| **Tier 2 Client Workstations** | Windows 10 Enterprise and above | Tier 2 (Standard Clients) |

Target environment characteristics:
*   **Air-Gapped / Isolated**: No active internet connectivity or external DNS dependencies.
*   **On-Premises Focused**: No Azure AD / Entra ID hybrid integrations, relying purely on native AD DS.
*   **Standard OS Baseline**: Built and tested against native Windows enterprise releases, with no dependence on third-party security agents for core functions.

---

## Administrative Tiering Model

To prevent credential theft and lateral movement, the guidebook structures all policies around the 3-Tier administrative tiering model:

<div class="tiering-model-container">
  <!-- Tier 0 -->
  <div class="tier-card tier-0">
    <div class="tier-badge">Tier 0</div>
    <div class="tier-content">
      <h3>Identity & Control Plane</h3>
      <p class="tier-desc">Direct or indirect administrative control over the Active Directory forest, identity systems, and key management infrastructure.</p>
      <div class="tier-elements">
        <span class="element-tag">Domain Controllers</span>
        <span class="element-tag">PKI & Active Directory Certificate Services (ADCS)</span>
        <span class="element-tag">Privileged Access Workstations (PAWs)</span>
        <span class="element-tag">Domain/Forest Admins</span>
      </div>
    </div>
  </div>
  <!-- Tier 1 -->
  <div class="tier-card tier-1">
    <div class="tier-badge">Tier 1</div>
    <div class="tier-content">
      <h3>Enterprise Servers & Services</h3>
      <p class="tier-desc">Corporate application servers, database systems, and management infrastructure. High business value but no direct identity fabric control.</p>
      <div class="tier-elements">
        <span class="element-tag">Enterprise Member Servers</span>
        <span class="element-tag">Application Service Accounts</span>
        <span class="element-tag">Server Administrators</span>
        <span class="element-tag">WSUS & Configuration Managers</span>
      </div>
    </div>
  </div>
  <!-- Tier 2 -->
  <div class="tier-card tier-2">
    <div class="tier-badge">Tier 2</div>
    <div class="tier-content">
      <h3>Endpoints & Standard Users</h3>
      <p class="tier-desc">Standard corporate client workstations, laptops, mobile devices, and normal business users.</p>
      <div class="tier-elements">
        <span class="element-tag">Client Workstations / Laptops</span>
        <span class="element-tag">Standard Corporate Users</span>
        <span class="element-tag">Local Workstation Administrators</span>
      </div>
    </div>
  </div>
</div>

---

## Guidebook Structure & Modules

The hardening guidelines are organized into eight functional modules:

| Module | Target Scope | Focus Areas |
| :--- | :--- | :--- |
| **[Module 1: Architecture & Administrative Tiering](01-architecture/README.md)** | Infrastructure Layout | Tier logons, administrative protocols, privileged group audits, forest functional levels, GPO management. |
| **[Module 2: Domain Controller Hardening](02-domain-controllers/README.md)** | Domain Controllers (Tier 0) | SMBv1/NTLMv1 deprecation, LDAP signing/channel binding, Print Spooler disablement, LSA/Credential Guard. |
| **[Module 3: Identities & Services Hardening](03-identities-services/README.md)** | Directory Identities | Password policies, LAPS, gMSAs, delegation restrictions, Protected Users, ADCS/PKI security. |
| **[Module 4: Network Configuration & Firewalling](04-network-firewall/README.md)** | Network Boundaries | Port matrices, RPC dynamic port restrictions, IPsec domain isolation, SMBv3 security, WinRM. |
| **[Module 5: Logging, Monitoring & SIEM](05-logging-monitoring/README.md)** | Directory Auditing | Security audit policies, PowerShell/CLI auditing, Sysmon deployment, secure log shipping. |
| **[Module 6: Secure Operations & Maintenance](06-operations-maintenance/README.md)** | Directory Operations | KRBTGT password rotation, AD Recycle Bin, ADMX Central Store management, Tier 0 WSUS baseline. |
| **[Module 7: Privileged Access Workstations Hardening](07-paws/README.md)** | Management Devices (Tier 0/1) | BitLocker with TPM/PIN, UEFI security, DMA protection, AppLocker, WDAC, kernel shadow stacks. |
| **[Module 8: Endpoint Hardening](08-endpoints/README.md)** | Client Workstations (Tier 2) | UAC policies, LOLBins blocklists, Application Control (WDAC), system service disabling, Windows Defender. |

## Continuous Auditing & Compliance Framework

To ensure that the security controls documented in this guidebook remain enforced and do not experience configuration drift, this repository includes a two-pronged automated auditing framework:

### 1. PowerShell DSC Audit Baseline

A native **[PowerShell DSC Audit Framework](audit/dsc/README.md)** that operates in `ApplyAndMonitor` mode, continuously checking target systems against the security baseline and logging details of any failing controls or drift. It is organized around targeting profiles for Common Controls, Domain Controllers, PAWs, and Endpoints. 

For details on configuration and compilation, refer to the **[DSC Audit Framework Documentation](audit/dsc/README.md)**.

### 2. Automated SCAP Benchmarks (XCCDF & OVAL)

A standardized, declarative security checking mechanism using **[SCAP XML Benchmarks](audit/scap/README.md)**:
*   **XCCDF Benchmark (`audit/scap/ad-hardening-xccdf.xml`)**: Defines the checklist groups, severities, and target profiles.
*   **OVAL Definitions (`audit/scap/ad-hardening-oval.xml`)**: Implements automated native checks (registry, services, privileges, account limits, and audit policies) to evaluate compliance without manual tasks.

For execution instructions using tools like `oscap` or enterprise compliance agents, refer to the **[SCAP Compliance Documentation](audit/scap/README.md)**.

---

## Standards & Compliance Mapping

All controls are mapped to international security standards to simplify audits and verify posture. For compliance mappings, see the dedicated matrices:

*   **[ANSSI Compliance Matrix](compliance/anssi.md)**: Aligned with ANSSI's *Hardening an Active Directory Directory Service* guidelines.
*   **[CIS Benchmarks Compliance Matrix](compliance/cis.md)**: Aligned with the Center for Internet Security (CIS) Windows Server and Windows Client Benchmarks.
*   **[Microsoft Security Baselines Compliance Matrix](compliance/microsoft.md)**: Aligned with the Microsoft Security Baselines specification.

---