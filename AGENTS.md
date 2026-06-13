# Agent Instructions: Technical Hardening Documentation

This repository contains the Active Directory Hardening Guidebook. When implementing or documenting new hardening controls, you must adhere to the rules and template conventions defined below to maintain consistency, completeness, and programmatic validation.

---

## Pre-Implementation Verification

Before documenting or implementing a new hardening control, you must perform a search against existing technical controls to double-check if the settings, policy paths, registry keys, or security concepts are not already covered or mentioned elsewhere in the repository.

To verify this:
1. Search for the specific GPO policy path, policy name, or registry key/value.
2. Search for related terms, protocols, or abbreviations (e.g., "NTLM", "Kerberos", "SMBv3").
3. Inspect all subdirectories (`01-architecture`, `02-domain-controllers`, `03-identities-services`, etc.) for existing files addressing similar subjects.

If the control is already covered or mentioned, modify or expand the existing documentation rather than creating a duplicate entry.

---

## The Documentation Template

All new technical hardening requirements must use the structure defined in **[TEMPLATE.md](TEMPLATE.md)**.

### Mandatory Template Sections
1. **Target Scope**: Clearly declare whether the requirement applies to Domain Controllers, Member Servers, or Tier 2 Client Workstations, and note the target OS range.
2. **Implementation Details**: Specify the Priority (**High / Medium / Low**) and locate the GPO path or registry branch.
3. **Rationale**: Detail the technical threat vector (e.g., coercion attacks like PetitPotam, hash relaying) and explain *why* the control is necessary.
4. **Legacy Impact & Compatibility**: Document any breaking changes (e.g., disabling NTLMv1 breaks legacy authentication for old NAS systems).
5. **Implementation Steps**:
   * **Priority 1**: Step-by-step GUI guide using Group Policy Object (GPO) configuration settings.
   * **Priority 2**: Pure PowerShell equivalent script blocks for both auditing and local remediation.
6. **Sources & Compliance References**: Link directly to ANSSI AD Guide recommendation numbers, CIS Benchmarks sections, or Microsoft Security Baseline specifications.

---

## Formatting Rules
 
* **No Emojis**: Emojis are strictly prohibited anywhere in this project. Do not use emojis in headers, list items, description text, or comments.
* **Requirement IDs**: Every technical control must start with a unique, sequential ID in its header, e.g., `# [REQ-LOG-001] Configure Advanced Security Audit Policies`. The ID uses the prefix `REQ-` followed by the module abbreviation (`ARCH`, `DC`, `ID`, `NET`, `LOG`, `OPS`, `PAW`, `END`) and a sequential three-digit number.

---

## PowerShell Guidelines for Hardening Controls

To ensure scripts run correctly on standard systems:
1. **Target Engine**: All PowerShell scripts must run natively on **Windows PowerShell 5.1** (the default version on Windows Server 2016 and standard Windows 10 client releases).
2. **No Modern Operators**: Do NOT use syntax introduced in PowerShell Core 6.0/7.0+, such as the ternary operator (`? :`) or null-coalescing operators (`??`). Use traditional `if / else` statements.
3. **Safe String Interpolation**: Avoid appending a colon (`:`) immediately after a variable name in double-quoted strings (e.g., write `"Port $($port): Closed"` instead of `"Port $port: Closed"` to prevent the parser from mistaking it for a scope modifier).
4. **Offline Compatibility**: Ensure scripts do not rely on active internet connections, cloud namespaces, or online validation modules.

---

## Script Extraction and Directories

Every module directory contains two folders:
* `implementation_scripts`: Contains PowerShell scripts to implement technical controls locally.
* `audit_scripts`: Contains PowerShell scripts to audit technical controls locally.

When adding or modifying a technical control:
1. Ensure the implementation and audit PowerShell code blocks start with a comment designating the script filename (e.g., `# Configure-DisableSMBv1.ps1` or `# Get-SMBv1Status.ps1`).
2. Extract the code block content and save it to the corresponding `implementation_scripts` or `audit_scripts` directory inside the module folder.
3. Add download links in the markdown file directly above the code blocks:
   * Implementation link: `[Download Script: Configure-DisableSMBv1.ps1](02-domain-controllers/implementation_scripts/Configure-DisableSMBv1.ps1)`
   * Audit link: `[Download Script: Get-SMBv1Status.ps1](02-domain-controllers/audit_scripts/Get-SMBv1Status.ps1)`
4. You can run the automation script to extract these scripts and inject the links:
   ```text
   py scripts/extract_scripts.py
   ```

---

## Validation Before Committing

This repository contains a programmatic validator: **[Verify-ADHardeningDocs.ps1](Verify-ADHardeningDocs.ps1)**.

Before marking your work as complete, you **must** run this verification script in a local PowerShell console:

```powershell
.\Verify-ADHardeningDocs.ps1
```

The script will:
* Check for broken internal markdown links between modules and templates.
* Extract all `powershell` or `ps1` code blocks from the markdown documents and run them through a syntax analyzer (`[System.Management.Automation.Language.Parser]`) to ensure compile-time validity without executing the instructions.
