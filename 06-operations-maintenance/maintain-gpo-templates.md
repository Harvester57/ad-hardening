# [REQ-OPS-003] Establish and Maintain Group Policy ADMX Central Store

## Target Scope
* **Applicable Systems**: Domain Controllers (SYSVOL Share)
* **Operating Systems**: Windows Server 2016 and above

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**: SYSVOL PolicyDefinitions Store (`\\<Domain_FQDN>\SYSVOL\<Domain_FQDN>\Policies\PolicyDefinitions`)

---

## Rationale
Group Policy Objects (GPOs) rely on XML-based Administrative Template files (`.admx`) and language-specific resource files (`.adml`) to display registry-based policy settings within administrative tools.

By default, the Group Policy Management Editor loads templates from the local computer's `%SystemRoot%\PolicyDefinitions` folder. In an enterprise AD environment, this behavior introduces several security and operational risks:
1. **Configuration Drift**: If different Domain Controllers or management workstations have different template versions installed, editing GPOs can result in missing configurations, corrupted settings, or inadvertent reversion of newer security settings.
2. **Missing Security Controls**: As operating systems evolve, new security controls (such as disabling legacy name resolution or enforcing LSA protection) are introduced in newer templates. Without updated templates, administrators cannot manage these settings via the GPMC GUI.

Establishing the **Central Store** in the SYSVOL share ensures that all administrators edit GPOs using a single, authoritative set of administrative templates.

---

## Legacy Impact & Compatibility
* **Replication Load**: Placing templates in the SYSVOL share triggers File Replication Service (FRS) or DFS Replication (DFSR) to replicate the files to all Domain Controllers. The store typically contains 10–50 MB of data, which has minimal impact on modern replication networks.
* **Consoles Compatibility**: Older administrative consoles (such as Windows Server 2008 R2) may display errors when opening GPOs edited with newer templates, but the settings themselves will still apply correctly to target machines.

---

## Implementation Steps

### Option A: Manual Central Store Establishment (Preferred)

1. Log on to a Domain Controller with **Schema Admins** or **Domain Admins** credentials.
2. Open File Explorer and navigate to the local SYSVOL Policies folder:
   `C:\Windows\SYSVOL\sysvol\<Domain_FQDN>\Policies` (or use the UNC path: `\\localhost\SYSVOL\<Domain_FQDN>\Policies`).
3. Create a new folder named `PolicyDefinitions`.
4. Create language-specific subdirectories inside it based on your environment (e.g. `en-US`).
5. Copy the contents of the local administrative template directory `C:\Windows\PolicyDefinitions` (all `.admx` files) into the newly created `PolicyDefinitions` folder in SYSVOL.
6. Copy the local `.adml` files from `C:\Windows\PolicyDefinitions\en-US` into the `en-US` subfolder in SYSVOL.
7. To update templates in an offline, air-gapped environment, manually transfer the latest Administrative Templates (downloaded as `.msi` packages from Microsoft) to the domain controller, extract them, and copy the new `.admx` and `.adml` files into the SYSVOL Central Store, replacing older versions.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following scripts to audit and initialize the Central Store folder structure.

#### 1. Local Audit (Audit-GPOCentralStore.ps1)

[Download Script: Audit-GPOCentralStore.ps1](audit_scripts/Audit-GPOCentralStore.ps1)

```powershell
# Audit-GPOCentralStore.ps1
# Description: Audits the existence of the GPO Central Store in SYSVOL.

Import-Module ActiveDirectory

Write-Host "--- Auditing Group Policy Central Store ---" -ForegroundColor Cyan

try {
    $Domain = Get-ADDomain -ErrorAction Stop
    $CentralStorePath = "\\$($Domain.DNSRoot)\SYSVOL\$($Domain.DNSRoot)\Policies\PolicyDefinitions"
    
    if (Test-Path -Path $CentralStorePath) {
        Write-Host "`nStatus: Compliant. Group Policy Central Store is established at:" -ForegroundColor Green
        Write-Host "    $CentralStorePath" -ForegroundColor White
        
        $AdmxFiles = Get-ChildItem -Path $CentralStorePath -Filter *.admx
        Write-Host "    Found $($AdmxFiles.Count) ADMX templates in the store." -ForegroundColor Green
    } else {
        Write-Host "`nVULNERABLE: Group Policy Central Store does NOT exist. Expected location:" -ForegroundColor Red
        Write-Host "    $CentralStorePath" -ForegroundColor Red
    }
} catch {
    Write-Host "VULNERABLE: Could not query Active Directory for SYSVOL path. Error: $($_.Exception.Message)" -ForegroundColor Red
}
```

#### 2. Local Remediation (Create-GPOCentralStore.ps1)

[Download Script: Create-GPOCentralStore.ps1](implementation_scripts/Create-GPOCentralStore.ps1)

```powershell
# Create-GPOCentralStore.ps1
# Description: Initializes the Central Store directory structure in SYSVOL.

Import-Module ActiveDirectory

Write-Host "Applying hardening requirement: Initialize GPO Central Store..." -ForegroundColor Cyan

try {
    $Domain = Get-ADDomain -ErrorAction Stop
    $CentralStorePath = "\\$($Domain.DNSRoot)\SYSVOL\$($Domain.DNSRoot)\Policies\PolicyDefinitions"
    
    if (-not (Test-Path -Path $CentralStorePath)) {
        New-Item -ItemType Directory -Path $CentralStorePath -Force -ErrorAction Stop | Out-Null
        # Create standard language folder
        New-Item -ItemType Directory -Path (Join-Path $CentralStorePath "en-US") -Force -ErrorAction Stop | Out-Null
        
        Write-Host "[+] Group Policy Central Store initialized successfully." -ForegroundColor Green
        Write-Host "    Path: $CentralStorePath" -ForegroundColor White
        Write-Host "    Please copy the latest .admx and .adml files to this directory." -ForegroundColor Yellow
    } else {
        Write-Host "[+] Central Store is already initialized at: $CentralStorePath" -ForegroundColor Green
    }
} catch {
    Write-Error "Failed to initialize GPO Central Store. Error: $($_.Exception.Message)"
}
```

---

## Sources & Compliance References
* **Microsoft Guidance**: How to create and manage the Central Store for Group Policy Administrative Templates.
* **ANSSI AD Hardening Guide**: Section on Group Policy template maintenance and update management.
