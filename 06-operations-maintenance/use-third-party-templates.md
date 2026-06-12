# Hardening Requirement: Implement Third-Party and Custom GPO Templates for COTS Hardening

## Target Scope
* **Applicable Systems**: Domain Members (Clients and Servers)
* **Operating Systems**: Windows 10/11, Windows Server 2016 and above

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**: SYSVOL PolicyDefinitions Store / Local Administrative Templates

---

## Rationale
Group Policy Objects (GPOs) natively manage core Windows operating system components but lack administrative control definitions for third-party Commercial Off-The-Shelf (COTS) software (such as Google Chrome, Microsoft Edge, Adobe Acrobat Reader) and advanced security guide extensions.

Implementing third-party and custom GPO templates provides the following benefits:
1. **Centralized Configuration**: Administrators can enforce security configurations across all enterprise workstations and member servers (e.g. disabling insecure browser protocols, locking PDF execution properties) directly from the Group Policy Management Console.
2. **Reduced Attack Surface**: Custom templates (such as [Security-ADMX GitHub Repository](https://github.com/Harvester57/Security-ADMX) or the Microsoft Security Guide template) expose hidden or advanced registry configurations, allowing administrators to restrict features like WDigest authentication or LSA credential caching that are not exposed in standard out-of-the-box Windows templates.
3. **Consistency**: Linking COTS hardening GPOs ensures that third-party applications remain compliant with corporate security baselines, preventing local user overrides.

---

## Legacy Impact & Compatibility
* **Application Interoperability**: Enforcing strict configurations on third-party software (such as blocking legacy TLS, enforcing browser extension whitelists, or restricting PDF javascript execution) may impact business applications or legacy intranet sites. All templates and settings must be fully validated in a testing sandbox prior to production deployment.
* **Template Updates**: As applications update, vendors release newer ADMX template versions. Administrators must periodically update the templates in the Central Store to support newer settings.

---

## Implementation Steps

### Option A: Manual Central Store Importing (Preferred)

1. Log on to a management workstation or Domain Controller with **Domain Admins** credentials.
2. Download the official Administrative Templates from the software manufacturer's website (e.g. Microsoft Edge Enterprise templates, Google Chrome templates).
3. Extract the downloaded files to locate the `.admx` files and matching `.adml` language-specific resource files (typically in `en-US` subfolders).
4. Navigate to the Central Store on a Domain Controller:
   `\\<Domain_FQDN>\SYSVOL\<Domain_FQDN>\Policies\PolicyDefinitions`
5. Copy the `.admx` files into the root of the `PolicyDefinitions` directory.
6. Copy the `.adml` files into the language subfolder matching the language (e.g. `PolicyDefinitions\en-US`).
7. Open the **Group Policy Management Console** (`gpmc.msc`) and edit a target hardening GPO. The new settings will appear under **Computer Configuration > Policies > Administrative Templates > [Software Name]**.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following scripts to audit and import custom templates.

#### 1. Local Audit (Audit-ThirdPartyTemplates.ps1)

[Download Script: Audit-ThirdPartyTemplates.ps1](audit_scripts/Audit-ThirdPartyTemplates.ps1)

```powershell
# Audit-ThirdPartyTemplates.ps1
# Description: Checks the GPO Central Store for common third-party templates.

Import-Module ActiveDirectory

Write-Host "--- Auditing Third-Party GPO Templates ---" -ForegroundColor Cyan

try {
    $Domain = Get-ADDomain -ErrorAction Stop
    $CentralStorePath = "\\$($Domain.DNSRoot)\SYSVOL\$($Domain.DNSRoot)\Policies\PolicyDefinitions"
    
    if (Test-Path -Path $CentralStorePath) {
        $Templates = @{
            "Microsoft Edge" = "msedge.admx"
            "Google Chrome" = "chrome.admx"
            "Adobe Acrobat" = "Acrobat.admx"
            "MS Security Guide" = "SecGuide.admx"
        }
        
        Write-Host "`nChecking for common templates in Central Store:" -ForegroundColor Yellow
        foreach ($key in $Templates.Keys) {
            $file = $Templates[$key]
            $fullPath = Join-Path $CentralStorePath $file
            
            if (Test-Path -Path $fullPath) {
                Write-Host "    - [FOUND] $key ($file)" -ForegroundColor Green
            } else {
                Write-Host "    - [MISSING] $key ($file)" -ForegroundColor Yellow
            }
        }
    } else {
        Write-Host "VULNERABLE: Group Policy Central Store does not exist. Cannot audit templates." -ForegroundColor Red
    }
} catch {
    Write-Host "VULNERABLE: Could not query Active Directory. Error: $($_.Exception.Message)" -ForegroundColor Red
}
```

#### 2. Local Remediation (Import-ThirdPartyTemplate.ps1)

[Download Script: Import-ThirdPartyTemplate.ps1](implementation_scripts/Import-ThirdPartyTemplate.ps1)

```powershell
# Import-ThirdPartyTemplate.ps1
# Description: Copies a specified ADMX and ADML template to the Central Store.

Import-Module ActiveDirectory

Write-Host "Applying hardening requirement: Copy GPO Templates to Central Store..." -ForegroundColor Cyan

# Define local source paths for templates (to be populated by administrator)
$SourceAdmx = "C:\SourceTemplates\msedge.admx"
$SourceAdml = "C:\SourceTemplates\en-US\msedge.adml"

try {
    $Domain = Get-ADDomain -ErrorAction Stop
    $CentralStorePath = "\\$($Domain.DNSRoot)\SYSVOL\$($Domain.DNSRoot)\Policies\PolicyDefinitions"
    
    if (-not (Test-Path -Path $CentralStorePath)) {
        Write-Error "GPO Central Store is not initialized. Please establish the Central Store first."
        exit 1
    }
    
    if ((Test-Path -Path $SourceAdmx) -and (Test-Path -Path $SourceAdml)) {
        # Copy ADMX file
        Copy-Item -Path $SourceAdmx -Destination $CentralStorePath -Force -ErrorAction Stop
        Write-Host "[+] Copied ADMX: $(Split-Path $SourceAdmx -Leaf) to Central Store." -ForegroundColor Green
        
        # Copy ADML file to matching subfolder
        $LangDir = Join-Path $CentralStorePath "en-US"
        if (-not (Test-Path -Path $LangDir)) {
            New-Item -ItemType Directory -Path $LangDir -Force -ErrorAction Stop | Out-Null
        }
        Copy-Item -Path $SourceAdml -Destination $LangDir -Force -ErrorAction Stop
        Write-Host "[+] Copied ADML: $(Split-Path $SourceAdml -Leaf) to Central Store en-US subfolder." -ForegroundColor Green
    } else {
        Write-Warning "Source template files not found at specified paths. Please ensure templates are downloaded locally."
    }
} catch {
    Write-Error "Failed to copy template files. Error: $($_.Exception.Message)"
}
```

---

## Sources & Compliance References
* **Security-ADMX Project**: Custom GPO templates for hardening Windows client and server environments. Available at the [Security-ADMX GitHub Repository](https://github.com/Harvester57/Security-ADMX).
* **CIS Microsoft Windows Server Benchmarks**: Sections recommending the use of administrative templates to control third-party browser settings.
* **ANSSI AD Hardening Guide**: Recommendations on secure configuration templates for operating systems and software.
