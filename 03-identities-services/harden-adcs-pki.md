# Hardening Requirement: Harden Active Directory Certificate Services (ADCS) and PKI

## Target Scope
* **Applicable Systems**: Member Servers (Certification Authorities), Domain Controllers
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**: 
  * **AD CS Template Container**: `CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=[Domain]`
  * **IIS Web Enrollment Server**: CA Web Enrollment IIS virtual directory configuration (`CertSrv`)

---

## Rationale
Active Directory Certificate Services (ADCS) is a built-in Public Key Infrastructure (PKI) solution widely used for issuing certificates for computer and user authentication. However, misconfigured certificate templates and CA web endpoints present severe privilege escalation vectors (collectively referred to as ESC1 through ESC8).

Key vulnerabilities include:
1. **ESC1 (Enrollee Supplies Subject / SAN Exploitation)**: If a certificate template allows the client requesting the certificate to supply the subject name (Subject Alternative Name - SAN) in the enrollment request, and that template allows client authentication, any unprivileged domain user can request a certificate in the name of a Domain Administrator or Domain Controller. Upon receiving the certificate, the attacker can authenticate as that administrator, resulting in instant forest compromise.
2. **ESC8 (IIS Web Enrollment NTLM Relay)**: The default ADCS HTTP Web Enrollment pages (`/certsrv`) do not enforce HTTPS and support NTLM authentication without protection. Attackers can coerce NTLM authentication from a Domain Controller (e.g., using printer spooler coercion) and relay that authentication to the CA web enrollment endpoint to request a DC certificate, taking over the domain.

Hardening ADCS templates and endpoints is critical to secure the Tier 0 boundary.

---

## Legacy Impact & Compatibility
* **Enrollment Disruption**: Disabling template configurations that allow client-specified SANs will block applications (such as third-party firewalls, load balancers, or web servers) that legitimately use this configuration to automatically request certificates with custom SANs. These systems should be migrated to secure enrollment agents or manual enrollment templates with manager approval.
* **Authentication Failures**: Disabling HTTP Web Enrollment (`/certsrv`) entirely is recommended. If it must remain active, IIS must be configured to enforce HTTPS and Extended Protection for Authentication (EPA), which will block legacy non-channel-bound clients.

---

## Implementation Steps

### Option A: Certificate Templates Console Configuration

#### 1. Mitigate ESC1 (Disable Enrollee Supplies Subject)
1. Open the **Certificate Templates Console** (`certtmpl.msc`) on the CA server or a management host.
2. Locate the active templates used for authentication (e.g., `User`, `Computer`, or custom templates).
3. Right-click the template and select **Properties**.
4. Select the **Subject Name** tab.
5. Ensure the option **Build from this Active Directory information** is selected. 
6. **Do NOT select** the option **Supply in the request**. If a template *must* allow user-supplied subjects (e.g., web server SSL templates), ensure that **Client Authentication** is *not* present in the Extended Key Usage (EKU) list, and enforce manager approval (see below).

#### 2. Enforce Manager Approval on Sensitive Templates
1. In the template properties, select the **Issuance Requirements** tab.
2. Check the box for **CA administrator approval**.
3. Under **Require the following for enrollment**, set the authorized signatures to `1` if an enrollment agent is required.
4. Save the template.

#### 3. Disable or Secure HTTP Web Enrollment (Mitigate ESC8)
1. Log on to the CA server hosting the Web Enrollment role.
2. Open **Internet Information Services (IIS) Manager** (`inetmgr.exe`).
3. In the left tree view, navigate to:
   `Sites\Default Web Site\CertSrv`
4. In the middle pane, double-click **Authentication**.
5. Select **Windows Authentication** and click **Advanced Settings** in the right pane.
6. Set **Extended Protection** to **Required** (or **Accept**).
7. Ensure that the **Default Web Site** binds exclusively to HTTPS (port 443) and redirect all HTTP traffic to HTTPS.
   * *Ideally, if Web Enrollment is not required, uninstall the "Active Directory Certificate Services Web Enrollment" role entirely via Server Manager.*

---

### Option B: PowerShell Configuration (Remediation / Non-GPO)

Run the following script block to audit active certificate templates for vulnerable configurations (ESC1).

[Download Script: Get-ADCSTemplateAudit.ps1](audit_scripts/Get-ADCSTemplateAudit.ps1)

```powershell
# Get-ADCSTemplateAudit.ps1
# Description: Audits Active Directory certificate templates for SAN and authentication misconfigurations.

Import-Module ActiveDirectory

Write-Host "--- Auditing ADCS Certificate Templates ---" -ForegroundColor Cyan

$ConfigDN = (Get-ADRootDSE).configurationNamingContext
$TemplatesPath = "LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,$($ConfigDN)"
$Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$TemplatesPath)
$Searcher.Filter = "(objectClass=pkipastructure)"
$Templates = $Searcher.FindAll()

$VulnerableCount = 0

foreach ($Result in $Templates) {
    $Template = $Result.GetDirectoryEntry()
    $TemplateName = $Template.cn.Value
    
    # Check if enrollee supplies subject name (SAN flag: 0x00010000)
    $NameFlags = $Template.'msPKI-Certificate-Name-Flag'.Value
    $SuppliesSubject = ($NameFlags -band 0x00010000) -eq 0x00010000
    
    # Check if template is used for Client Authentication (EKU OID: 1.3.6.1.5.5.7.3.2)
    $EkUs = $Template.'pKIExtendedKeyUsage'.Value
    $AllowsClientAuth = $false
    foreach ($Eku in $EkUs) {
        if ($Eku -eq "1.3.6.1.5.5.7.3.2" -or $Eku -eq "1.3.6.1.4.1.311.20.2.2") { # Client Auth or Smartcard Logon
            $AllowsClientAuth = $true
        }
    }
    
    # Check if manager approval is required (Enrollment flag: 0x00000002)
    $EnrollFlags = $Template.'msPKI-Enrollment-Flag'.Value
    $RequiresApproval = ($EnrollFlags -band 0x00000002) -eq 0x00000002

    if ($SuppliesSubject -and $AllowsClientAuth -and -not $RequiresApproval) {
        Write-Host "[!] VULNERABLE TEMPLATE DETECTED (ESC1): $TemplateName" -ForegroundColor Red
        Write-Host "    - Allows Client Authentication" -ForegroundColor White
        Write-Host "    - Enrollee supplies Subject/SAN" -ForegroundColor White
        Write-Host "    - Requires NO Manager Approval" -ForegroundColor White
        $VulnerableCount++
    }
}

if ($VulnerableCount -eq 0) {
    Write-Host "[+] No vulnerable ESC1 certificate templates found." -ForegroundColor Green
} else {
    Write-Host "[-] Action Required: Resolve the above vulnerable templates immediately." -ForegroundColor Red
}
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Recommendations R36, R37 (Section 3.3.4)
* **ANSSI Remediation of Active Directory Tier 0 Guide**: Section 9 (Page 35)
* **Microsoft Security Advisory**: KB5014754 (Certificate-based authentication changes)
* **Other Reference**: CVE-2022-26923 (Active Directory Domain Services Privilege Escalation)
