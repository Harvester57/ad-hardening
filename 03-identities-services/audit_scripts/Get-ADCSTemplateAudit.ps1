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
