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
