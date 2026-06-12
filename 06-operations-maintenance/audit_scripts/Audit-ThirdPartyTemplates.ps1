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
