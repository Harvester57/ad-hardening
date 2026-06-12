# Audit-ADRecycleBin.ps1
# Description: Audits the enablement status of the AD Recycle Bin.

Import-Module ActiveDirectory

Write-Host "--- Auditing Active Directory Recycle Bin ---" -ForegroundColor Cyan

try {
    $Forest = Get-ADForest -ErrorAction Stop
    $RecycleBinFeature = Get-ADOptionalFeature -Filter "Name -eq 'Recycle Bin Feature'" -ErrorAction Stop
    $EnabledFeatures = Get-ADOptionalFeature -Filter "Name -eq 'Recycle Bin Feature'" -Properties EnabledScopes | Select-Object -ExpandProperty EnabledScopes
    
    if ($EnabledFeatures) {
        Write-Host "`nStatus: Compliant. Active Directory Recycle Bin is enabled in the forest '$($Forest.Name)'." -ForegroundColor Green
    } else {
        Write-Host "`nVULNERABLE: Active Directory Recycle Bin is NOT enabled in the forest '$($Forest.Name)'." -ForegroundColor Red
    }
} catch {
    Write-Host "VULNERABLE: Could not query optional features. Error: $($_.Exception.Message)" -ForegroundColor Red
}
