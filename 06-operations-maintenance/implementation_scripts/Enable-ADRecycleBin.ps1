# Enable-ADRecycleBin.ps1
# Description: Enables the Active Directory Recycle Bin optional feature forest-wide.

Import-Module ActiveDirectory

Write-Host "Applying hardening requirement: Enable Active Directory Recycle Bin..." -ForegroundColor Cyan

try {
    $Forest = Get-ADForest -ErrorAction Stop
    $RecycleBinFeature = Get-ADOptionalFeature -Filter "Name -eq 'Recycle Bin Feature'" -ErrorAction Stop
    $EnabledFeatures = Get-ADOptionalFeature -Filter "Name -eq 'Recycle Bin Feature'" -Properties EnabledScopes | Select-Object -ExpandProperty EnabledScopes
    
    if (-not $EnabledFeatures) {
        Write-Host "[+] Enabling Recycle Bin Feature in forest '$($Forest.Name)'..." -ForegroundColor Yellow
        Enable-ADOptionalFeature -Identity $RecycleBinFeature -Scope ForestOrConfigurationSet -Target $Forest.Name -Confirm:$false -ErrorAction Stop
        Write-Host "[+] Active Directory Recycle Bin enabled successfully." -ForegroundColor Green
    } else {
        Write-Host "[+] Active Directory Recycle Bin is already enabled." -ForegroundColor Green
    }
} catch {
    Write-Error "Failed to enable AD Recycle Bin. Error: $($_.Exception.Message)"
}
