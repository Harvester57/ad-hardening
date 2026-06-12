# Audit-ADFunctionalLevels.ps1
# Description: Audits the current domain and forest functional levels.

Import-Module ActiveDirectory

Write-Host "--- Auditing Active Directory Functional Levels ---" -ForegroundColor Cyan

$Domain = Get-ADDomain -ErrorAction SilentlyContinue
$Forest = Get-ADForest -ErrorAction SilentlyContinue

if ($Domain -and $Forest) {
    $DomainMode = $Domain.DomainMode
    $ForestMode = $Forest.ForestMode
    
    $MinDomainMode = [Microsoft.ActiveDirectory.Management.ADDomainMode]::Windows2016Domain
    $MinForestMode = [Microsoft.ActiveDirectory.Management.ADForestMode]::Windows2016Forest
    
    $DomainCompliant = [int]$DomainMode -ge [int]$MinDomainMode
    $ForestCompliant = [int]$ForestMode -ge [int]$MinForestMode
    
    if ($DomainCompliant) {
        Write-Host "Status: Domain Functional Level is compliant ($DomainMode)." -ForegroundColor Green
    } else {
        Write-Host "VULNERABLE: Domain Functional Level ($DomainMode) is below Windows Server 2016." -ForegroundColor Red
    }
    
    if ($ForestCompliant) {
        Write-Host "Status: Forest Functional Level is compliant ($ForestMode)." -ForegroundColor Green
    } else {
        Write-Host "VULNERABLE: Forest Functional Level ($ForestMode) is below Windows Server 2016." -ForegroundColor Red
    }
} else {
    Write-Host "VULNERABLE: Could not retrieve Active Directory settings. Run on a domain-joined machine with AD module installed." -ForegroundColor Red
}
