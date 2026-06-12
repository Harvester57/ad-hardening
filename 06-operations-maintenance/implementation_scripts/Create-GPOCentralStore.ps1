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
