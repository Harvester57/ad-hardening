# Get-SYSVOLDfsrMigrationStatus.ps1
# Description: Checks the current SYSVOL replication migration state.

Import-Module ActiveDirectory

Write-Host "--- Auditing SYSVOL DFSR Migration Status ---" -ForegroundColor Cyan

# Check if the FRS service is still running on this DC
$FrsService = Get-Service -Name "NtFrs" -ErrorAction SilentlyContinue

if ($null -ne $FrsService) {
    Write-Host "[*] FRS Service State: $($FrsService.Status)" -ForegroundColor White
} else {
    Write-Host "[+] FRS Service is not installed (expected in modern server configurations)." -ForegroundColor Green
}

# Run dfsrmig validation checks
$DfsMigOutput = & dfsrmig.exe /getglobalstate 2>&1

if ($DfsMigOutput -like "*Eliminated*") {
    Write-Host "[+] SYSVOL migration to DFSR is complete and finalized (State 3: Eliminated)." -ForegroundColor Green
} else {
    Write-Host "[-] WARNING: SYSVOL replication is not fully migrated to DFSR." -ForegroundColor Red
    Write-Host "    Current Status: $DfsMigOutput" -ForegroundColor Yellow
}
