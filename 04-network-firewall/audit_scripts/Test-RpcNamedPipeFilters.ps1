# Test-RpcNamedPipeFilters.ps1
# Description: Audits active RPC filters configuration using Netsh queries.

Write-Host "Auditing RPC filters configuration..." -ForegroundColor Cyan

# Query RPC filters
$filters = netsh rpc filter show filter

# Check for presence of SCM block rule filterkey or Mimikatz block rule filterkey
$scmFound = $false
$mimiFound = $false

foreach ($line in $filters) {
    if ($line -like "*d0c7640c-9355-4e52-8335-c12835559c10*") {
        $scmFound = $true
    }
    if ($line -like "*644291ca-9530-4066-b654-e7b838ebdc06*") {
        $mimiFound = $true
    }
}

if ($scmFound -and $mimiFound) {
    Write-Host "[+] RPC Filters for named pipes are active (SCM and Mimikatz filterkeys found)." -ForegroundColor Green
    Write-Host "Audit result: COMPLIANT" -ForegroundColor Green
} else {
    Write-Host "[!] NON-COMPLIANT: Core RPC named pipe filters are missing or inactive." -ForegroundColor Red
    if (-not $scmFound) {
        Write-Host "    - Missing SCM Named Pipe Filter (d0c7640c-9355-4e52-8335-c12835559c10)" -ForegroundColor Yellow
    }
    if (-not $mimiFound) {
        Write-Host "    - Missing Mimikatz Filter (644291ca-9530-4066-b654-e7b838ebdc06)" -ForegroundColor Yellow
    }
    Write-Host "Audit result: NON-COMPLIANT" -ForegroundColor Red
}
