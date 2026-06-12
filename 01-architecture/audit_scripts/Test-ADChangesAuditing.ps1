# Test-ADChangesAuditing.ps1
# Audits local DC auditpol settings to verify Directory Service auditing is enabled.

Write-Host "--- Auditing Directory Service Audit Policy ---" -ForegroundColor Cyan

$rawOutput = auditpol.exe /get /subcategory:"Directory Service Changes" /r
# Parse CSV output: Machine,Subcategory,GUID,PolicyVal
if ($rawOutput -match "^.+,Directory Service Changes,.+,(.+)$") {
    $policyVal = $Matches[1]
    $color = if ($policyVal -match "Success") { "Green" } else { "Red" }
    Write-Host "    - Directory Service Changes Audit: $policyVal (Required = Success and Failure)" -ForegroundColor $color
} else {
    Write-Warning "    - Status: Could not parse DS auditpol status."
}
