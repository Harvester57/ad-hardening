# Get-DcAuditDsaccessStatus.ps1
$script:Vulnerable = $false

# Audit Subcategory: Directory Service Changes
$RawOutput = auditpol.exe /get /subcategory:"Directory Service Changes" /r
if ($RawOutput -notmatch ",Directory Service Changes,.*,(Success and Failure|Success & Failure)") {
    $script:Vulnerable = $true
}

# Audit Subcategory: Directory Service Access
$RawOutput = auditpol.exe /get /subcategory:"Directory Service Access" /r
if ($RawOutput -notmatch ",Directory Service Access,.*,(Success and Failure|Success & Failure)") {
    $script:Vulnerable = $true
}

if ($script:Vulnerable) {
    Write-Output "Non-Compliant"
    exit 1
} else {
    Write-Output "Compliant"
    exit 0
}
