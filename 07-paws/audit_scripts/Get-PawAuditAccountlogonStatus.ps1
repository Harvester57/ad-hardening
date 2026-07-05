# Get-PawAuditAccountlogonStatus.ps1
$script:Vulnerable = $false

# Audit Subcategory: Credential Validation
$RawOutput = auditpol.exe /get /subcategory:"Credential Validation" /r
if ($RawOutput -notmatch ",Credential Validation,.*,(Success and Failure|Success & Failure)") {
    $script:Vulnerable = $true
}

if ($script:Vulnerable) {
    Write-Output "Non-Compliant"
    exit 1
} else {
    Write-Output "Compliant"
    exit 0
}
