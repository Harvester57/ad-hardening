# Get-DcAuditAccountlogonStatus.ps1
$script:Vulnerable = $false

# Audit Subcategory: Kerberos Authentication Service
$RawOutput = auditpol.exe /get /subcategory:"Kerberos Authentication Service" /r
if ($RawOutput -notmatch ",Kerberos Authentication Service,.*,(Success and Failure|Success & Failure)") {
    $script:Vulnerable = $true
}

# Audit Subcategory: Kerberos Service Ticket Operations
$RawOutput = auditpol.exe /get /subcategory:"Kerberos Service Ticket Operations" /r
if ($RawOutput -notmatch ",Kerberos Service Ticket Operations,.*,(Success and Failure|Success & Failure)") {
    $script:Vulnerable = $true
}

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
