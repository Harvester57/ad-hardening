# Get-DcAuditSystemeventsStatus.ps1
$script:Vulnerable = $false

# Audit Subcategory: IPsec Driver
$RawOutput = auditpol.exe /get /subcategory:"IPsec Driver" /r
if ($RawOutput -notmatch ",IPsec Driver,.*,(Success and Failure|Success & Failure)") {
    $script:Vulnerable = $true
}

# Audit Subcategory: Other System Events
$RawOutput = auditpol.exe /get /subcategory:"Other System Events" /r
if ($RawOutput -notmatch ",Other System Events,.*,(Success and Failure|Success & Failure)") {
    $script:Vulnerable = $true
}

# Audit Subcategory: Security State Change
$RawOutput = auditpol.exe /get /subcategory:"Security State Change" /r
if ($RawOutput -notmatch ",Security State Change,.*,(Success and Failure|Success & Failure)") {
    $script:Vulnerable = $true
}

# Audit Subcategory: Security System Extension
$RawOutput = auditpol.exe /get /subcategory:"Security System Extension" /r
if ($RawOutput -notmatch ",Security System Extension,.*,(Success and Failure|Success & Failure)") {
    $script:Vulnerable = $true
}

# Audit Subcategory: System Integrity
$RawOutput = auditpol.exe /get /subcategory:"System Integrity" /r
if ($RawOutput -notmatch ",System Integrity,.*,(Success and Failure|Success & Failure)") {
    $script:Vulnerable = $true
}

if ($script:Vulnerable) {
    Write-Output "Non-Compliant"
    exit 1
} else {
    Write-Output "Compliant"
    exit 0
}
