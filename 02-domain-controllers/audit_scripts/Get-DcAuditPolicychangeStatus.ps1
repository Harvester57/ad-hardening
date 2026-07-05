# Get-DcAuditPolicychangeStatus.ps1
$script:Vulnerable = $false

# Audit Subcategory: Policy Change
$RawOutput = auditpol.exe /get /subcategory:"Policy Change" /r
if ($RawOutput -notmatch ",Policy Change,.*,(Success and Failure|Success & Failure)") {
    $script:Vulnerable = $true
}

# Audit Subcategory: Authentication Policy Change
$RawOutput = auditpol.exe /get /subcategory:"Authentication Policy Change" /r
if ($RawOutput -notmatch ",Authentication Policy Change,.*,Success") {
    $script:Vulnerable = $true
}

# Audit Subcategory: Authorization Policy Change
$RawOutput = auditpol.exe /get /subcategory:"Authorization Policy Change" /r
if ($RawOutput -notmatch ",Authorization Policy Change,.*,Success") {
    $script:Vulnerable = $true
}

# Audit Subcategory: MPSSVC Rule-Level Policy Change
$RawOutput = auditpol.exe /get /subcategory:"MPSSVC Rule-Level Policy Change" /r
if ($RawOutput -notmatch ",MPSSVC Rule-Level Policy Change,.*,(Success and Failure|Success & Failure)") {
    $script:Vulnerable = $true
}

# Audit Subcategory: Other Policy Change Events
$RawOutput = auditpol.exe /get /subcategory:"Other Policy Change Events" /r
if ($RawOutput -notmatch ",Other Policy Change Events,.*,Failure") {
    $script:Vulnerable = $true
}

if ($script:Vulnerable) {
    Write-Output "Non-Compliant"
    exit 1
} else {
    Write-Output "Compliant"
    exit 0
}
