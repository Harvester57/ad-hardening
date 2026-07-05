# Get-EndAuditAccountmanagementStatus.ps1
$script:Vulnerable = $false

# Audit Subcategory: User Account Management
$RawOutput = auditpol.exe /get /subcategory:"User Account Management" /r
if ($RawOutput -notmatch ",User Account Management,.*,(Success and Failure|Success & Failure)") {
    $script:Vulnerable = $true
}

# Audit Subcategory: Security Group Management
$RawOutput = auditpol.exe /get /subcategory:"Security Group Management" /r
if ($RawOutput -notmatch ",Security Group Management,.*,(Success and Failure|Success & Failure)") {
    $script:Vulnerable = $true
}

# Audit Subcategory: Other Account Management Events
$RawOutput = auditpol.exe /get /subcategory:"Other Account Management Events" /r
if ($RawOutput -notmatch ",Other Account Management Events,.*,(Success and Failure|Success & Failure)") {
    $script:Vulnerable = $true
}

if ($script:Vulnerable) {
    Write-Output "Non-Compliant"
    exit 1
} else {
    Write-Output "Compliant"
    exit 0
}
