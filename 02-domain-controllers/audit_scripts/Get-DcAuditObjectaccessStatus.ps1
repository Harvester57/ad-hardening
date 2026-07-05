# Get-DcAuditObjectaccessStatus.ps1
$script:Vulnerable = $false

# Audit Subcategory: Handle Manipulation
$RawOutput = auditpol.exe /get /subcategory:"Handle Manipulation" /r
if ($RawOutput -notmatch ",Handle Manipulation,.*,(Success and Failure|Success & Failure)") {
    $script:Vulnerable = $true
}

# Audit Subcategory: Registry
$RawOutput = auditpol.exe /get /subcategory:"Registry" /r
if ($RawOutput -notmatch ",Registry,.*,(Success and Failure|Success & Failure)") {
    $script:Vulnerable = $true
}

# Audit Subcategory: File Share
$RawOutput = auditpol.exe /get /subcategory:"File Share" /r
if ($RawOutput -notmatch ",File Share,.*,(Success and Failure|Success & Failure)") {
    $script:Vulnerable = $true
}

# Audit Subcategory: Detailed File Share
$RawOutput = auditpol.exe /get /subcategory:"Detailed File Share" /r
if ($RawOutput -notmatch ",Detailed File Share,.*,Failure") {
    $script:Vulnerable = $true
}

# Audit Subcategory: Other Object Access Events
$RawOutput = auditpol.exe /get /subcategory:"Other Object Access Events" /r
if ($RawOutput -notmatch ",Other Object Access Events,.*,(Success and Failure|Success & Failure)") {
    $script:Vulnerable = $true
}

if ($script:Vulnerable) {
    Write-Output "Non-Compliant"
    exit 1
} else {
    Write-Output "Compliant"
    exit 0
}
