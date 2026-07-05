# Get-EndAuditObjectaccessStatus.ps1
$script:Vulnerable = $false

# Audit Subcategory: Registry
$RawOutput = auditpol.exe /get /subcategory:"Registry" /r
if ($RawOutput -notmatch ",Registry,.*,Failure") {
    $script:Vulnerable = $true
}

# Audit Subcategory: File Share
$RawOutput = auditpol.exe /get /subcategory:"File Share" /r
if ($RawOutput -notmatch ",File Share,.*,Failure") {
    $script:Vulnerable = $true
}

# Audit Subcategory: Detailed File Share
$RawOutput = auditpol.exe /get /subcategory:"Detailed File Share" /r
if ($RawOutput -notmatch ",Detailed File Share,.*,Failure") {
    $script:Vulnerable = $true
}

# Audit Subcategory: Handle Manipulation
$RawOutput = auditpol.exe /get /subcategory:"Handle Manipulation" /r
if ($RawOutput -notmatch ",Handle Manipulation,.*,Failure") {
    $script:Vulnerable = $true
}

if ($script:Vulnerable) {
    Write-Output "Non-Compliant"
    exit 1
} else {
    Write-Output "Compliant"
    exit 0
}
