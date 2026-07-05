# Get-EndAuditDetailedtrackingStatus.ps1
$script:Vulnerable = $false

# Audit Subcategory: Process Creation
$RawOutput = auditpol.exe /get /subcategory:"Process Creation" /r
if ($RawOutput -notmatch ",Process Creation,.*,(Success and Failure|Success & Failure)") {
    $script:Vulnerable = $true
}

# Audit Subcategory: DPAPI Activity
$RawOutput = auditpol.exe /get /subcategory:"DPAPI Activity" /r
if ($RawOutput -notmatch ",DPAPI Activity,.*,(Success and Failure|Success & Failure)") {
    $script:Vulnerable = $true
}

# Audit Subcategory: PNP Activity
$RawOutput = auditpol.exe /get /subcategory:"PNP Activity" /r
if ($RawOutput -notmatch ",PNP Activity,.*,Success") {
    $script:Vulnerable = $true
}

if ($script:Vulnerable) {
    Write-Output "Non-Compliant"
    exit 1
} else {
    Write-Output "Compliant"
    exit 0
}
