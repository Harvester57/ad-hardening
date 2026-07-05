# Get-DcAuditPrivilegeuseStatus.ps1
$script:Vulnerable = $false

# Audit Subcategory: Sensitive Privilege Use
$RawOutput = auditpol.exe /get /subcategory:"Sensitive Privilege Use" /r
if ($RawOutput -notmatch ",Sensitive Privilege Use,.*,(Success and Failure|Success & Failure)") {
    $script:Vulnerable = $true
}

if ($script:Vulnerable) {
    Write-Output "Non-Compliant"
    exit 1
} else {
    Write-Output "Compliant"
    exit 0
}
