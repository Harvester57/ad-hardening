# Get-PawAuditLogonlogoffStatus.ps1
$script:Vulnerable = $false

# Audit Subcategory: Logon
$RawOutput = auditpol.exe /get /subcategory:"Logon" /r
if ($RawOutput -notmatch ",Logon,.*,(Success and Failure|Success & Failure)") {
    $script:Vulnerable = $true
}

# Audit Subcategory: Logoff
$RawOutput = auditpol.exe /get /subcategory:"Logoff" /r
if ($RawOutput -notmatch ",Logoff,.*,Success") {
    $script:Vulnerable = $true
}

# Audit Subcategory: Special Logon
$RawOutput = auditpol.exe /get /subcategory:"Special Logon" /r
if ($RawOutput -notmatch ",Special Logon,.*,(Success and Failure|Success & Failure)") {
    $script:Vulnerable = $true
}

# Audit Subcategory: Account Lockout
$RawOutput = auditpol.exe /get /subcategory:"Account Lockout" /r
if ($RawOutput -notmatch ",Account Lockout,.*,(Success and Failure|Success & Failure)") {
    $script:Vulnerable = $true
}

# Audit Subcategory: Other Logon/Logoff Events
$RawOutput = auditpol.exe /get /subcategory:"Other Logon/Logoff Events" /r
if ($RawOutput -notmatch ",Other Logon/Logoff Events,.*,(Success and Failure|Success & Failure)") {
    $script:Vulnerable = $true
}

if ($script:Vulnerable) {
    Write-Output "Non-Compliant"
    exit 1
} else {
    Write-Output "Compliant"
    exit 0
}
