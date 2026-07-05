# Get-PawAuditAuditoverrideStatus.ps1
$script:Vulnerable = $false

# Audit Registry: SCENoApplyLegacyAuditPolicy
$RegVal = Get-ItemProperty -Path "reg:\HKLM\System\CurrentControlSet\Control\Lsa" -Name "SCENoApplyLegacyAuditPolicy" -ErrorAction SilentlyContinue
if (-not $RegVal -or $RegVal.SCENoApplyLegacyAuditPolicy -ne 1) {
    $script:Vulnerable = $true
}

# Audit Registry: LogLevel
$RegVal = Get-ItemProperty -Path "reg:\HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters" -Name "LogLevel" -ErrorAction SilentlyContinue
if (-not $RegVal -or $RegVal.LogLevel -ne 0) {
    $script:Vulnerable = $true
}

if ($script:Vulnerable) {
    Write-Output "Non-Compliant"
    exit 1
} else {
    Write-Output "Compliant"
    exit 0
}
