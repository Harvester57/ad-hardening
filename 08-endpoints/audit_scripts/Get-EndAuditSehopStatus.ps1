# Get-EndAuditSehopStatus.ps1
$script:Vulnerable = $false

# Audit Registry value: DisableExceptionChainValidation
$RegVal = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "DisableExceptionChainValidation" -ErrorAction SilentlyContinue
if (-not $RegVal -or $RegVal.DisableExceptionChainValidation -ne 0) {
    $script:Vulnerable = $true
}

if ($script:Vulnerable) {
    Write-Output "Non-Compliant"
    exit 1
} else {
    Write-Output "Compliant"
    exit 0
}
