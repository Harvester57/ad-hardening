# Get-EndAuditLockbatchfilesStatus.ps1
$script:Vulnerable = $false

# Audit Registry value: LockBatchFilesWhenInUse
$RegVal = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Command Processor" -Name "LockBatchFilesWhenInUse" -ErrorAction SilentlyContinue
if (-not $RegVal -or $RegVal.LockBatchFilesWhenInUse -ne 1) {
    $script:Vulnerable = $true
}

if ($script:Vulnerable) {
    Write-Output "Non-Compliant"
    exit 1
} else {
    Write-Output "Compliant"
    exit 0
}
