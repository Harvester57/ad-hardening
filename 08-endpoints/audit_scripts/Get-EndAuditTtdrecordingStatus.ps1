# Get-EndAuditTtdrecordingStatus.ps1
$script:Vulnerable = $false

# Audit Registry value: RecordingPolicy
$RegVal = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\TTD" -Name "RecordingPolicy" -ErrorAction SilentlyContinue
if (-not $RegVal -or $RegVal.RecordingPolicy -ne 2) {
    $script:Vulnerable = $true
}

if ($script:Vulnerable) {
    Write-Output "Non-Compliant"
    exit 1
} else {
    Write-Output "Compliant"
    exit 0
}
