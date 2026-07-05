# Get-EndAuditAttachmentzoneStatus.ps1
$script:Vulnerable = $false

# Audit Registry value: SaveZoneInformation
$RegVal = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "SaveZoneInformation" -ErrorAction SilentlyContinue
if (-not $RegVal -or $RegVal.SaveZoneInformation -ne 2) {
    $script:Vulnerable = $true
}

if ($script:Vulnerable) {
    Write-Output "Non-Compliant"
    exit 1
} else {
    Write-Output "Compliant"
    exit 0
}
