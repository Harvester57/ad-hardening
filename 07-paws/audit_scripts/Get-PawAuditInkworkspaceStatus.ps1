# Get-PawAuditInkworkspaceStatus.ps1
$script:Vulnerable = $false

# Audit Registry value: AllowWindowsInkWorkspace
$RegVal = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Name "AllowWindowsInkWorkspace" -ErrorAction SilentlyContinue
if (-not $RegVal -or $RegVal.AllowWindowsInkWorkspace -ne 1) {
    $script:Vulnerable = $true
}

if ($script:Vulnerable) {
    Write-Output "Non-Compliant"
    exit 1
} else {
    Write-Output "Compliant"
    exit 0
}
