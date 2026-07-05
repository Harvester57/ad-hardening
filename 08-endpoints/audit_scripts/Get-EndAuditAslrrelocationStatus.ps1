# Get-EndAuditAslrrelocationStatus.ps1
$script:Vulnerable = $false

# Audit Registry value: MoveImages
$RegVal = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "MoveImages" -ErrorAction SilentlyContinue
if (-not $RegVal -or $RegVal.MoveImages -ne 4294967295) {
    $script:Vulnerable = $true
}

if ($script:Vulnerable) {
    Write-Output "Non-Compliant"
    exit 1
} else {
    Write-Output "Compliant"
    exit 0
}
