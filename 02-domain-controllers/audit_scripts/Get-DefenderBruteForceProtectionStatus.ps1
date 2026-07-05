# Get-DefenderBruteForceProtectionStatus.ps1
$Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Remediation\Behavioral Network Blocks\Brute Force Protection"
$Reg = Get-ItemProperty -Path $Path -Name "BruteForceProtectionAggressiveness" -ErrorAction SilentlyContinue
if ($Reg -and $Reg.BruteForceProtectionAggressiveness -eq 1) {
    Write-Output "Compliant"
    exit 0
} else {
    Write-Output "Non-Compliant"
    exit 1
}
