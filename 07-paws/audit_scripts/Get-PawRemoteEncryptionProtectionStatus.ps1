# Get-PawRemoteEncryptionProtectionStatus.ps1
# Description: Audits Microsoft Defender Remote Encryption Protection configuration status on PAWs.

$KeyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Remediation\Behavioral Network Blocks\Brute Force Protection"
$Reg = Get-ItemProperty -Path $KeyPath -Name "BruteForceProtectionConfiguredState" -ErrorAction SilentlyContinue

if ($Reg -and $Reg.BruteForceProtectionConfiguredState -eq 2) {
    Write-Output "Compliant"
    exit 0
} else {
    Write-Output "Non-Compliant"
    exit 1
}
