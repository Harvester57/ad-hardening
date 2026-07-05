# Get-DefenderRemoteEncryptionProtectionStatus.ps1
$Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Remediation\Behavioral Network Blocks\Remote Encryption Protection"
$Reg = Get-ItemProperty -Path $Path -Name "RemoteEncryptionProtectionAggressiveness" -ErrorAction SilentlyContinue
if ($Reg -and $Reg.RemoteEncryptionProtectionAggressiveness -eq 1) {
    Write-Output "Compliant"
    exit 0
} else {
    Write-Output "Non-Compliant"
    exit 1
}
