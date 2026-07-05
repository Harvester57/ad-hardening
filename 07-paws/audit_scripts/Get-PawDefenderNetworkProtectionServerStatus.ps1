# Get-PawDefenderNetworkProtectionServerStatus.ps1
$Reg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" -Name "AllowNetworkProtectionOnWinServer" -ErrorAction SilentlyContinue
if ($Reg -and $Reg.AllowNetworkProtectionOnWinServer -eq 1) {
    Write-Output "Compliant"
    exit 0
} else {
    Write-Output "Non-Compliant"
    exit 1
}
