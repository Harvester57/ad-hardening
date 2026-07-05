# Get-DefenderAmsiSignatureStatus.ps1
$AmsiPath = "HKLM:\SOFTWARE\Microsoft\AMSI"
if (Test-Path $AmsiPath) {
    $AmsiBits = Get-ItemProperty -Path $AmsiPath -Name "FeatureBits" -ErrorAction SilentlyContinue
    if ($AmsiBits -and $AmsiBits.FeatureBits -eq 2) {
        Write-Output "Compliant"
        exit 0
    }
}
Write-Output "Non-Compliant"
exit 1
