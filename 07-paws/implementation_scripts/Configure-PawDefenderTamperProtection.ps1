# Configure-PawDefenderTamperProtection.ps1
$FeaturesPath = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features"
if (-not (Test-Path $FeaturesPath)) { New-Item -Path $FeaturesPath -Force | Out-Null }
try {
    Set-ItemProperty -Path $FeaturesPath -Name "TamperProtection" -Value 5 -Type DWord -ErrorAction Stop -Force
} catch {
    Write-Warning "Registry blocked. Tamper Protection registry key is normally protected by TrustedInstaller. Ensure GPO setting is applied."
}
