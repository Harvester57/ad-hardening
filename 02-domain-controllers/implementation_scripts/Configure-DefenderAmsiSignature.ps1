# Configure-DefenderAmsiSignature.ps1
$AmsiPath = "HKLM:\SOFTWARE\Microsoft\AMSI"
if (-not (Test-Path $AmsiPath)) { New-Item -Path $AmsiPath -Force | Out-Null }
Set-ItemProperty -Path $AmsiPath -Name "FeatureBits" -Value 2 -Type DWord -Force
