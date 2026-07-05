# Configure-DefenderRemoteEncryptionProtection.ps1
$Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Remediation\Behavioral Network Blocks\Remote Encryption Protection"
if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
Set-ItemProperty -Path $Path -Name "RemoteEncryptionProtectionAggressiveness" -Value 1 -Type DWord -Force
