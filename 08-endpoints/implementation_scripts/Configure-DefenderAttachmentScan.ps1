# Configure-DefenderAttachmentScan.ps1
$Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments"
if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
Set-ItemProperty -Path $Path -Name "ScanWithAntiVirus" -Value 3 -Type DWord -Force
