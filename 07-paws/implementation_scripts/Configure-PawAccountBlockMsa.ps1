# Configure-PawAccountBlockMsa.ps1
Write-Host "Blocking consumer Microsoft account user authentication on PAWs..." -ForegroundColor Cyan

$MsaPath = "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftAccount"
if (-not (Test-Path $MsaPath)) { New-Item -Path $MsaPath -Force | Out-Null }
Set-ItemProperty -Path $MsaPath -Name "DisableUserAuth" -Value 1 -Type DWord -Force

Write-Host "Consumer Microsoft account user authentication blocked." -ForegroundColor Green
