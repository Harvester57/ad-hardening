# Configure-ProhibitWcnWizards.ps1
# Description: Prohibits access to Windows Connect Now wizards on Domain Controllers.

Write-Host "Prohibiting access to Windows Connect Now wizards..." -ForegroundColor Cyan

$WcnUiPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\UI"
if (-not (Test-Path -Path $WcnUiPath)) {
    New-Item -Path $WcnUiPath -Force | Out-Null
}

Set-ItemProperty -Path $WcnUiPath -Name "DisableWcnUi" -Value 1 -Type DWord -ErrorAction Stop

Write-Host "Windows Connect Now wizards prohibited successfully (DisableWcnUi = 1)." -ForegroundColor Green
