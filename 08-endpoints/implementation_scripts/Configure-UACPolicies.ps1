# Configure-UACPolicies.ps1
# Enforces hardened User Account Control (UAC) registry configuration values.

Write-Host "--- Hardening User Account Control Policies ---" -ForegroundColor Cyan

$SystemPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

if (-not (Test-Path $SystemPath)) {
    New-Item -Path $SystemPath -Force | Out-Null
}

# ConsentPromptBehaviorAdmin = 1 (Prompt for credentials on secure desktop)
Set-ItemProperty -Path $SystemPath -Name "ConsentPromptBehaviorAdmin" -Value 1 -Type DWord
# ConsentPromptBehaviorUser = 0 (Automatically deny elevation requests)
Set-ItemProperty -Path $SystemPath -Name "ConsentPromptBehaviorUser" -Value 0 -Type DWord
# EnableLUA = 1 (Enable User Account Control / Admin Approval Mode)
Set-ItemProperty -Path $SystemPath -Name "EnableLUA" -Value 1 -Type DWord
# PromptOnSecureDesktop = 1 (Switch to secure desktop when prompting)
Set-ItemProperty -Path $SystemPath -Name "PromptOnSecureDesktop" -Value 1 -Type DWord

Write-Host "[+] UAC registry values configured successfully." -ForegroundColor Green
