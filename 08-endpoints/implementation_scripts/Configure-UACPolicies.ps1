# Configure-UACPolicies.ps1
# Enforces hardened User Account Control (UAC) registry configuration values including network restrictions, installer detection, and virtualization.

Write-Host "--- Hardening User Account Control Policies ---" -ForegroundColor Cyan

$SystemPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

if (-not (Test-Path $SystemPath)) {
    New-Item -Path $SystemPath -Force | Out-Null
}

# ConsentPromptBehaviorAdmin = 1 (Prompt for credentials on secure desktop)
Set-ItemProperty -Path $SystemPath -Name "ConsentPromptBehaviorAdmin" -Value 1 -Type DWord -Force
# ConsentPromptBehaviorUser = 0 (Automatically deny elevation requests)
Set-ItemProperty -Path $SystemPath -Name "ConsentPromptBehaviorUser" -Value 0 -Type DWord -Force
# EnableLUA = 1 (Enable User Account Control / Admin Approval Mode)
Set-ItemProperty -Path $SystemPath -Name "EnableLUA" -Value 1 -Type DWord -Force
# PromptOnSecureDesktop = 1 (Switch to secure desktop when prompting)
Set-ItemProperty -Path $SystemPath -Name "PromptOnSecureDesktop" -Value 1 -Type DWord -Force
# LocalAccountTokenFilterPolicy = 0 (Apply UAC restrictions to local accounts on network logons)
Set-ItemProperty -Path $SystemPath -Name "LocalAccountTokenFilterPolicy" -Value 0 -Type DWord -Force
# EnableInstallDetection = 1 (Detect application installations and prompt for elevation)
Set-ItemProperty -Path $SystemPath -Name "EnableInstallDetection" -Value 1 -Type DWord -Force
# EnableVirtualization = 1 (Virtualize file and registry write failures to per-user locations)
Set-ItemProperty -Path $SystemPath -Name "EnableVirtualization" -Value 1 -Type DWord -Force

# Configure Windows Sudo command behavior (Enabled = 1 [Force new elevated window])
$SudoPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Sudo"
if (-not (Test-Path $SudoPath)) {
    New-Item -Path $SudoPath -Force | Out-Null
}
Set-ItemProperty -Path $SudoPath -Name "Enabled" -Value 1 -Type DWord -Force

Write-Host "[+] UAC registry values configured successfully." -ForegroundColor Green
