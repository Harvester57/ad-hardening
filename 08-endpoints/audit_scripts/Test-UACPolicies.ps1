# Test-UACPolicies.ps1
# Verifies local system registry settings for User Account Control.

Write-Host "--- Auditing User Account Control Policies ---" -ForegroundColor Cyan

$SystemPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

$AdminPrompt = Get-ItemProperty -Path $SystemPath -Name "ConsentPromptBehaviorAdmin" -ErrorAction SilentlyContinue
$UserPrompt = Get-ItemProperty -Path $SystemPath -Name "ConsentPromptBehaviorUser" -ErrorAction SilentlyContinue
$LuaState = Get-ItemProperty -Path $SystemPath -Name "EnableLUA" -ErrorAction SilentlyContinue
$SecureDesk = Get-ItemProperty -Path $SystemPath -Name "PromptOnSecureDesktop" -ErrorAction SilentlyContinue

$AdminVal = if ($AdminPrompt) { $AdminPrompt.ConsentPromptBehaviorAdmin } else { 0 }
$UserVal = if ($UserPrompt) { $UserPrompt.ConsentPromptBehaviorUser } else { 3 }
$LuaVal = if ($LuaState) { $LuaState.EnableLUA } else { 0 }
$SecureVal = if ($SecureDesk) { $SecureDesk.PromptOnSecureDesktop } else { 0 }

$AdminColor = if ($AdminVal -eq 1 -or $AdminVal -eq 3) { "Green" } else { "Red" }
$UserColor = if ($UserVal -eq 0) { "Green" } else { "Red" }
$LuaColor = if ($LuaVal -eq 1) { "Green" } else { "Red" }
$SecureColor = if ($SecureVal -eq 1) { "Green" } else { "Red" }

Write-Host "    - ConsentPromptBehaviorAdmin: $AdminVal (Required = 1 [Prompt for Creds] or 3 [Prompt for Consent on Secure Desktop])" -ForegroundColor $AdminColor
Write-Host "    - ConsentPromptBehaviorUser: $UserVal (Required = 0 [Auto Deny])" -ForegroundColor $UserColor
Write-Host "    - EnableLUA: $LuaVal (Required = 1)" -ForegroundColor $LuaColor
Write-Host "    - PromptOnSecureDesktop: $SecureVal (Required = 1)" -ForegroundColor $SecureColor
