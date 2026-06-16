# Test-PawUACPolicies.ps1
# Description: Verifies local system registry settings for User Account Control on PAWs.

Write-Host "--- Auditing User Account Control Policies ---" -ForegroundColor Cyan

$SystemPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$script:Vulnerable = $false

function Test-UACRegistryValue ($name, $expected, $message) {
    $val = Get-ItemProperty -Path $SystemPath -Name $name -ErrorAction SilentlyContinue
    $actual = if ($val) { $val.$name } else { $null }
    $color = "Red"
    if ($actual -eq $expected) {
        $color = "Green"
    } else {
        $script:Vulnerable = $true
    }
    Write-Host "    - Registry Setting: $name | Actual: '$actual' (Expected: '$expected') | $message" -ForegroundColor $color
}

Test-UACRegistryValue "ConsentPromptBehaviorAdmin" 1 "Behavior of elevation prompt for administrators"
Test-UACRegistryValue "ConsentPromptBehaviorUser" 0 "Behavior of elevation prompt for standard users"
Test-UACRegistryValue "EnableLUA" 1 "Run all administrators in Admin Approval Mode"
Test-UACRegistryValue "PromptOnSecureDesktop" 1 "Switch to secure desktop when prompting"
Test-UACRegistryValue "LocalAccountTokenFilterPolicy" 0 "UAC network restrictions"
Test-UACRegistryValue "EnableInstallDetection" 1 "Installer detection"
Test-UACRegistryValue "EnableVirtualization" 1 "UAC virtualization"

# Audit Sudo command
$SudoPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Sudo"
if (Test-Path $SudoPath) {
    $SudoState = Get-ItemProperty -Path $SudoPath -Name "Enabled" -ErrorAction SilentlyContinue
    $SudoVal = if ($SudoState) { $SudoState.Enabled } else { 0 }
    $SudoColor = if ($SudoVal -eq 0 -or $SudoVal -eq 1) { "Green" } else { "Red" }
    Write-Host "    - Sudo Command Enabled state: $SudoVal (Required = 1 [New Window] or 0 [Disabled])" -ForegroundColor $SudoColor
    if ($SudoVal -ne 0 -and $SudoVal -ne 1) {
        $script:Vulnerable = $true
    }
} else {
    Write-Host "    - Sudo Command Enabled state: Not Configured (Default/Compliant as it inherits disabled)" -ForegroundColor Green
}

if ($script:Vulnerable) {
    Write-Host "Audit Result: VULNERABLE" -ForegroundColor Red
    exit 1
} else {
    Write-Host "Audit Result: SECURE" -ForegroundColor Green
    exit 0
}
