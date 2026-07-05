# Get-EndAuditSpeculativemitigationsStatus.ps1
$script:Vulnerable = $false

# Audit Registry value: FeatureSettingsOverride
$RegVal = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "FeatureSettingsOverride" -ErrorAction SilentlyContinue
if (-not $RegVal -or $RegVal.FeatureSettingsOverride -ne 72) {
    $script:Vulnerable = $true
}

# Audit Registry value: FeatureSettingsOverrideMask
$RegVal = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "FeatureSettingsOverrideMask" -ErrorAction SilentlyContinue
if (-not $RegVal -or $RegVal.FeatureSettingsOverrideMask -ne 3) {
    $script:Vulnerable = $true
}

if ($script:Vulnerable) {
    Write-Output "Non-Compliant"
    exit 1
} else {
    Write-Output "Compliant"
    exit 0
}
