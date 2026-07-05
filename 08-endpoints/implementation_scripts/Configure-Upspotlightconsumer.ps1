# Configure-Upspotlightconsumer.ps1
Write-Host "Applying User Profile restriction: spotlight-consumer..." -ForegroundColor Cyan

function Set-RegValue {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [string]$hive,
        [string]$keyPath,
        [string]$name,
        [string]$value,
        [string]$type
    )
    if ($PSCmdlet.ShouldProcess("$hive\$keyPath", "Set registry value $name to $value")) {
        $fullPath = "$hive\$keyPath"
        $parent = Split-Path -Path $fullPath
        if (-not (Test-Path $parent)) { New-Item -Path $parent -Force | Out-Null }
        if (-not (Test-Path $fullPath)) { New-Item -Path $fullPath -Force | Out-Null }
        Set-ItemProperty -Path $fullPath -Name $name -Value $value -Type $type -Force
    }
}
Set-RegValue "HKCU:" "Software\Policies\Microsoft\Windows\CloudContent" "DisableThirdPartySuggestions" "1" "DWord"
Set-RegValue "HKCU:" "Software\Policies\Microsoft\Windows\CloudContent" "ConfigureWindowsSpotlight" "2" "DWord"
Set-RegValue "HKCU:" "Software\Policies\Microsoft\Windows\CloudContent" "DisableSpotlightCollectionOnDesktop" "1" "DWord"
Set-RegValue "HKLM:" "SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableWindowsConsumerFeatures" "1" "DWord"

# Apply to Default User profile for new sessions
$DefaultHivePath = "C:\Users\Default\NTUSER.DAT"
if (Test-Path $DefaultHivePath) {
    reg load HKU\DefaultUser $DefaultHivePath | Out-Null
    $DefaultKey = "Registry::HKU\DefaultUser\Software\Policies\Microsoft\Windows\CloudContent"
    if (-not (Test-Path $DefaultKey)) { New-Item -Path $DefaultKey -Force | Out-Null }
    Set-ItemProperty -Path $DefaultKey -Name "DisableThirdPartySuggestions" -Value "1" -Type DWord -Force
    $DefaultKey = "Registry::HKU\DefaultUser\Software\Policies\Microsoft\Windows\CloudContent"
    if (-not (Test-Path $DefaultKey)) { New-Item -Path $DefaultKey -Force | Out-Null }
    Set-ItemProperty -Path $DefaultKey -Name "ConfigureWindowsSpotlight" -Value "2" -Type DWord -Force
    $DefaultKey = "Registry::HKU\DefaultUser\Software\Policies\Microsoft\Windows\CloudContent"
    if (-not (Test-Path $DefaultKey)) { New-Item -Path $DefaultKey -Force | Out-Null }
    Set-ItemProperty -Path $DefaultKey -Name "DisableSpotlightCollectionOnDesktop" -Value "1" -Type DWord -Force
    [GC]::Collect()
    [GC]::WaitForPendingFinalizers()
    reg unload HKU\DefaultUser | Out-Null
}

