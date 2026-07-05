# Configure-Upsystemmitigations.ps1
Write-Host "Applying User Profile restriction: system-mitigations..." -ForegroundColor Cyan

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
Set-RegValue "HKLM:" "SYSTEM\CurrentControlSet\Control\Session Manager\kernel" "DisableExceptionChainValidation" "0" "DWord"
Set-RegValue "HKLM:" "SYSTEM\CurrentControlSet\Control\Session Manager" "ProtectionMode" "1" "DWord"
Set-RegValue "HKLM:" "SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "MoveImages" "4294967295" "DWord"
Set-RegValue "HKLM:" "SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "FeatureSettingsOverride" "72" "DWord"
Set-RegValue "HKLM:" "SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "FeatureSettingsOverrideMask" "3" "DWord"
Set-RegValue "HKLM:" "Software\Microsoft\Cryptography\Wintrust\Config" "EnableCertPaddingCheck" "1" "DWord"
Set-RegValue "HKLM:" "Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config" "EnableCertPaddingCheck" "1" "DWord"
Set-RegValue "HKLM:" "SOFTWARE\Microsoft\Command Processor" "LockBatchFilesWhenInUse" "1" "DWord"
Set-RegValue "HKLM:" "SOFTWARE\Microsoft\TTD" "RecordingPolicy" "2" "DWord"
Set-RegValue "HKLM:" "SOFTWARE\Policies\Microsoft\SystemCertificates\Root\ProtectedRoots" "Flags" "1" "DWord"
Set-RegValue "HKLM:" "Software\Microsoft\Windows NT\CurrentVersion\Windows" "LoadAppInit_DLLs" "0" "DWord"
Set-RegValue "HKLM:" "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" "SaveZoneInformation" "2" "DWord"
Set-RegValue "HKLM:" "SOFTWARE\Policies\Microsoft\Windows\GameDVR" "AllowGameDVR" "0" "DWord"
Set-RegValue "HKLM:" "SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" "AllowWindowsInkWorkspace" "1" "DWord"

