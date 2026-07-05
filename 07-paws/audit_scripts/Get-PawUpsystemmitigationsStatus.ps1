# Get-PawUpsystemmitigationsStatus.ps1
# Get-PawUpsystemmitigationsStatus.ps1
$script:Vulnerable = $false

function Test-RegValue {
    param (
        [string]$hive,
        [string]$keyPath,
        [string]$name,
        [string]$expected
    )
    $fullPath = "$hive\$keyPath"
    $val = Get-ItemProperty -Path $fullPath -Name $name -ErrorAction SilentlyContinue
    $actual = if ($val) { $val.$name } else { "" }
    if ($actual -ne $expected) {
        $script:Vulnerable = $true
    }
}
Test-RegValue "HKLM:" "SYSTEM\CurrentControlSet\Control\Session Manager\kernel" "DisableExceptionChainValidation" "0"
Test-RegValue "HKLM:" "SYSTEM\CurrentControlSet\Control\Session Manager" "ProtectionMode" "1"
Test-RegValue "HKLM:" "SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "MoveImages" "4294967295"
Test-RegValue "HKLM:" "SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "FeatureSettingsOverride" "72"
Test-RegValue "HKLM:" "SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "FeatureSettingsOverrideMask" "3"
Test-RegValue "HKLM:" "Software\Microsoft\Cryptography\Wintrust\Config" "EnableCertPaddingCheck" "1"
Test-RegValue "HKLM:" "Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config" "EnableCertPaddingCheck" "1"
Test-RegValue "HKLM:" "SOFTWARE\Microsoft\Command Processor" "LockBatchFilesWhenInUse" "1"
Test-RegValue "HKLM:" "SOFTWARE\Microsoft\TTD" "RecordingPolicy" "2"
Test-RegValue "HKLM:" "SOFTWARE\Policies\Microsoft\SystemCertificates\Root\ProtectedRoots" "Flags" "1"
Test-RegValue "HKLM:" "Software\Microsoft\Windows NT\CurrentVersion\Windows" "LoadAppInit_DLLs" "0"
Test-RegValue "HKLM:" "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" "SaveZoneInformation" "2"
Test-RegValue "HKLM:" "SOFTWARE\Policies\Microsoft\Windows\GameDVR" "AllowGameDVR" "0"
Test-RegValue "HKLM:" "SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" "AllowWindowsInkWorkspace" "1"

if ($script:Vulnerable) {
    Write-Output "Non-Compliant"
    exit 1
} else {
    Write-Output "Compliant"
    exit 0
}
