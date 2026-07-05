# Get-PawUprunassuppressionStatus.ps1
# Get-PawUprunassuppressionStatus.ps1
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
Test-RegValue "HKLM:" "SOFTWARE\Classes\batfile\shell\runasuser" "SuppressionPolicy" "4096"
Test-RegValue "HKLM:" "SOFTWARE\Classes\cmdfile\shell\runasuser" "SuppressionPolicy" "4096"
Test-RegValue "HKLM:" "SOFTWARE\Classes\exefile\shell\runasuser" "SuppressionPolicy" "4096"
Test-RegValue "HKLM:" "SOFTWARE\Classes\mscfile\shell\runasuser" "SuppressionPolicy" "4096"

if ($script:Vulnerable) {
    Write-Output "Non-Compliant"
    exit 1
} else {
    Write-Output "Compliant"
    exit 0
}
