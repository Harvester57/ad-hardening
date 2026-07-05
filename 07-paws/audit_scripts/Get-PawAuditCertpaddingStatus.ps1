# Get-PawAuditCertpaddingStatus.ps1
$script:Vulnerable = $false

# Audit Registry value: EnableCertPaddingCheck
$RegVal = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Cryptography\Wintrust\Config" -Name "EnableCertPaddingCheck" -ErrorAction SilentlyContinue
if (-not $RegVal -or $RegVal.EnableCertPaddingCheck -ne 1) {
    $script:Vulnerable = $true
}

# Audit Registry value: EnableCertPaddingCheck
$RegVal = Get-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config" -Name "EnableCertPaddingCheck" -ErrorAction SilentlyContinue
if (-not $RegVal -or $RegVal.EnableCertPaddingCheck -ne 1) {
    $script:Vulnerable = $true
}

if ($script:Vulnerable) {
    Write-Output "Non-Compliant"
    exit 1
} else {
    Write-Output "Compliant"
    exit 0
}
