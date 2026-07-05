# Get-EndAuditProtectedrootsStatus.ps1
$script:Vulnerable = $false

# Audit Registry value: Flags
$RegVal = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\Root\ProtectedRoots" -Name "Flags" -ErrorAction SilentlyContinue
if (-not $RegVal -or $RegVal.Flags -ne 1) {
    $script:Vulnerable = $true
}

if ($script:Vulnerable) {
    Write-Output "Non-Compliant"
    exit 1
} else {
    Write-Output "Compliant"
    exit 0
}
