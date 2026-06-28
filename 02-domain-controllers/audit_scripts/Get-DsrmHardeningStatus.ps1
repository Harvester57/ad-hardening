# Get-DsrmHardeningStatus.ps1
# Check if DsrmAdminLogonBehavior registry parameter is set to 1.

$RegPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
$ValueName = "DsrmAdminLogonBehavior"

if (-not (Test-Path $RegPath)) {
    Write-Host "[!] NON-COMPLIANT: Registry key '$RegPath' does not exist." -ForegroundColor Red
    exit 1
}

$Value = Get-ItemProperty -Path $RegPath -Name $ValueName -ErrorAction SilentlyContinue

if ($null -eq $Value -or $Value.$ValueName -ne 1) {
    Write-Host "[!] NON-COMPLIANT: DSRM network logon is not restricted (DsrmAdminLogonBehavior is not 1)." -ForegroundColor Red
    exit 1
} else {
    Write-Host "[+] COMPLIANT: DSRM network logon is restricted (DsrmAdminLogonBehavior = 1)." -ForegroundColor Green
    exit 0
}
