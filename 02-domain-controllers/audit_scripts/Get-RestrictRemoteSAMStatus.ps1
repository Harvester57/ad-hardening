# Get-RestrictRemoteSAMStatus.ps1
# Description: Audits the RestrictRemoteSAM registry value.

Write-Host "--- Auditing RestrictRemoteSAM ---" -ForegroundColor Cyan

$regPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
$lsaReg = Get-ItemProperty -Path $regPath -Name "RestrictRemoteSAM" -ErrorAction SilentlyContinue

if ($lsaReg) {
    $sddlVal = $lsaReg.RestrictRemoteSAM
    if ($sddlVal -eq "O:BAG:BAD:(A;;RC;;;BA)") {
        Write-Host "[+] Remote SAM access is secure. RestrictRemoteSAM matches expected SDDL: $($sddlVal)." -ForegroundColor Green
    } else {
        Write-Host "[!] VULNERABLE: RestrictRemoteSAM is configured but has a different SDDL: $($sddlVal) (Expected: O:BAG:BAD:(A;;RC;;;BA))." -ForegroundColor Red
    }
} else {
    Write-Host "[!] VULNERABLE: RestrictRemoteSAM registry key is missing. System allows remote SAM enumeration by standard users." -ForegroundColor Red
}
