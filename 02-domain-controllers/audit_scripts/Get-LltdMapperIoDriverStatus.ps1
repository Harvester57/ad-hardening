# Get-LltdMapperIoDriverStatus.ps1
# Description: Audits registry configuration of LLTD Mapper I/O (LLTDIO) driver on Domain Controllers.

Write-Host "--- Auditing LLTD Mapper I/O Driver Status ---" -ForegroundColor Cyan

$LltdPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD"
$Expected = @{
    "AllowLLTDIOOnDomain"        = 0
    "AllowLLTDIOOnPublicNet"     = 0
    "EnableLLTDIO"               = 0
    "ProhibitLLTDIOOnPrivateNet" = 0
}

$IsVulnerable = $false

if (Test-Path -Path $LltdPath) {
    $Reg = Get-ItemProperty -Path $LltdPath -ErrorAction SilentlyContinue
    foreach ($Key in $Expected.Keys) {
        $Val = $Reg.$Key
        $Exp = $Expected[$Key]
        if ($Val -eq $Exp) {
            Write-Host "    [+] $($Key): $($Val) (Expected: $($Exp))" -ForegroundColor Green
        } else {
            Write-Host "    [!] $($Key): $($Val) (Expected: $($Exp))" -ForegroundColor Red
            $IsVulnerable = $true
        }
    }
} else {
    Write-Host "    [!] LLTD Registry Path NOT FOUND" -ForegroundColor Red
    $IsVulnerable = $true
}

if ($IsVulnerable) {
    exit 1
} else {
    exit 0
}
