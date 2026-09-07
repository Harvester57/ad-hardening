# Get-LltdResponderDriverStatus.ps1
# Description: Audits registry configuration of LLTD Responder (RSPNDR) driver on Domain Controllers.

Write-Host "--- Auditing LLTD Responder Driver Status ---" -ForegroundColor Cyan

$LltdPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD"
$Expected = @{
    "AllowRspndrOnDomain"        = 0
    "AllowRspndrOnPublicNet"     = 0
    "EnableRspndr"               = 0
    "ProhibitRspndrOnPrivateNet" = 0
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
