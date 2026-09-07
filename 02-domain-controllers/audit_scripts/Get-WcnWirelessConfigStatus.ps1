# Get-WcnWirelessConfigStatus.ps1
# Description: Audits registry configuration of Windows Connect Now registrars on Domain Controllers.

Write-Host "--- Auditing Windows Connect Now Wireless Settings Configuration Status ---" -ForegroundColor Cyan

$WcnRegsPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars"
$Expected = @{
    "EnableRegistrars"               = 0
    "DisableUPnPRegistrar"           = 1
    "DisableInBand802DOT11Registrar" = 1
    "DisableFlashConfigRegistrar"    = 1
    "DisableWPDRegistrar"            = 1
}

$IsVulnerable = $false

if (Test-Path -Path $WcnRegsPath) {
    $Reg = Get-ItemProperty -Path $WcnRegsPath -ErrorAction SilentlyContinue
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
    Write-Host "    [!] WCN Registrars Registry Path NOT FOUND" -ForegroundColor Red
    $IsVulnerable = $true
}

if ($IsVulnerable) {
    exit 1
} else {
    exit 0
}
