# Test-TLSConfiguration.ps1
# Description: Audits TLS/Schannel protocol configuration, cipher suites, and ECC curves.

Write-Host "Auditing TLS and Cryptographic configurations..." -ForegroundColor Cyan

$NonCompliantCount = 0
$SchannelRoot = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"

# 1. Audit Protocols
$ProtocolsToDisable = @("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1")
foreach ($Proto in $ProtocolsToDisable) {
    $Subkeys = @("Client", "Server")
    foreach ($Subkey in $Subkeys) {
        $Path = "$($SchannelRoot)\$($Proto)\$($Subkey)"
        if (Test-Path $Path) {
            $Enabled = Get-ItemPropertyValue -Path $Path -Name "Enabled" -ErrorAction SilentlyContinue
            if ($Enabled -ne 0) {
                Write-Host "    - Protocol $($Proto) ($($Subkey)) is not disabled (Non-Compliant)." -ForegroundColor Red
                $NonCompliantCount++
            } else {
                Write-Host "    - Protocol $($Proto) ($($Subkey)) is disabled (Compliant)." -ForegroundColor Green
            }
        } else {
            Write-Host "    - Protocol $($Proto) ($($Subkey)) registry key does not exist (Compliant)." -ForegroundColor Green
        }
    }
}

# 2. Audit SSL Policy and ECC Curves
$SSLConfigPath = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"
if (Test-Path $SSLConfigPath) {
    $Functions = Get-ItemPropertyValue -Path $SSLConfigPath -Name "Functions" -ErrorAction SilentlyContinue
    $EccCurves = Get-ItemPropertyValue -Path $SSLConfigPath -Name "EccCurves" -ErrorAction SilentlyContinue

    if ($null -eq $Functions -or $Functions.Length -eq 0) {
        Write-Host "    - SSL Cipher Suite order policy is not configured (Non-Compliant)." -ForegroundColor Red
        $NonCompliantCount++
    } else {
        if ($Functions[0] -match "GCM") {
            Write-Host "    - SSL Cipher Suite priority matches standards (Compliant)." -ForegroundColor Green
        } else {
            Write-Host "    - SSL Cipher Suite priority does not favor secure GCM suites first (Non-Compliant)." -ForegroundColor Red
            $NonCompliantCount++
        }
    }

    if ($null -eq $EccCurves -or $EccCurves.Length -eq 0) {
        Write-Host "    - ECC Curve priority policy is not configured (Non-Compliant)." -ForegroundColor Red
        $NonCompliantCount++
    } else {
        if ($EccCurves[0] -eq "curve25519" -or $EccCurves[0] -eq "nistP384") {
            Write-Host "    - ECC Curve priority matches standards (Compliant)." -ForegroundColor Green
        } else {
            Write-Host "    - ECC Curve priority does not favor curve25519/nistP384 (Non-Compliant)." -ForegroundColor Red
            $NonCompliantCount++
        }
    }
} else {
    Write-Host "    - Custom SSL configuration policies are not configured (Non-Compliant)." -ForegroundColor Red
    $NonCompliantCount++
}

if ($NonCompliantCount -eq 0) {
    Write-Host "TLS and Cryptographic configuration: Compliant." -ForegroundColor Green
} else {
    Write-Host "TLS and Cryptographic configuration: Non-Compliant ($($NonCompliantCount) issue(s) detected)." -ForegroundColor Red
}
