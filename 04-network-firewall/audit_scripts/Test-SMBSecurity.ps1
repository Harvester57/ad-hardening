# Test-SMBSecurity.ps1
# Description: Audits local SMB configuration for signing, encryption, and dialects.

Write-Host "Auditing SMB security configuration..." -ForegroundColor Cyan

$NonCompliantCount = 0

# Retrieve configurations
$ServerConfig = Get-SmbServerConfiguration
$ClientConfig = Get-SmbClientConfiguration

# 1. Audit SMBv1 Server status
if ($ServerConfig.EnableSMB1Protocol -eq $true) {
    Write-Host "    - SMBv1 Server protocol is enabled (Non-Compliant)." -ForegroundColor Red
    $NonCompliantCount++
} else {
    Write-Host "    - SMBv1 Server protocol is disabled (Compliant)." -ForegroundColor Green
}

# 2. Audit Signing Requirements
if ($ServerConfig.RequireSecuritySignature -ne $true) {
    Write-Host "    - SMB Server signing is not required (Non-Compliant)." -ForegroundColor Red
    $NonCompliantCount++
} else {
    Write-Host "    - SMB Server signing is mandated (Compliant)." -ForegroundColor Green
}

if ($ClientConfig.RequireSecuritySignature -ne $true) {
    Write-Host "    - SMB Client signing is not required (Non-Compliant)." -ForegroundColor Red
    $NonCompliantCount++
} else {
    Write-Host "    - SMB Client signing is mandated (Compliant)." -ForegroundColor Green
}

# 3. Audit Encryption Requirements
if ($ServerConfig.EncryptData -ne $true) {
    Write-Host "    - SMB Server global data encryption is not enforced (Non-Compliant)." -ForegroundColor Red
    $NonCompliantCount++
} else {
    Write-Host "    - SMB Server global data encryption is enforced (Compliant)." -ForegroundColor Green
}

# 4. Audit Registry Dialects
$ServerParamsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
$ClientParamsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"

if (Test-Path $ServerParamsPath) {
    $ServerMinDialect = Get-ItemPropertyValue -Path $ServerParamsPath -Name "MinSMB2Dialect" -ErrorAction SilentlyContinue
    if ($null -eq $ServerMinDialect -or $ServerMinDialect -lt 0x00000300) {
        Write-Host "    - Server minimum dialect is less than SMB 3.0 or not set (Non-Compliant)." -ForegroundColor Red
        $NonCompliantCount++
    } else {
        Write-Host "    - Server minimum dialect is set to SMB 3.0+ (Compliant)." -ForegroundColor Green
    }
} else {
    Write-Host "    - LanmanServer registry path is missing (Non-Compliant)." -ForegroundColor Red
    $NonCompliantCount++
}

if (Test-Path $ClientParamsPath) {
    $ClientMinDialect = Get-ItemPropertyValue -Path $ClientParamsPath -Name "MinSMB2Dialect" -ErrorAction SilentlyContinue
    if ($null -eq $ClientMinDialect -or $ClientMinDialect -lt 0x00000300) {
        Write-Host "    - Client minimum dialect is less than SMB 3.0 or not set (Non-Compliant)." -ForegroundColor Red
        $NonCompliantCount++
    } else {
        Write-Host "    - Client minimum dialect is set to SMB 3.0+ (Compliant)." -ForegroundColor Green
    }
} else {
    Write-Host "    - LanmanWorkstation registry path is missing (Non-Compliant)." -ForegroundColor Red
    $NonCompliantCount++
}

if ($NonCompliantCount -eq 0) {
    Write-Host "SMB Security configuration: Compliant." -ForegroundColor Green
} else {
    Write-Host "SMB Security configuration: Non-Compliant ($($NonCompliantCount) issue(s) detected)." -ForegroundColor Red
}
