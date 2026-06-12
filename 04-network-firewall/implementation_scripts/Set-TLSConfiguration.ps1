# Set-TLSConfiguration.ps1
# Description: Hardens TLS/Schannel protocols, prioritizes modern cipher suites, and orders ECC curves.

Write-Host "Configuring Schannel protocols, cipher suites, and ECC curves..." -ForegroundColor Cyan

# Define Protocols to disable
$ProtocolsToDisable = @("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1")
# Define Protocols to enable
$ProtocolsToEnable = @("TLS 1.2", "TLS 1.3")

# 1. Configure Protocols
$SchannelRoot = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"

foreach ($Proto in $ProtocolsToDisable) {
    $Subkeys = @("Client", "Server")
    foreach ($Subkey in $Subkeys) {
        $Path = "$($SchannelRoot)\$($Proto)\$($Subkey)"
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }
        Set-ItemProperty -Path $Path -Name "Enabled" -Value 0 -Type DWord -Force | Out-Null
        Set-ItemProperty -Path $Path -Name "DisabledByDefault" -Value 1 -Type DWord -Force | Out-Null
    }
}

foreach ($Proto in $ProtocolsToEnable) {
    $Subkeys = @("Client", "Server")
    foreach ($Subkey in $Subkeys) {
        $Path = "$($SchannelRoot)\$($Proto)\$($Subkey)"
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }
        Set-ItemProperty -Path $Path -Name "Enabled" -Value 1 -Type DWord -Force | Out-Null
        Set-ItemProperty -Path $Path -Name "DisabledByDefault" -Value 0 -Type DWord -Force | Out-Null
    }
}

# 2. Configure SSL Cipher Suite Order and ECC Curve Order Policy
$SSLConfigPath = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"
if (-not (Test-Path $SSLConfigPath)) {
    New-Item -Path $SSLConfigPath -Force | Out-Null
}

# Define cipher suites list
$CipherSuites = @(
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"
)

# Define ECC curves list
$EccCurves = @(
    "curve25519",
    "nistP384",
    "nistP256"
)

# Apply policy properties
Set-ItemProperty -Path $SSLConfigPath -Name "Functions" -Value $CipherSuites -Type MultiString -Force | Out-Null
Set-ItemProperty -Path $SSLConfigPath -Name "EccCurves" -Value $EccCurves -Type MultiString -Force | Out-Null

# 3. Configure .NET strong cryptography, strong-name bypass, and WinHTTP TLS
$RegistryTargets = @(
    @{ Path = "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727"; Name = "SchUseStrongCrypto"; Value = 1; Type = "DWord" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727"; Name = "SystemDefaultTlsVersions"; Value = 1; Type = "DWord" }
    @{ Path = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727"; Name = "SchUseStrongCrypto"; Value = 1; Type = "DWord" }
    @{ Path = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727"; Name = "SystemDefaultTlsVersions"; Value = 1; Type = "DWord" }
    
    @{ Path = "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319"; Name = "SchUseStrongCrypto"; Value = 1; Type = "DWord" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319"; Name = "SystemDefaultTlsVersions"; Value = 1; Type = "DWord" }
    @{ Path = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319"; Name = "SchUseStrongCrypto"; Value = 1; Type = "DWord" }
    @{ Path = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319"; Name = "SystemDefaultTlsVersions"; Value = 1; Type = "DWord" }
    
    @{ Path = "HKLM:\SOFTWARE\Microsoft\.NETFramework"; Name = "AllowStrongNameBypass"; Value = 0; Type = "DWord" }
    @{ Path = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework"; Name = "AllowStrongNameBypass"; Value = 0; Type = "DWord" }
    
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp"; Name = "DefaultSecureProtocols"; Value = 2048; Type = "DWord" }
    @{ Path = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp"; Name = "DefaultSecureProtocols"; Value = 2048; Type = "DWord" }
)

foreach ($target in $RegistryTargets) {
    if (-not (Test-Path $target.Path)) {
        New-Item -Path $target.Path -Force | Out-Null
    }
    Set-ItemProperty -Path $target.Path -Name $target.Name -Value $target.Value -Type $target.Type -Force | Out-Null
}

Write-Host "Schannel configuration applied. A system reboot is required to apply changes." -ForegroundColor Green
