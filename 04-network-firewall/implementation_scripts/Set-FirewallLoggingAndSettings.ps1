# Set-FirewallLoggingAndSettings.ps1
# Description: Configures Windows Defender Firewall settings, log size, and log permissions for all profiles.

Write-Host "Applying Windows Defender Firewall hardening settings..." -ForegroundColor Cyan

# 1. Detect if the local system is a Domain Controller (ProductType = 2 is Domain Controller)
$IsDomainController = $false
$OSInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
if ($null -ne $OSInfo) {
    if ($OSInfo.ProductType -eq 2) {
        $IsDomainController = $true
    }
}

# 2. Configure Domain, Private, and Public profiles
$Profiles = @("Domain", "Private", "Public")

foreach ($FwProfile in $Profiles) {
    Write-Host "Configuring Profile: $($FwProfile)..." -ForegroundColor Cyan
    
    # Enable firewall and set default inbound/outbound behavior and notifications
    Set-NetFirewallProfile -Profile $FwProfile `
                           -Enabled True `
                           -DefaultInboundAction Block `
                           -DefaultOutboundAction Allow `
                           -NotifyOnListen False `
                           -AllowUnicastResponseToMulticast True | Out-Null
                           
    # Configure logging: log dropped packets, disable successful logs, set size to 32MB (32768 KB)
    Set-NetFirewallProfile -Profile $FwProfile `
                           -LogBlocked True `
                           -LogAllowed False `
                           -LogMaxSizeKilobytes 32768 `
                           -LogFileName "%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log" | Out-Null
                           
    # Disable local rule merging only on Domain Controllers to prevent bypasses
    if ($IsDomainController) {
        Set-NetFirewallProfile -Profile $FwProfile `
                               -AllowLocalFirewallRules False `
                               -AllowLocalIPsecRules False | Out-Null
        Write-Host "Disabled local rule merging on DC for profile: $($FwProfile)" -ForegroundColor Green
    } else {
        Set-NetFirewallProfile -Profile $FwProfile `
                               -AllowLocalFirewallRules True `
                               -AllowLocalIPsecRules True | Out-Null
        Write-Host "Configured profile: $($FwProfile) with local rule merging allowed" -ForegroundColor Green
    }
}

Write-Host "Firewall logging and operational settings configuration completed successfully." -ForegroundColor Green
