# Set-ADPortMatrixRules.ps1
# Configures local Windows Defender Firewall profiles and applies basic AD port matrix baseline rules.

Write-Host "Applying network firewall baseline policies..." -ForegroundColor Cyan

# 1. Enable firewall and set default block inbound
Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow
Write-Host "Firewall profiles enabled with Default Inbound Block." -ForegroundColor Green

# 2. Configure AD Port Matrix inbound rules (for local system role validation)
# Allow critical outbound by default, construct rules for inbound
$Rules = @(
    @{ Name = "AD-DNS-TCP"; Port = 53; Proto = "TCP" },
    @{ Name = "AD-DNS-UDP"; Port = 53; Proto = "UDP" },
    @{ Name = "AD-Kerberos-TCP"; Port = 88; Proto = "TCP" },
    @{ Name = "AD-Kerberos-UDP"; Port = 88; Proto = "UDP" },
    @{ Name = "AD-NTP-UDP"; Port = 123; Proto = "UDP" },
    @{ Name = "AD-RPC-Mapper-TCP"; Port = 135; Proto = "TCP" },
    @{ Name = "AD-LDAP-TCP"; Port = 389; Proto = "TCP" },
    @{ Name = "AD-LDAP-UDP"; Port = 389; Proto = "UDP" },
    @{ Name = "AD-SMB-TCP"; Port = 445; Proto = "TCP" },
    @{ Name = "AD-Kpwd-TCP"; Port = 464; Proto = "TCP" },
    @{ Name = "AD-Kpwd-UDP"; Port = 464; Proto = "UDP" },
    @{ Name = "AD-LDAPS-TCP"; Port = 636; Proto = "TCP" },
    @{ Name = "AD-GC-TCP"; Port = 3268; Proto = "TCP" },
    @{ Name = "AD-GC-SSL-TCP"; Port = 3269; Proto = "TCP" }
)

foreach ($Rule in $Rules) {
    $Name = $Rule.Name
    $Port = $Rule.Port
    $Proto = $Rule.Proto
    
    $Existing = Get-NetFirewallRule -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $Existing) {
        New-NetFirewallRule -Name $Name -DisplayName $Name `
            -Direction Inbound `
            -Action Allow `
            -Protocol $Proto `
            -LocalPort $Port `
            -Profile Domain, Private `
            -Enabled True | Out-Null
        Write-Host "Inbound rule created: $($Name) on port $($Port) ($($Proto))" -ForegroundColor Green
    } else {
        Set-NetFirewallRule -Name $Name -Enabled True -Action Allow | Out-Null
        Write-Host "Inbound rule verified: $($Name)" -ForegroundColor Gray
    }
}

Write-Host "Firewall port matrix configuration completed successfully." -ForegroundColor Cyan
