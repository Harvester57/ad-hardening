# Set-ADPortMatrixRules.ps1
# Configures local Windows Defender Firewall profiles and applies basic AD port matrix baseline rules.

param(
    [string[]]$ManagementAddresses
)

# If not passed, prompt user dynamically
if ($null -eq $ManagementAddresses) {
    if ([Environment]::UserInteractive) {
        $inputVal = Read-Host "Enter remote IP addresses/subnets for remote management (comma-separated, e.g. 10.0.0.0/24,192.168.1.50) [leave empty for LocalSubnet]"
        if ([string]::IsNullOrWhiteSpace($inputVal)) {
            $ManagementAddresses = @("LocalSubnet")
        } else {
            $ManagementAddresses = $inputVal.Split(",") | ForEach-Object { $_.Trim() }
        }
    } else {
        $ManagementAddresses = @("LocalSubnet")
    }
}

Write-Host "Applying network firewall baseline policies..." -ForegroundColor Cyan

# 1. Enable firewall and set default block inbound
Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow
Write-Host "Firewall profiles enabled with Default Inbound Block." -ForegroundColor Green

# 2. Configure AD Port Matrix inbound rules (for local system role validation)
$Rules = @(
    @{ Name = "AD-DNS-TCP"; Port = 53; Proto = "TCP"; Remote = "Any" },
    @{ Name = "AD-DNS-UDP"; Port = 53; Proto = "UDP"; Remote = "Any" },
    @{ Name = "AD-Kerberos-TCP"; Port = 88; Proto = "TCP"; Remote = "Any" },
    @{ Name = "AD-Kerberos-UDP"; Port = 88; Proto = "UDP"; Remote = "Any" },
    @{ Name = "AD-NTP-UDP"; Port = 123; Proto = "UDP"; Remote = "Any" },
    @{ Name = "AD-RPC-Mapper-TCP"; Port = 135; Proto = "TCP"; Remote = "Any" },
    @{ Name = "AD-LDAP-TCP"; Port = 389; Proto = "TCP"; Remote = "Any" },
    @{ Name = "AD-LDAP-UDP"; Port = 389; Proto = "UDP"; Remote = "Any" },
    @{ Name = "AD-SMB-TCP"; Port = 445; Proto = "TCP"; Remote = "Any" },
    @{ Name = "AD-Kpwd-TCP"; Port = 464; Proto = "TCP"; Remote = "Any" },
    @{ Name = "AD-Kpwd-UDP"; Port = 464; Proto = "UDP"; Remote = "Any" },
    @{ Name = "AD-LDAPS-TCP"; Port = 636; Proto = "TCP"; Remote = "Any" },
    @{ Name = "AD-GC-TCP"; Port = 3268; Proto = "TCP"; Remote = "Any" },
    @{ Name = "AD-GC-SSL-TCP"; Port = 3269; Proto = "TCP"; Remote = "Any" },
    @{ Name = "AD-NTDS-Static-TCP"; Port = 38901; Proto = "TCP"; Remote = "Any" },
    @{ Name = "AD-Netlogon-Static-TCP"; Port = 38902; Proto = "TCP"; Remote = "Any" },
    @{ Name = "AD-DFSR-Static-TCP"; Port = 5722; Proto = "TCP"; Remote = "Any" },
    @{ Name = "AD-RDP-TCP"; Port = 3389; Proto = "TCP"; Remote = $ManagementAddresses },
    @{ Name = "AD-WinRM-HTTP-TCP"; Port = 5985; Proto = "TCP"; Remote = $ManagementAddresses },
    @{ Name = "AD-WinRM-HTTPS-TCP"; Port = 5986; Proto = "TCP"; Remote = $ManagementAddresses }
)

foreach ($Rule in $Rules) {
    $Name = $Rule.Name
    $Port = $Rule.Port
    $Proto = $Rule.Proto
    $Remote = $Rule.Remote
    
    $Existing = Get-NetFirewallRule -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $Existing) {
        New-NetFirewallRule -Name $Name -DisplayName $Name `
            -Direction Inbound `
            -Action Allow `
            -Protocol $Proto `
            -LocalPort $Port `
            -RemoteAddress $Remote `
            -Profile Domain, Private `
            -Enabled True | Out-Null
        Write-Host "Inbound rule created: $($Name) on port $($Port) ($($Proto)) from remote address: $($Remote -join ', ')" -ForegroundColor Green
    } else {
        Set-NetFirewallRule -Name $Name -Enabled True -Action Allow -RemoteAddress $Remote | Out-Null
        Write-Host "Inbound rule verified: $($Name) restricted to remote address: $($Remote -join ', ')" -ForegroundColor Gray
    }
}

Write-Host "Firewall port matrix configuration completed successfully." -ForegroundColor Cyan

