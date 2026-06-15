# Set-IntraDcManagementBlocking.ps1
# Description: Configures local Windows Firewall rules to block remote management traffic (RDP, WinRM, WMI, ADWS) originating from other Domain Controllers to prevent lateral movement.

Write-Host "Applying hardening requirement: Block Management Traffic Between DCs..." -ForegroundColor Cyan

# 1. Get IP addresses of all Domain Controllers in the domain
$DcIPs = @()
try {
    $Dcs = Get-ADDomainController -Filter * -ErrorAction Stop
    foreach ($Dc in $Dcs) {
        # Skip local computer
        if ($Dc.Name -ne $env:COMPUTERNAME) {
            if ($Dc.IPv4Address) { $DcIPs += $Dc.IPv4Address }
            if ($Dc.IPv6Address) { $DcIPs += $Dc.IPv6Address }
        }
    }
} catch {
    Write-Host "    Get-ADDomainController not available or not in AD domain. Skipping dynamic discovery." -ForegroundColor Yellow
}

if ($DcIPs.Count -eq 0) {
    Write-Host "    No other Domain Controllers discovered. Blocking rule will be created but inactive." -ForegroundColor Yellow
    # Fallback to a dummy address to ensure rule structure is correct
    $DcIPs = @("255.255.255.255")
} else {
    Write-Host "    Discovered other DCs: $($DcIPs -join ', ')" -ForegroundColor Gray
}

# 2. Configure local block rules for DC-to-DC remote management
$BlockRules = @(
    @{ Name = "AD-Block-IntraDC-RDP"; Port = 3389; Proto = "TCP" },
    @{ Name = "AD-Block-IntraDC-WinRM-HTTP"; Port = 5985; Proto = "TCP" },
    @{ Name = "AD-Block-IntraDC-WinRM-HTTPS"; Port = 5986; Proto = "TCP" },
    @{ Name = "AD-Block-IntraDC-WMI"; Port = 24158; Proto = "TCP" },
    @{ Name = "AD-Block-IntraDC-ADWS"; Port = 9389; Proto = "TCP" }
)

foreach ($Rule in $BlockRules) {
    $Name = $Rule.Name
    $Port = $Rule.Port
    $Proto = $Rule.Proto
    
    $Existing = Get-NetFirewallRule -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $Existing) {
        New-NetFirewallRule -Name $Name -DisplayName $Name `
            -Direction Inbound `
            -Action Block `
            -Protocol $Proto `
            -LocalPort $Port `
            -RemoteAddress $DcIPs `
            -Profile Domain, Private `
            -Enabled True | Out-Null
        Write-Host "Block rule created: $($Name) on port $($Port) ($($Proto)) from other DCs." -ForegroundColor Green
    } else {
        Set-NetFirewallRule -Name $Name -Enabled True -Action Block -RemoteAddress $DcIPs | Out-Null
        Write-Host "Block rule verified: $($Name) on port $($Port) ($($Proto)) from other DCs." -ForegroundColor Gray
    }
}

Write-Host "Intra-DC management blocking rules applied successfully." -ForegroundColor Cyan
