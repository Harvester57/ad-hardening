# Set-WorkstationIsolation.ps1
# Configures local firewall rules to block inbound SMB, RPC, and RDP from peer subnets.
# Allows access only from designated Domain Controller and Admin Management subnets.

# Adjust subnets for your local environment
$AdminSubnet = "10.10.0.0/24"      # PAW / Jump Host / DC Subnet
$PeerSubnet = "10.20.0.0/16"       # Local client/member peer subnet

Write-Host "Applying Workstation and Server Isolation Firewall Rules..." -ForegroundColor Cyan

# 1. Enable firewall profiles
Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled True
Write-Host "All firewall profiles enabled." -ForegroundColor Green

# 2. Block Inbound SMB (TCP 445) from peer subnet
New-NetFirewallRule -DisplayName "Hardening: Block Inbound SMB from Peers" `
    -Direction Inbound `
    -Action Block `
    -Protocol TCP `
    -LocalPort 445 `
    -RemoteAddress $PeerSubnet `
    -Profile Domain, Private `
    -Enabled True | Out-Null
Write-Host "SMB peer blocking rule created." -ForegroundColor Green

# 3. Block Inbound RDP (TCP 3389) from peer subnet
New-NetFirewallRule -DisplayName "Hardening: Block Inbound RDP from Peers" `
    -Direction Inbound `
    -Action Block `
    -Protocol TCP `
    -LocalPort 3389 `
    -RemoteAddress $PeerSubnet `
    -Profile Domain, Private `
    -Enabled True | Out-Null
Write-Host "RDP peer blocking rule created." -ForegroundColor Green

# 4. Block Inbound WinRM (TCP 5985, 5986) from peer subnet
New-NetFirewallRule -DisplayName "Hardening: Block Inbound WinRM from Peers" `
    -Direction Inbound `
    -Action Block `
    -Protocol TCP `
    -LocalPort @(5985, 5986) `
    -RemoteAddress $PeerSubnet `
    -Profile Domain, Private `
    -Enabled True | Out-Null
Write-Host "WinRM peer blocking rule created." -ForegroundColor Green

# 5. Block Inbound RPC (TCP 135) from peer subnet
New-NetFirewallRule -DisplayName "Hardening: Block Inbound RPC Mapper from Peers" `
    -Direction Inbound `
    -Action Block `
    -Protocol TCP `
    -LocalPort 135 `
    -RemoteAddress $PeerSubnet `
    -Profile Domain, Private `
    -Enabled True | Out-Null
Write-Host "RPC Endpoint Mapper peer blocking rule created." -ForegroundColor Green

# 6. Allow Inbound Administration from Management Subnet (RDP, WinRM, SMB)
New-NetFirewallRule -DisplayName "Hardening: Allow Admin Management Inbound" `
    -Direction Inbound `
    -Action Allow `
    -Protocol TCP `
    -LocalPort @(445, 3389, 5985, 5986) `
    -RemoteAddress $AdminSubnet `
    -Profile Domain `
    -Enabled True | Out-Null
Write-Host "Management subnet inbound allowance rule created." -ForegroundColor Green

Write-Host "Workstation and Server isolation firewall rules applied successfully." -ForegroundColor Cyan
