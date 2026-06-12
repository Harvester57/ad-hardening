# Set-AdminProtocolRestrictions.ps1
# Creates inbound firewall rules to restrict RDP and WinRM to designated management subnets.

Write-Host "--- Restricting Administrative Protocols Inbound ---" -ForegroundColor Cyan

# Define the authorized administrative network subnet
$AdminSubnet = "10.10.0.0/24" # Replace with your PAW / Jump Host subnet

# 1. Restrict RDP (TCP port 3389) Inbound
$RdpRule = Get-NetFirewallRule -DisplayName "Remote Desktop - User Mode (TCP-In)" -ErrorAction SilentlyContinue
if ($RdpRule) {
    Write-Host "[+] Restricting existing RDP firewall rule to admin subnet..." -ForegroundColor Gray
    Set-NetFirewallRule -DisplayName "Remote Desktop - User Mode (TCP-In)" -RemoteAddress $AdminSubnet
    Write-Host "    RDP rule restricted." -ForegroundColor Green
} else {
    Write-Host "[+] Creating new restricted RDP inbound rule..." -ForegroundColor Gray
    New-NetFirewallRule -DisplayName "Hardening: Restricted RDP Inbound" `
        -Direction Inbound `
        -Action Allow `
        -Protocol TCP `
        -LocalPort 3389 `
        -RemoteAddress $AdminSubnet `
        -Enabled True | Out-Null
    Write-Host "    Restricted RDP rule created." -ForegroundColor Green
}

# 2. Restrict WinRM HTTPS (TCP port 5986) Inbound
$WinRMRule = Get-NetFirewallRule -DisplayName "Windows Remote Management (HTTPS-In)" -ErrorAction SilentlyContinue
if ($WinRMRule) {
    Write-Host "[+] Restricting existing WinRM HTTPS rule to admin subnet..." -ForegroundColor Gray
    Set-NetFirewallRule -DisplayName "Windows Remote Management (HTTPS-In)" -RemoteAddress $AdminSubnet
    Write-Host "    WinRM rule restricted." -ForegroundColor Green
} else {
    Write-Host "[+] Creating new restricted WinRM HTTPS inbound rule..." -ForegroundColor Gray
    New-NetFirewallRule -DisplayName "Hardening: Restricted WinRM HTTPS Inbound" `
        -Direction Inbound `
        -Action Allow `
        -Protocol TCP `
        -LocalPort 5986 `
        -RemoteAddress $AdminSubnet `
        -Enabled True | Out-Null
    Write-Host "    Restricted WinRM rule created." -ForegroundColor Green
}
