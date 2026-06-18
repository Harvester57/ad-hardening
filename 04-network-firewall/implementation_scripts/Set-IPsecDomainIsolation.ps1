# Set-IPsecDomainIsolation.ps1
# Configures local IPsec Connection Security Rules for Domain Isolation.
# Detects role (DC vs Endpoint) and applies appropriate isolation policies.

Write-Host "Configuring IPsec Connection Security Rules..." -ForegroundColor Cyan

# 1. Determine local machine role (Domain Controller vs Endpoint/Member Server)
$IsDomainController = $false
try {
    $ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    if ($ComputerSystem.DomainRole -eq 4 -or $ComputerSystem.DomainRole -eq 5) {
        $IsDomainController = $true
    }
} catch {
    # Fallback to checking NTDS service or environment variables if CimInstance fails
    if (Get-Service -Name NTDS -ErrorAction SilentlyContinue) {
        $IsDomainController = $true
    }
}

if ($IsDomainController) {
    Write-Host "Local system identified as a Domain Controller." -ForegroundColor Yellow
    
    # Define Rule Names
    $GeneralRuleName = "Hardening: IPsec DC Client Access"
    $DCDCRuleName = "Hardening: IPsec DC-to-DC Replication"
    
    # A. DC General Client Access Rule: Inbound/Outbound set to Request
    # Allows initial cleartext bootstrap (Kerberos, DNS, LDAP) for clients, then promotes to IPsec
    $ExistingGeneral = Get-NetIPsecRule -DisplayName $GeneralRuleName -ErrorAction SilentlyContinue
    if ($null -eq $ExistingGeneral) {
        New-NetIPsecRule -DisplayName $GeneralRuleName `
            -InboundSecurity Request `
            -OutboundSecurity Request `
            -Phase1AuthSet "ComputerKerberos" `
            -Enabled True | Out-Null
        Write-Host "Created general DC IPsec rule (Request mode)." -ForegroundColor Green
    } else {
        Set-NetIPsecRule -DisplayName $GeneralRuleName `
            -InboundSecurity Request `
            -OutboundSecurity Request `
            -Phase1AuthSet "ComputerKerberos" `
            -Enabled True | Out-Null
        Write-Host "Updated general DC IPsec rule (Request mode)." -ForegroundColor Gray
    }
    
    # B. DC-to-DC Replication Rule: Require authentication and require encryption
    # Targets replication ports or remote DC subnets
    $ExistingDCDC = Get-NetIPsecRule -DisplayName $DCDCRuleName -ErrorAction SilentlyContinue
    
    # Attempt to retrieve other DCs in the domain for remote IP targeting
    $DCIps = @()
    try {
        if (Get-Module -ListAvailable -Name ActiveDirectory) {
            Import-Module ActiveDirectory -ErrorAction Stop
            $DCIps = Get-ADDomainController -Filter * | Where-Object { $_.IPv4Address -ne (Get-NetIPAddress -AddressFamily IPv4 | Select-Object -ExpandProperty IPAddress) } | Select-Object -ExpandProperty IPv4Address
        }
    } catch {
        Write-Host "Could not query AD for other DC IP addresses. Rule will apply generally to replication ports." -ForegroundColor Yellow
    }
    
    # Configure the rule targeting replication traffic (TCP 49152-65535 or custom RPC)
    # Require authentication (forces IPsec) for DC-to-DC communication
    $Params = @{
        DisplayName = $DCDCRuleName
        InboundSecurity = "Require"
        OutboundSecurity = "Require"
        Phase1AuthSet = "ComputerKerberos"
        Protocol = "TCP"
        LocalPort = "49152-65535"
        Enabled = "True"
    }
    if ($DCIps.Count -gt 0) {
        $Params["RemoteAddress"] = $DCIps
    }
    
    if ($null -eq $ExistingDCDC) {
        New-NetIPsecRule @Params | Out-Null
        Write-Host "Created DC-to-DC replication encryption rule (Require mode)." -ForegroundColor Green
    } else {
        # RemoteAddress cannot be passed empty if we update, so omit if empty
        if ($null -eq $Params["RemoteAddress"]) {
            Set-NetIPsecRule -DisplayName $DCDCRuleName `
                -InboundSecurity Require `
                -OutboundSecurity Require `
                -Phase1AuthSet "ComputerKerberos" `
                -Protocol TCP `
                -LocalPort "49152-65535" `
                -Enabled True | Out-Null
        } else {
            Set-NetIPsecRule @Params | Out-Null
        }
        Write-Host "Updated DC-to-DC replication encryption rule (Require mode)." -ForegroundColor Gray
    }
} else {
    Write-Host "Local system identified as an Endpoint/Member Server." -ForegroundColor Yellow
    
    $RuleName = "Hardening: IPsec Domain Isolation"
    $ExistingRule = Get-NetIPsecRule -DisplayName $RuleName -ErrorAction SilentlyContinue
    
    # Endpoints: Request inbound and Request outbound for safe deployment, 
    # then promote to Require inbound and Request outbound (fallback to cleartext for DCs/Internet)
    if ($null -eq $ExistingRule) {
        New-NetIPsecRule -DisplayName $RuleName `
            -InboundSecurity Request `
            -OutboundSecurity Request `
            -Phase1AuthSet "ComputerKerberos" `
            -Enabled True | Out-Null
        Write-Host "Created general Endpoint IPsec rule (Request mode)." -ForegroundColor Green
    } else {
        Set-NetIPsecRule -DisplayName $RuleName `
            -InboundSecurity Request `
            -OutboundSecurity Request `
            -Phase1AuthSet "ComputerKerberos" `
            -Enabled True | Out-Null
        Write-Host "Updated general Endpoint IPsec rule (Request mode)." -ForegroundColor Gray
    }
    
    # Create Exemption Rules for DHCP and DNS to prevent boot lockouts
    $DHCPRuleName = "Exempt: DHCP Traffic"
    $DNSRuleName = "Exempt: DNS Traffic"
    
    # DHCP Rule (UDP 67, 68)
    $ExistingDHCP = Get-NetIPsecRule -DisplayName $DHCPRuleName -ErrorAction SilentlyContinue
    if ($null -eq $ExistingDHCP) {
        New-NetIPsecRule -DisplayName $DHCPRuleName `
            -InboundSecurity None `
            -OutboundSecurity None `
            -Protocol UDP `
            -LocalPort @("67", "68") `
            -Enabled True | Out-Null
        Write-Host "Created DHCP exemption rule." -ForegroundColor Green
    }
    
    # DNS Rule (UDP/TCP 53)
    $ExistingDNS = Get-NetIPsecRule -DisplayName $DNSRuleName -ErrorAction SilentlyContinue
    if ($null -eq $ExistingDNS) {
        New-NetIPsecRule -DisplayName $DNSRuleName `
            -InboundSecurity None `
            -OutboundSecurity None `
            -Protocol UDP `
            -RemotePort "53" `
            -Enabled True | Out-Null
        New-NetIPsecRule -DisplayName "$DNSRuleName (TCP)" `
            -InboundSecurity None `
            -OutboundSecurity None `
            -Protocol TCP `
            -RemotePort "53" `
            -Enabled True | Out-Null
        Write-Host "Created DNS exemption rules." -ForegroundColor Green
    }
}
