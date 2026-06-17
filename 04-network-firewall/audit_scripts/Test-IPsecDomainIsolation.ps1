# Test-IPsecDomainIsolation.ps1
# Checks the state of local IPsec Connection Security Rules.
# Accounts for role-specific rules (DC vs Endpoint).

Write-Host "Auditing IPsec Connection Security Rules..." -ForegroundColor Cyan

# 1. Determine local machine role
$IsDomainController = $false
try {
    $ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    if ($ComputerSystem.DomainRole -eq 4 -or $ComputerSystem.DomainRole -eq 5) {
        $IsDomainController = $true
    }
} catch {
    if (Get-Service -Name NTDS -ErrorAction SilentlyContinue) {
        $IsDomainController = $true
    }
}

$NonCompliant = $false

if ($IsDomainController) {
    Write-Host "Auditing Domain Controller IPsec rules..." -ForegroundColor Yellow
    
    # DC should have a Client Access rule set to Request (or better)
    $GeneralRule = Get-NetIPsecRule -DisplayName "Hardening: IPsec DC Client Access" -ErrorAction SilentlyContinue
    if ($null -eq $GeneralRule -or $GeneralRule.Enabled -ne $true) {
        Write-Host "    - General DC IPsec rule: NOT FOUND or DISABLED (Non-Compliant)" -ForegroundColor Red
        $NonCompliant = $true
    } else {
        $InboundSec = $GeneralRule.InboundSecurity
        $OutboundSec = $GeneralRule.OutboundSecurity
        if ($InboundSec -ne "Request" -and $InboundSec -ne "Require") {
            Write-Host "    - General DC IPsec Inbound Security is '$InboundSec' (Non-Compliant, should be Request)" -ForegroundColor Red
            $NonCompliant = $true
        } else {
            Write-Host "    - General DC IPsec Inbound Security: $InboundSec (Compliant)" -ForegroundColor Green
        }
    }
    
    # DC should have a DC-to-DC replication rule set to Require
    $DCDCRule = Get-NetIPsecRule -DisplayName "Hardening: IPsec DC-to-DC Replication" -ErrorAction SilentlyContinue
    if ($null -eq $DCDCRule -or $DCDCRule.Enabled -ne $true) {
        Write-Host "    - DC-to-DC Replication rule: NOT FOUND or DISABLED (Non-Compliant)" -ForegroundColor Red
        $NonCompliant = $true
    } else {
        $InboundSec = $DCDCRule.InboundSecurity
        $OutboundSec = $DCDCRule.OutboundSecurity
        if ($InboundSec -ne "Require" -or $OutboundSec -ne "Require") {
            Write-Host "    - DC-to-DC IPsec Inbound/Outbound is '$InboundSec'/'$OutboundSec' (Non-Compliant, should be Require)" -ForegroundColor Red
            $NonCompliant = $true
        } else {
            Write-Host "    - DC-to-DC IPsec rule: Require (Compliant)" -ForegroundColor Green
        }
    }
} else {
    Write-Host "Auditing Endpoint/Member Server IPsec rules..." -ForegroundColor Yellow
    
    # Endpoint should have a general Domain Isolation rule set to Request (transition) or Require (inbound) / Request (outbound)
    $GeneralRule = Get-NetIPsecRule -DisplayName "Hardening: IPsec Domain Isolation" -ErrorAction SilentlyContinue
    if ($null -eq $GeneralRule -or $GeneralRule.Enabled -ne $true) {
        Write-Host "    - Endpoint Domain Isolation rule: NOT FOUND or DISABLED (Non-Compliant)" -ForegroundColor Red
        $NonCompliant = $true
    } else {
        $InboundSec = $GeneralRule.InboundSecurity
        $OutboundSec = $GeneralRule.OutboundSecurity
        
        # Request/Request or Require/Request are acceptable depending on transition phase
        if ($InboundSec -eq "None" -or $OutboundSec -eq "None") {
            Write-Host "    - Endpoint Domain Isolation is set to None (Non-Compliant)" -ForegroundColor Red
            $NonCompliant = $true
        } else {
            Write-Host "    - Endpoint Domain Isolation rule: Enabled (Inbound: $InboundSec, Outbound: $OutboundSec) (Compliant)" -ForegroundColor Green
        }
    }
    
    # DHCP and DNS exemptions should be configured if outbound is strict
    $DHCPRule = Get-NetIPsecRule -DisplayName "Exempt: DHCP Traffic" -ErrorAction SilentlyContinue
    if ($null -eq $DHCPRule) {
        Write-Host "    - DHCP Exemption rule: NOT FOUND (Warning: highly recommended to prevent DHCP issues)" -ForegroundColor Yellow
    } else {
        Write-Host "    - DHCP Exemption rule: FOUND (Compliant)" -ForegroundColor Green
    }
    
    $DNSRule = Get-NetIPsecRule -DisplayName "Exempt: DNS Traffic" -ErrorAction SilentlyContinue
    if ($null -eq $DNSRule) {
        Write-Host "    - DNS Exemption rule: NOT FOUND (Warning: highly recommended to prevent DNS name resolution failures during boot)" -ForegroundColor Yellow
    } else {
        Write-Host "    - DNS Exemption rule: FOUND (Compliant)" -ForegroundColor Green
    }
}

if ($NonCompliant) {
    Write-Host "IPsec Domain Isolation Audit: Non-Compliant." -ForegroundColor Red
    exit 1
} else {
    Write-Host "IPsec Domain Isolation Audit: Compliant." -ForegroundColor Green
    exit 0
}
