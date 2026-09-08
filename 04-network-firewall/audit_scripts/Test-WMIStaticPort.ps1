# Test-WMIStaticPort.ps1
# Description: Audits WMI static port registry configuration, DCOM authentication level, service isolation, and firewall rules.
# Target Engine: Windows PowerShell 5.1

Write-Host "Auditing WMI static port configuration and service hardening..." -ForegroundColor Cyan
$vulnerable = $false

# 1. Audit AppID Endpoints Registry Setting
$WmiAppIdPath = "HKLM:\SOFTWARE\Classes\AppID\{8BC3F05E-D86B-11D0-A075-00C04FB68820}"
$AppIdProps = Get-ItemProperty -Path $WmiAppIdPath -ErrorAction SilentlyContinue

if ($AppIdProps -and $AppIdProps.Endpoints) {
    $Endpoints = $AppIdProps.Endpoints
    if ($Endpoints -contains "ncacn_ip_tcp,0,24158") {
        Write-Host "[+] WMI static port registry endpoint is configured correctly (TCP 24158)." -ForegroundColor Green
    } else {
        Write-Host "[!] NON-COMPLIANT: WMI Endpoints registry value is: '$($Endpoints -join ', ')' (Expected: 'ncacn_ip_tcp,0,24158')" -ForegroundColor Red
        $vulnerable = $true
    }
} else {
    Write-Host "[!] NON-COMPLIANT: WMI AppID 'Endpoints' registry value is missing or inaccessible." -ForegroundColor Red
    $vulnerable = $true
}

# 2. Audit AppID DCOM Authentication Level (Packet Privacy = 6)
if ($AppIdProps -and $null -ne $AppIdProps.AuthenticationLevel) {
    $AuthLevel = [int]$AppIdProps.AuthenticationLevel
    if ($AuthLevel -ge 6) {
        Write-Host "[+] WMI AppID DCOM AuthenticationLevel is configured to Packet Privacy ($AuthLevel)." -ForegroundColor Green
    } else {
        Write-Host "[!] NON-COMPLIANT: WMI AppID AuthenticationLevel is: $AuthLevel (Expected: 6 [RPC_C_AUTHN_LEVEL_PKT_PRIVACY])" -ForegroundColor Red
        $vulnerable = $true
    }
} else {
    Write-Host "[!] NON-COMPLIANT: WMI AppID 'AuthenticationLevel' value is missing (Expected: 6)." -ForegroundColor Red
    $vulnerable = $true
}

# 3. Audit WMI Service Execution Type (Standalone Host = 16)
$WinmgmtPath = "HKLM:\SYSTEM\CurrentControlSet\Services\winmgmt"
$TypeVal = Get-ItemProperty -Path $WinmgmtPath -Name "Type" -ErrorAction SilentlyContinue

if ($TypeVal -and $null -ne $TypeVal.Type) {
    $Type = [int]$TypeVal.Type
    if ($Type -eq 16) {
        Write-Host "[+] WMI is configured to run as a standalone process (Type = 16 [SERVICE_WIN32_OWN_PROCESS])." -ForegroundColor Green
    } else {
        Write-Host "[!] NON-COMPLIANT: WMI service execution type is: $Type (Expected: 16 [SERVICE_WIN32_OWN_PROCESS])" -ForegroundColor Red
        $vulnerable = $true
    }
} else {
    Write-Host "[!] NON-COMPLIANT: WMI service registry key is missing or inaccessible." -ForegroundColor Red
    $vulnerable = $true
}

# 4. Audit Host Firewall Inbound Rule for TCP 24158
$FwRules = Get-NetFirewallRule -Direction Inbound -Enabled True -ErrorAction SilentlyContinue |
    Where-Object { $_.Action -eq "Allow" }

$WmiStaticPortAllowed = $false
foreach ($Rule in $FwRules) {
    $PortFilter = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $Rule -ErrorAction SilentlyContinue
    if ($PortFilter -and $PortFilter.Protocol -eq "TCP") {
        $LocalPorts = @($PortFilter.LocalPort)
        if ($LocalPorts -contains "24158") {
            $WmiStaticPortAllowed = $true
            break
        }
    }
}

if ($WmiStaticPortAllowed) {
    Write-Host "[+] Windows Defender Firewall has an active inbound allow rule for TCP port 24158." -ForegroundColor Green
} else {
    Write-Host "[!] NON-COMPLIANT: No active inbound firewall rule permitting TCP port 24158 found." -ForegroundColor Red
    $vulnerable = $true
}

# 5. Audit Built-in Dynamic WMI Firewall Rules
$DynamicWmiRules = Get-NetFirewallRule -DisplayGroup "Windows Management Instrumentation (WMI)" -Direction Inbound -Enabled True -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -like "*WMI-In*" }

if ($DynamicWmiRules) {
    $UnrestrictedDynamicRule = $false
    foreach ($DynRule in $DynamicWmiRules) {
        $AddressFilter = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $DynRule -ErrorAction SilentlyContinue
        if ($AddressFilter -and ($AddressFilter.RemoteAddress -contains "Any" -or -not $AddressFilter.RemoteAddress)) {
            $UnrestrictedDynamicRule = $true
            break
        }
    }
    if ($UnrestrictedDynamicRule) {
        Write-Host "[!] NON-COMPLIANT: Built-in dynamic WMI firewall rules are enabled and allow unconstrained dynamic RPC ports from Any address." -ForegroundColor Red
        $vulnerable = $true
    } else {
        Write-Host "[+] Built-in dynamic WMI firewall rules are restricted to specific subnets." -ForegroundColor Green
    }
} else {
    Write-Host "[+] Built-in generic dynamic WMI inbound firewall rules are disabled." -ForegroundColor Green
}

# Final Verdict
if ($vulnerable) {
    Write-Host "Audit result: NON-COMPLIANT" -ForegroundColor Red
} else {
    Write-Host "Audit result: COMPLIANT" -ForegroundColor Green
}
