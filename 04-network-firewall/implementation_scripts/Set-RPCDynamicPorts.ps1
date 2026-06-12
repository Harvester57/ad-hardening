# Set-RPCDynamicPorts.ps1
# Configures static RPC ports for NTDS/Netlogon and restricts system-wide ephemeral range.

Write-Host "Configuring RPC dynamic port restrictions..." -ForegroundColor Cyan

# 1. If Domain Controller, configure static ports for NTDS and Netlogon
$IsDC = (Get-CimInstance -ClassName Win32_ComputerSystem).Roles -contains "Primary_Domain_Controller"

if ($IsDC) {
    Write-Host "[+] Target is a Domain Controller. Configuring NTDS and Netlogon static ports..." -ForegroundColor Gray
    
    # NTDS Static Port -> TCP 50000
    $NtdsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
    if (-not (Test-Path $NtdsPath)) {
        New-Item -Path $NtdsPath -Force | Out-Null
    }
    Set-ItemProperty -Path $NtdsPath -Name "TCP/IP Port" -Value 50000 -Type DWord
    Write-Host "    NTDS Static Port set to TCP 50000." -ForegroundColor Green
    
    # Netlogon Static Port -> TCP 50001
    $NetlogonPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
    if (-not (Test-Path $NetlogonPath)) {
        New-Item -Path $NetlogonPath -Force | Out-Null
    }
    Set-ItemProperty -Path $NetlogonPath -Name "DCTcpipPort" -Value 50001 -Type DWord
    Write-Host "    Netlogon Static Port set to TCP 50001." -ForegroundColor Green

    # DFSR Static Port -> TCP 50002 (if DFSR namespace is present)
    try {
        $DfsrConfig = Get-CimInstance -Namespace "root\MicrosoftDFS" -ClassName DfsrServiceConfiguration -ErrorAction Stop
        if ($null -ne $DfsrConfig) {
            Set-CimInstance -Query "Select * from DfsrServiceConfiguration" -Namespace "root\MicrosoftDFS" -Property @{ RpcPortAssignment = 50002 } -ErrorAction Stop | Out-Null
            Write-Host "    DFSR Static Replication Port set to TCP 50002." -ForegroundColor Green
        }
    } catch {
        Write-Host "    DFSR WMI configuration not accessible or role not installed. Skipping." -ForegroundColor Yellow
    }
}

# 2. Restrict system-wide dynamic RPC port range (50000 - 50100)
Write-Host "[+] Enforcing global dynamic RPC ports via Netsh..." -ForegroundColor Gray

# Configure IPv4 Dynamic Ports
$ProcV4 = Start-Process netsh -ArgumentList "int ipv4 set dynamicport tcp start=50000 num=100" -Wait -NoNewWindow -PassThru
if ($ProcV4.ExitCode -eq 0) {
    Write-Host "    IPv4 Dynamic Port Range set to 50000-50100." -ForegroundColor Green
} else {
    Write-Error "    Failed to set IPv4 dynamic port range."
}

# Configure IPv6 Dynamic Ports
$ProcV6 = Start-Process netsh -ArgumentList "int ipv6 set dynamicport tcp start=50000 num=100" -Wait -NoNewWindow -PassThru
if ($ProcV6.ExitCode -eq 0) {
    Write-Host "    IPv6 Dynamic Port Range set to 50000-50100." -ForegroundColor Green
} else {
    Write-Error "    Failed to set IPv6 dynamic port range."
}

Write-Host "RPC Dynamic Port configuration applied successfully." -ForegroundColor Cyan
