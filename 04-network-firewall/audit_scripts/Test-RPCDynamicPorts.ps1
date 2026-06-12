# Test-RPCDynamicPorts.ps1
# Audits dynamic RPC configurations and static ports.

Write-Host "Auditing dynamic RPC configurations..." -ForegroundColor Cyan

$IsDC = (Get-CimInstance -ClassName Win32_ComputerSystem).Roles -contains "Primary_Domain_Controller"

if ($IsDC) {
    # 1. NTDS Static Port Audit
    $NtdsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
    $NtdsVal = Get-ItemProperty -Path $NtdsPath -Name "TCP/IP Port" -ErrorAction SilentlyContinue
    $NtdsPort = if ($NtdsVal) { $NtdsVal."TCP/IP Port" } else { 0 }
    
    $NtdsColor = if ($NtdsPort -eq 50000) { "Green" } else { "Red" }
    Write-Host "    - NTDS Static Port: $($NtdsPort) (Expected = 50000)" -ForegroundColor $NtdsColor
    
    # 2. Netlogon Static Port Audit
    $NetlogonPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
    $NetlogonVal = Get-ItemProperty -Path $NetlogonPath -Name "DCTcpipPort" -ErrorAction SilentlyContinue
    $NetlogonPort = if ($NetlogonVal) { $NetlogonVal.DCTcpipPort } else { 0 }
    
    $NetlogonColor = if ($NetlogonPort -eq 50001) { "Green" } else { "Red" }
    Write-Host "    - Netlogon Static Port: $($NetlogonPort) (Expected = 50001)" -ForegroundColor $NetlogonColor

    # 3. DFSR Port Audit
    try {
        $DfsrConfig = Get-CimInstance -Namespace "root\MicrosoftDFS" -ClassName DfsrServiceConfiguration -ErrorAction Stop
        if ($null -ne $DfsrConfig) {
            $DfsrPort = $DfsrConfig.RpcPortAssignment
            $DfsrColor = if ($DfsrPort -eq 50002) { "Green" } else { "Red" }
            Write-Host "    - DFSR Replication Port: $($DfsrPort) (Expected = 50002)" -ForegroundColor $DfsrColor
        }
    } catch {
        Write-Host "    - DFSR role not available on this server." -ForegroundColor Gray
    }
}

# 4. Global Dynamic Port Audit (Netsh query)
Write-Host "[+] Querying active TCP dynamic port settings..." -ForegroundColor Yellow

$IPv4Ports = netsh int ipv4 show dynamicport tcp
$IPv6Ports = netsh int ipv6 show dynamicport tcp

# Parse netsh output (look for "Start Port" or number of ports)
$IPv4Match = $IPv4Ports -join "`n"
$IPv6Match = $IPv6Ports -join "`n"

Write-Host "--- IPv4 Dynamic Port Output ---" -ForegroundColor Gray
Write-Host $IPv4Match -ForegroundColor DarkGray
Write-Host "--- IPv6 Dynamic Port Output ---" -ForegroundColor Gray
Write-Host $IPv6Match -ForegroundColor DarkGray
