# Test-RPCDynamicPorts.ps1
# Description: Audits dynamic RPC configurations and static ports.

Write-Host "Auditing dynamic RPC configurations..." -ForegroundColor Cyan

$IsDC = (Get-CimInstance -ClassName Win32_ComputerSystem).Roles -contains "Primary_Domain_Controller"
$vulnerable = $false

if ($IsDC) {
    # 1. NTDS Static Port Audit
    $NtdsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
    $NtdsVal = Get-ItemProperty -Path $NtdsPath -Name "TCP/IP Port" -ErrorAction SilentlyContinue
    $NtdsPort = if ($NtdsVal) { $NtdsVal."TCP/IP Port" } else { 0 }
    
    $NtdsColor = if ($NtdsPort -eq 38901) { "Green" } else { "Red"; $vulnerable = $true }
    Write-Host "    - NTDS Static Port: $($NtdsPort) (Expected = 38901)" -ForegroundColor $NtdsColor
    
    # 2. Netlogon Static Port Audit
    $NetlogonPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
    $NetlogonVal = Get-ItemProperty -Path $NetlogonPath -Name "DCTcpipPort" -ErrorAction SilentlyContinue
    $NetlogonPort = if ($NetlogonVal) { $NetlogonVal.DCTcpipPort } else { 0 }
    
    $NetlogonColor = if ($NetlogonPort -eq 38902) { "Green" } else { "Red"; $vulnerable = $true }
    Write-Host "    - Netlogon Static Port: $($NetlogonPort) (Expected = 38902)" -ForegroundColor $NetlogonColor

    # 3. DFSR Port Audit
    try {
        $DfsrConfig = Get-CimInstance -Namespace "root\MicrosoftDFS" -ClassName DfsrServiceConfiguration -ErrorAction Stop
        if ($null -ne $DfsrConfig) {
            $DfsrPort = $DfsrConfig.RpcPortAssignment
            $DfsrColor = if ($DfsrPort -eq 5722) { "Green" } else { "Red"; $vulnerable = $true }
            Write-Host "    - DFSR Replication Port: $($DfsrPort) (Expected = 5722)" -ForegroundColor $DfsrColor
        }
    } catch {
        Write-Host "    - DFSR role not active or WMI inaccessible." -ForegroundColor Gray
    }
}

# 4. Global Dynamic Port Audit (Netsh query)
Write-Host "[+] Querying active TCP dynamic port settings..." -ForegroundColor Yellow

$IPv4Ports = netsh int ipv4 show dynamicport tcp
$IPv6Ports = netsh int ipv6 show dynamicport tcp

Write-Host "--- IPv4 Dynamic Port Output ---" -ForegroundColor Gray
$IPv4Ports | Out-String | Write-Host -ForegroundColor DarkGray
Write-Host "--- IPv6 Dynamic Port Output ---" -ForegroundColor Gray
$IPv6Ports | Out-String | Write-Host -ForegroundColor DarkGray

# Verify if dynamic ranges are narrowed
$RpcInternetPath = "HKLM:\SOFTWARE\Microsoft\Rpc\Internet"
if (Test-Path $RpcInternetPath) {
    Write-Host "[!] VULNERABLE: Restrictive RPC Internet registry settings found. Narrowing dynamic ranges is not recommended." -ForegroundColor Red
    $vulnerable = $true
} else {
    Write-Host "[+] Restrictive RPC Internet registry settings are absent." -ForegroundColor Green
}

if ($vulnerable) {
    Write-Host "Audit result: NON-COMPLIANT" -ForegroundColor Red
} else {
    Write-Host "Audit result: COMPLIANT" -ForegroundColor Green
}
