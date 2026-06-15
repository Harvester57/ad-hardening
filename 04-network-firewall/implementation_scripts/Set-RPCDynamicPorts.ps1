# Set-RPCDynamicPorts.ps1
# Description: Configures static RPC ports for NTDS, Netlogon, and DFSR, and ensures system-wide dynamic RPC ranges are at default values.

Write-Host "Configuring RPC dynamic port restrictions..." -ForegroundColor Cyan

$IsDC = (Get-CimInstance -ClassName Win32_ComputerSystem).Roles -contains "Primary_Domain_Controller"

if ($IsDC) {
    Write-Host "[+] Target is a Domain Controller. Configuring static ports..." -ForegroundColor Gray
    
    # NTDS Static Port -> TCP 38901
    $NtdsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
    if (-not (Test-Path $NtdsPath)) {
        New-Item -Path $NtdsPath -Force | Out-Null
    }
    Set-ItemProperty -Path $NtdsPath -Name "TCP/IP Port" -Value 38901 -Type DWord
    Write-Host "    NTDS Static Port set to TCP 38901." -ForegroundColor Green
    
    # Netlogon Static Port -> TCP 38902
    $NetlogonPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
    if (-not (Test-Path $NetlogonPath)) {
        New-Item -Path $NetlogonPath -Force | Out-Null
    }
    Set-ItemProperty -Path $NetlogonPath -Name "DCTcpipPort" -Value 38902 -Type DWord
    Write-Host "    Netlogon Static Port set to TCP 38902." -ForegroundColor Green

    # DFSR Static Port -> TCP 5722 (if DFSR namespace is present)
    try {
        $DfsrConfig = Get-CimInstance -Namespace "root\MicrosoftDFS" -ClassName DfsrServiceConfiguration -ErrorAction Stop
        if ($null -ne $DfsrConfig) {
            Set-CimInstance -Query "Select * from DfsrServiceConfiguration" -Namespace "root\MicrosoftDFS" -Property @{ RpcPortAssignment = 5722 } -ErrorAction Stop | Out-Null
            Write-Host "    DFSR Static Replication Port set to TCP 5722." -ForegroundColor Green
        }
    } catch {
        Write-Host "    DFSR WMI configuration not accessible or role not installed. Skipping." -ForegroundColor Yellow
    }
}

# Ensure system-wide dynamic RPC range is at default (start=49152, num=16384)
# In accordance with Microsoft Directory Services guidelines to prevent port exhaustion.
Write-Host "[+] Resetting global dynamic RPC ports to default..." -ForegroundColor Gray

$ProcV4 = Start-Process netsh -ArgumentList "int ipv4 set dynamicport tcp start=49152 num=16384" -Wait -NoNewWindow -PassThru
if ($ProcV4.ExitCode -eq 0) {
    Write-Host "    IPv4 Dynamic Port Range reset to default (49152-65535)." -ForegroundColor Green
} else {
    Write-Error "    Failed to reset IPv4 dynamic port range."
}

$ProcV6 = Start-Process netsh -ArgumentList "int ipv6 set dynamicport tcp start=49152 num=16384" -Wait -NoNewWindow -PassThru
if ($ProcV6.ExitCode -eq 0) {
    Write-Host "    IPv6 Dynamic Port Range reset to default (49152-65535)." -ForegroundColor Green
} else {
    Write-Error "    Failed to reset IPv6 dynamic port range."
}

# Clean HKLM\SOFTWARE\Microsoft\Rpc\Internet range narrowing if present
$RpcInternetPath = "HKLM:\SOFTWARE\Microsoft\Rpc\Internet"
if (Test-Path $RpcInternetPath) {
    Remove-Item -Path $RpcInternetPath -Force -Recurse | Out-Null
    Write-Host "    Removed restrictive RPC Internet registry settings to restore defaults." -ForegroundColor Green
}

Write-Host "RPC dynamic port configuration applied successfully." -ForegroundColor Cyan
