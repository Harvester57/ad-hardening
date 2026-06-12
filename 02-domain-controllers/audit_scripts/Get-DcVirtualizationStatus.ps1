# Get-DcVirtualizationStatus.ps1
# Description: Audits the virtualization environment of the Domain Controller.

Write-Host "--- Auditing DC Virtualization Status ---" -ForegroundColor Cyan

# 1. Determine if running on physical or virtual hardware
$ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
$Model = $ComputerSystem.Model
$Manufacturer = $ComputerSystem.Manufacturer

Write-Host "[*] Host Manufacturer: $($Manufacturer)" -ForegroundColor White
Write-Host "[*] System Model:       $($Model)" -ForegroundColor White

$IsVirtual = $false
$HypervisorType = "Unknown"

if ($Model -match "Virtual Machine|VMware|VirtualBox|Xen") {
    $IsVirtual = $true
    if ($Manufacturer -match "Microsoft") { $HypervisorType = "Hyper-V" }
    elseif ($Manufacturer -match "VMware") { $HypervisorType = "VMware ESXi" }
}

if ($IsVirtual) {
    Write-Host "[-] WARNING: Domain Controller is virtualized on $($HypervisorType)." -ForegroundColor Yellow
    Write-Host "    Ensure the underlying host is secured as a Tier 0 asset." -ForegroundColor Yellow
    
    # 2. Check VM integration service settings if Hyper-V guest
    if ($HypervisorType -eq "Hyper-V") {
        $IntegrationServices = Get-Service -Name "vm*" -ErrorAction SilentlyContinue
        if ($IntegrationServices) {
            Write-Host "    Integration Services detected:" -ForegroundColor White
            foreach ($Svc in $IntegrationServices) {
                Write-Host "    - $($Svc.Name): $($Svc.Status)" -ForegroundColor White
            }
        }
    }
} else {
    Write-Host "[+] Domain Controller is running on physical hardware (secure boundary)." -ForegroundColor Green
}
