# Test-VBSCredentialGuard.ps1
# Queries the local Win32_DeviceGuard class to verify active protection states.

Write-Host "--- Auditing Virtualization-Based Security Baseline ---" -ForegroundColor Cyan

try {
    $DG = Get-CimInstance -Namespace "Root\Microsoft\Windows\DeviceGuard" -ClassName "Win32_DeviceGuard" -ErrorAction Stop
    
    # SecurityServicesRunning: 1 = Credential Guard, 2 = HVCI
    $CredGuardRunning = $DG.SecurityServicesRunning -contains 1
    $HvciRunning = $DG.SecurityServicesRunning -contains 2
    
    $VbsColor = if ($DG.VirtualizationBasedSecurityStatus -eq 2) { "Green" } else { "Red" }
    $CredColor = if ($CredGuardRunning) { "Green" } else { "Red" }
    $HvciColor = if ($HvciRunning) { "Green" } else { "Red" }
    
    Write-Host "    - VBS Status: $($DG.VirtualizationBasedSecurityStatus) (Required = 2 [Running])" -ForegroundColor $VbsColor
    Write-Host "    - Credential Guard Running: $CredGuardRunning (Required = True)" -ForegroundColor $CredColor
    Write-Host "    - Hypervisor Code Integrity Running: $HvciRunning (Required = True)" -ForegroundColor $HvciColor
    
    # Query registry properties for System Guard and UEFI MAT
    $SystemGuard = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "ConfigureSystemGuardLaunch" -ErrorAction SilentlyContinue).ConfigureSystemGuardLaunch
    $MatRequired = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "HVCIMATRequired" -ErrorAction SilentlyContinue).HVCIMATRequired
    
    $SgColor = if ($SystemGuard -eq 1) { "Green" } else { "Red" }
    $MatColor = if ($MatRequired -eq 1) { "Green" } else { "Red" }
    
    Write-Host "    - System Guard Secure Launch: $SystemGuard (Required = 1)" -ForegroundColor $SgColor
    Write-Host "    - UEFI Memory Attributes Table Required: $MatRequired (Required = 1)" -ForegroundColor $MatColor
} catch {
    Write-Host "    - VULNERABLE: DeviceGuard WMI class could not be queried. VBS is likely disabled." -ForegroundColor Red
}
