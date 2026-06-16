# Test-PawKernelShadowStacks.ps1
# Description: Audits the registry status of Kernel-mode Hardware-enforced Stack Protection (Kernel Shadow Stacks) for PAWs.

Write-Host "--- Auditing PAW Kernel-mode Hardware-enforced Stack Protection ---" -ForegroundColor Cyan

$script:Vulnerable = $false
$RegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\KernelShadowStacks"

# Check registry value
$val = Get-ItemProperty -Path $RegPath -Name "Enabled" -ErrorAction SilentlyContinue
$actual = if ($val) { $val.Enabled } else { "" }

if ($actual -eq 1) {
    Write-Host "    - Registry Setting: KernelShadowStacks Enabled | Actual: '1' (Expected: '1')" -ForegroundColor Green
} else {
    $script:Vulnerable = $true
    Write-Host "    - Registry Setting: KernelShadowStacks Enabled | Actual: '$actual' (Expected: '1')" -ForegroundColor Red
}

# Verify VBS dependency is met
try {
    $DG = Get-CimInstance -Namespace "Root\Microsoft\Windows\DeviceGuard" -ClassName "Win32_DeviceGuard" -ErrorAction Stop
    if ($DG.VirtualizationBasedSecurityStatus -eq 2) {
        Write-Host "    - VBS Status: Running" -ForegroundColor Green
    } else {
        $script:Vulnerable = $true
        Write-Host "    - VBS Status: Not Running (VBS is required for Kernel Shadow Stacks)" -ForegroundColor Red
    }
} catch {
    $script:Vulnerable = $true
    Write-Host "    - DeviceGuard WMI class query failed. VBS is likely disabled." -ForegroundColor Red
}

if ($script:Vulnerable) {
    Write-Host "Audit Result: VULNERABLE" -ForegroundColor Red
} else {
    Write-Host "Audit Result: SECURE" -ForegroundColor Green
}
