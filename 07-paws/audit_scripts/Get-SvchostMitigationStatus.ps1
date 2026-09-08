# Get-SvchostMitigationStatus.ps1
# Description: Audits the configuration state of svchost.exe mitigation options on PAWs.

[CmdletBinding()]
param()

$RegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SCMConfig"
$ValueName = "EnableSvchostMitigationPolicy"
$ExpectedValue = 1

Write-Host "Auditing hardening requirement: Configure svchost.exe mitigation options on PAW..." -ForegroundColor Cyan

$osVersion = [System.Environment]::OSVersion.Version
$osBuild = $osVersion.Build

if ($osBuild -lt 18362) {
    Write-Warning "Audit Result: Non-Applicable / Unsupported. OS build $($osBuild) precedes the introduction of svchost mitigation policy (requires Windows 10 1903+ or Windows 11)."
    exit 1
}

if (Test-Path -Path $RegPath) {
    $item = Get-ItemProperty -Path $RegPath -Name $ValueName -ErrorAction SilentlyContinue
    if ($null -ne $item -and $item.$ValueName -eq $ExpectedValue) {
        Write-Host "Audit Result: Compliant. svchost.exe mitigation policy is enabled in registry ($($RegPath)\$($ValueName) = 1)." -ForegroundColor Green

        # Optional check for running svchost processes
        $svchostProcesses = Get-Process -Name "svchost" -ErrorAction SilentlyContinue
        if ($svchostProcesses) {
            Write-Host "Found $($svchostProcesses.Count) running svchost.exe process instances. Process mitigation flags are enforced dynamically at process spawn by the Service Control Manager." -ForegroundColor Gray
        }

        exit 0
    }
}

Write-Host "Audit Result: Non-Compliant. svchost.exe mitigation options are disabled or not configured ($($RegPath)\$($ValueName))." -ForegroundColor Red
exit 1
