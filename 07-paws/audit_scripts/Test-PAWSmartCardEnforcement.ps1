# Test-PAWSmartCardEnforcement.ps1
# Description: Audits if the registry is configured to require smart cards for interactive logons on PAWs.
# Target Engine: Windows PowerShell 5.1

Write-Host "--- Auditing PAW Smart Card Interactive Logon Requirement ---" -ForegroundColor Cyan

$RegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$ValueName = "ScForceOption"
$ExpectedValue = 1

$Vulnerable = $false

if (Test-Path $RegPath) {
    $Property = Get-ItemProperty -Path $RegPath -Name $ValueName -ErrorAction SilentlyContinue
    if ($null -ne $Property -and $Property.$ValueName -eq $ExpectedValue) {
        Write-Host "    - Registry Setting: $ValueName | Actual: $($Property.$ValueName) (Expected: $ExpectedValue)" -ForegroundColor Green
    } else {
        $actualVal = if ($null -ne $Property) { $Property.$ValueName } else { "Not Found" }
        Write-Host "    - Registry Setting: $ValueName | Actual: $actualVal (Expected: $ExpectedValue)" -ForegroundColor Red
        $Vulnerable = $true
    }
} else {
    Write-Host "    - Registry Path: $RegPath | Actual: Path Not Found (Expected: Path Exists)" -ForegroundColor Red
    $Vulnerable = $true
}

if ($Vulnerable) {
    Write-Host "Audit Result: VULNERABLE" -ForegroundColor Red
    exit 1
} else {
    Write-Host "Audit Result: SECURE" -ForegroundColor Green
    exit 0
}
