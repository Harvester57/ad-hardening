# Get-PawAccountHelloPinStatus.ps1
# Description: Audits Windows Hello for Business, PIN complexity, and TPM enforcement status on PAWs.

Write-Host "--- Auditing PAW Windows Hello and PIN Policies ---" -ForegroundColor Cyan
$script:Vulnerable = $false

function Test-RegVal ($Path, $Name, $Expected) {
    if (-not (Test-Path -Path $Path)) {
        Write-Host "    [!] MISSING KEY: $Path" -ForegroundColor Red
        $script:Vulnerable = $true
        return
    }
    $Prop = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $Prop -or $null -eq $Prop.$Name) {
        Write-Host "    [!] MISSING VALUE: $Name under $Path (Expected: $Expected)" -ForegroundColor Red
        $script:Vulnerable = $true
        return
    }
    $Val = $Prop.$Name
    if ($Val -ne $Expected) {
        Write-Host "    [!] VULNERABLE: $Name under $Path is '$Val' (Expected: $Expected)" -ForegroundColor Red
        $script:Vulnerable = $true
    } else {
        Write-Host "    [+] $($Name): $Val (Secure)" -ForegroundColor Green
    }
}

Test-RegVal "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "AllowDomainPINLogon" 0
Test-RegVal "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity" "MinimumPINLength" 6
Test-RegVal "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork" "RequireSecurityDevice" 1
Test-RegVal "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\ExcludeSecurityDevices" "TPM12" 0
Test-RegVal "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "MSAOptional" 1

if ($script:Vulnerable) {
    Write-Output "Non-Compliant"
    exit 1
} else {
    Write-Output "Compliant"
    exit 0
}
