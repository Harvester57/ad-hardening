# Get-PawAccountLocalBlankPasswordsStatus.ps1
# Description: Audits local account restrictions, LM hash generation, and sharing model on PAWs.

Write-Host "--- Auditing PAW Local Account and Blank Password Restrictions ---" -ForegroundColor Cyan
$script:Vulnerable = $false

$LsaPath = "HKLM:\System\CurrentControlSet\Control\Lsa"

function Test-RegVal ($Name, $Expected) {
    if (-not (Test-Path -Path $LsaPath)) {
        Write-Host "    [!] MISSING KEY: $LsaPath" -ForegroundColor Red
        $script:Vulnerable = $true
        return
    }
    $Prop = Get-ItemProperty -Path $LsaPath -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $Prop -or $null -eq $Prop.$Name) {
        Write-Host "    [!] MISSING VALUE: $Name under $LsaPath (Expected: $Expected)" -ForegroundColor Red
        $script:Vulnerable = $true
        return
    }
    $Val = $Prop.$Name
    if ($Val -ne $Expected) {
        Write-Host "    [!] VULNERABLE: $Name is '$Val' (Expected: $Expected)" -ForegroundColor Red
        $script:Vulnerable = $true
    } else {
        Write-Host "    [+] $($Name): $Val (Secure)" -ForegroundColor Green
    }
}

Test-RegVal "LimitBlankPasswordUse" 1
Test-RegVal "NoLMHash" 1
Test-RegVal "ForceNetworkLogon" 0

if ($script:Vulnerable) {
    Write-Output "Non-Compliant"
    exit 1
} else {
    Write-Output "Compliant"
    exit 0
}
