# Get-PawAccountLocalBlankPasswordsStatus.ps1
Write-Host "--- Auditing PAW Local Account and Blank Password Restrictions ---" -ForegroundColor Cyan
$script:Vulnerable = $false

$LsaPath = "HKLM:\System\CurrentControlSet\Control\Lsa"

function Test-RegVal ($Name, $Expected) {
    $Val = (Get-ItemProperty -Path $LsaPath -Name $Name -ErrorAction SilentlyContinue).$Name
    if ($Val -ne $Expected) {
        Write-Host "    [!] VULNERABLE: $Name is '$Val' (Expected: $Expected)" -ForegroundColor Red
        $script:Vulnerable = $true
    } else {
        Write-Host "    [+] $($Name): $Val" -ForegroundColor Green
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
