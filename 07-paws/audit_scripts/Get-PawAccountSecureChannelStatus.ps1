# Get-PawAccountSecureChannelStatus.ps1
Write-Host "--- Auditing PAW Domain Member Secure Channel Settings ---" -ForegroundColor Cyan
$script:Vulnerable = $false

$NetlogonPath = "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters"

function Test-RegVal ($Name, $Expected) {
    $Val = (Get-ItemProperty -Path $NetlogonPath -Name $Name -ErrorAction SilentlyContinue).$Name
    if ($Val -ne $Expected) {
        Write-Host "    [!] VULNERABLE: $Name is '$Val' (Expected: $Expected)" -ForegroundColor Red
        $script:Vulnerable = $true
    } else {
        Write-Host "    [+] $($Name): $Val" -ForegroundColor Green
    }
}

Test-RegVal "RequireSignOrSeal" 1
Test-RegVal "SealSecureChannel" 1
Test-RegVal "SignSecureChannel" 1
Test-RegVal "DisablePasswordChange" 0
Test-RegVal "RequireStrongKey" 1

$MaxAge = (Get-ItemProperty -Path $NetlogonPath -Name "MaximumPasswordAge" -ErrorAction SilentlyContinue).MaximumPasswordAge
if ($null -eq $MaxAge -or $MaxAge -gt 30 -or $MaxAge -eq 0) {
    Write-Host "    [!] VULNERABLE: MaximumPasswordAge is '$MaxAge' (Expected: 30 or fewer, but not 0)" -ForegroundColor Red
    $script:Vulnerable = $true
} else {
    Write-Host "    [+] MaximumPasswordAge: $MaxAge" -ForegroundColor Green
}

if ($script:Vulnerable) {
    Write-Output "Non-Compliant"
    exit 1
} else {
    Write-Output "Compliant"
    exit 0
}
