# Get-PawAccountSecureChannelStatus.ps1
# Description: Audits Netlogon secure channel parameters on PAWs.

Write-Host "--- Auditing PAW Domain Member Secure Channel Settings ---" -ForegroundColor Cyan
$script:Vulnerable = $false

$NetlogonPath = "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters"

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

Test-RegVal $NetlogonPath "RequireSignOrSeal" 1
Test-RegVal $NetlogonPath "SealSecureChannel" 1
Test-RegVal $NetlogonPath "SignSecureChannel" 1
Test-RegVal $NetlogonPath "DisablePasswordChange" 0
Test-RegVal $NetlogonPath "MaximumPasswordAge" 30
Test-RegVal $NetlogonPath "RequireStrongKey" 1

if ($script:Vulnerable) {
    Write-Output "Non-Compliant"
    exit 1
} else {
    Write-Output "Compliant"
    exit 0
}
