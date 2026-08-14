# Get-PawAccountSmbSecurityStatus.ps1
Write-Host "--- Auditing PAW SMB Client and Server Security Options ---" -ForegroundColor Cyan
$script:Vulnerable = $false

$LanmanWorkPath = "HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters"
$LanmanServerPath = "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters"
$NetlogonPath = "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters"

function Test-RegVal ($Path, $Name, $Expected) {
    $Val = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name
    if ($Val -ne $Expected) {
        Write-Host "    [!] VULNERABLE: $Name is '$Val' (Expected: $Expected)" -ForegroundColor Red
        $script:Vulnerable = $true
    } else {
        Write-Host "    [+] $($Name): $Val" -ForegroundColor Green
    }
}

Test-RegVal $LanmanWorkPath "EnablePlainTextPassword" 0
Test-RegVal $LanmanServerPath "AutoDisconnect" 15
Test-RegVal $LanmanServerPath "EnableForcedLogoff" 1
Test-RegVal $NetlogonPath "ForceLogoffWhenHourExpire" 1

$NullShares = (Get-ItemProperty -Path $LanmanServerPath -Name "NullSessionShares" -ErrorAction SilentlyContinue).NullSessionShares
if ($null -ne $NullShares -and $NullShares.Count -gt 0 -and $NullShares[0] -ne "") {
    Write-Host "    [!] VULNERABLE: NullSessionShares contains values: $($NullShares -join ', ')" -ForegroundColor Red
    $script:Vulnerable = $true
} else {
    Write-Host "    [+] NullSessionShares: None" -ForegroundColor Green
}

if ($script:Vulnerable) {
    Write-Output "Non-Compliant"
    exit 1
} else {
    Write-Output "Compliant"
    exit 0
}
