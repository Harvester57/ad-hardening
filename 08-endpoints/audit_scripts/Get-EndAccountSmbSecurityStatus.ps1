# Get-EndAccountSmbSecurityStatus.ps1
# Description: Audits SMB client and server security options on Endpoints.

Write-Host "--- Auditing Endpoint SMB Client and Server Security Options ---" -ForegroundColor Cyan
$script:Vulnerable = $false

$WorkstationPath = "HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters"
$ServerPath = "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters"
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

Test-RegVal $WorkstationPath "EnablePlainTextPassword" 0
Test-RegVal $ServerPath "AutoDisconnect" 15
Test-RegVal $ServerPath "EnableForcedLogoff" 1
Test-RegVal $NetlogonPath "ForceLogoffWhenHourExpire" 1

# Audit NullSessionShares
if (Test-Path -Path $ServerPath) {
    $NullShares = (Get-ItemProperty -Path $ServerPath -Name "NullSessionShares" -ErrorAction SilentlyContinue).NullSessionShares
    if ($null -ne $NullShares -and $NullShares.Count -gt 0 -and ($NullShares -join "") -ne "") {
        Write-Host "    [!] VULNERABLE: NullSessionShares contains: $($NullShares -join ', ')" -ForegroundColor Red
        $script:Vulnerable = $true
    } else {
        Write-Host "    [+] NullSessionShares: Empty (Secure)" -ForegroundColor Green
    }
}

if ($script:Vulnerable) {
    Write-Output "Non-Compliant"
    exit 1
} else {
    Write-Output "Compliant"
    exit 0
}
