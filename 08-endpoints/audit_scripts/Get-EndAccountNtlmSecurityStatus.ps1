# Get-EndAccountNtlmSecurityStatus.ps1
Write-Host "--- Auditing Endpoint NTLM and LAN Manager Security ---" -ForegroundColor Cyan
$script:Vulnerable = $false

$LsaPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
$MsvPath = "HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0"

function Test-RegVal ($Path, $Name, $Expected) {
    $Val = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name
    if ($Val -ne $Expected) {
        Write-Host "    [!] VULNERABLE: $Name under $Path is '$Val' (Expected: $Expected)" -ForegroundColor Red
        $script:Vulnerable = $true
    } else {
        Write-Host "    [+] $($Name): $Val" -ForegroundColor Green
    }
}

Test-RegVal $LsaPath "LmCompatibilityLevel" 5
Test-RegVal $MsvPath "NTLMMinClientSec" 537395200
Test-RegVal $MsvPath "NTLMMinServerSec" 537395200
Test-RegVal $MsvPath "allownullsessionfallback" 0

if ($script:Vulnerable) {
    Write-Output "Non-Compliant"
    exit 1
} else {
    Write-Output "Compliant"
    exit 0
}
