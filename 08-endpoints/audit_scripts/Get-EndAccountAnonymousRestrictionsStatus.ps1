# Get-EndAccountAnonymousRestrictionsStatus.ps1
# Description: Audits Endpoint anonymous enumeration, PKU2U, and subsystem object security configuration.

Write-Host "--- Auditing Endpoint Anonymous Access and Enumeration Restrictions ---" -ForegroundColor Cyan
$script:Vulnerable = $false

$LsaPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
$KerbPath = "HKLM:\System\CurrentControlSet\Control\Lsa\Kerberos\Parameters"

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

Test-RegVal $LsaPath "RestrictAnonymousSAM" 1
Test-RegVal $LsaPath "RestrictAnonymous" 1
Test-RegVal $LsaPath "ObaseCaseInsensitive" 1
Test-RegVal $KerbPath "AllowPKU2U" 0

if ($script:Vulnerable) {
    Write-Output "Non-Compliant"
    exit 1
} else {
    Write-Output "Compliant"
    exit 0
}
