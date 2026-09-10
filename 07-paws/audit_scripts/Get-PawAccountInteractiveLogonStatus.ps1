# Get-PawAccountInteractiveLogonStatus.ps1
# Description: Audits interactive logon security options on PAWs.

Write-Host "--- Auditing PAW Interactive Logon Security Options ---" -ForegroundColor Cyan
$script:Vulnerable = $false

$SystemPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

function Test-RegVal ($Name, $Expected) {
    if (-not (Test-Path -Path $SystemPath)) {
        Write-Host "    [!] MISSING KEY: $SystemPath" -ForegroundColor Red
        $script:Vulnerable = $true
        return
    }
    $Prop = Get-ItemProperty -Path $SystemPath -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $Prop -or $null -eq $Prop.$Name) {
        Write-Host "    [!] MISSING VALUE: $Name under $SystemPath (Expected: $Expected)" -ForegroundColor Red
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

Test-RegVal "DisableCAD" 0
Test-RegVal "DontDisplayLastUserName" 1
Test-RegVal "CrashOnAuditFail" 0

if ($script:Vulnerable) {
    Write-Output "Non-Compliant"
    exit 1
} else {
    Write-Output "Compliant"
    exit 0
}
