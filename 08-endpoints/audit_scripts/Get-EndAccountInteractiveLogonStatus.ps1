# Get-EndAccountInteractiveLogonStatus.ps1
Write-Host "--- Auditing Endpoint Interactive Logon Security Options ---" -ForegroundColor Cyan
$script:Vulnerable = $false

$SystemPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

function Test-RegVal ($Name, $Expected) {
    $Val = (Get-ItemProperty -Path $SystemPath -Name $Name -ErrorAction SilentlyContinue).$Name
    if ($Val -ne $Expected) {
        Write-Host "    [!] VULNERABLE: $Name is '$Val' (Expected: $Expected)" -ForegroundColor Red
        $script:Vulnerable = $true
    } else {
        Write-Host "    [+] $($Name): $Val" -ForegroundColor Green
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
