# Get-OfficeSecurityStatus.ps1
# Description: Audits Microsoft Office macro settings and Outlook OLE package restrictions.

Write-Host "--- Auditing Microsoft Office Security Baseline ---" -ForegroundColor Cyan

$script:Vulnerable = $false

# Helper to audit registry values under HKCU
function Test-UserRegistryValue ($Path, $Name, $ExpectedValue) {
    $FullRegistryPath = "HKCU:\$Path"
    $Val = Get-ItemProperty -Path $FullRegistryPath -Name $Name -ErrorAction SilentlyContinue
    $Actual = if ($val) { $val.$Name } else { "" }
    $Color = "Red"
    if ($Actual -eq $ExpectedValue) {
        $Color = "Green"
    } else {
        $script:Vulnerable = $true
    }
    Write-Host "    - User Registry: $Name | Actual: '$Actual' (Expected: '$ExpectedValue')" -ForegroundColor $Color
}

# 1. Audit macro signing warning
Test-UserRegistryValue "software\policies\microsoft\office\16.0\common\security" "vbawarnings" 3

# 2. Audit macro Internet blocks
$Apps = @("excel", "word", "powerpoint", "access", "visio")
foreach ($App in $Apps) {
    Test-UserRegistryValue "software\policies\microsoft\office\16.0\$App\security" "blockcontentexecutionfrominternet" 1
}

# 3. Audit Outlook OLE package block
Test-UserRegistryValue "software\policies\microsoft\office\16.0\outlook\security" "ShowOLEPackageObj" 0

if ($script:Vulnerable) {
    Write-Host "Audit Result: VULNERABLE" -ForegroundColor Red
} else {
    Write-Host "Audit Result: SECURE" -ForegroundColor Green
}
