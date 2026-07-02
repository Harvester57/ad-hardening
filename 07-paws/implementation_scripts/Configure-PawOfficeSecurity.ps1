# Configure-PawOfficeSecurity.ps1
# Description: Configures registry settings under the HKCU hive to restrict VBA macros and block Outlook OLE package execution on PAWs.

Write-Host "Applying Microsoft Office security and OLE restrictions..." -ForegroundColor Cyan

# Helper to configure User Registry DWORD values
function Set-UserRegDWord {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [string]$Path,
        [string]$Name,
        [int]$Value
    )
    if ($PSCmdlet.ShouldProcess($Path, "Set registry DWORD value $Name to $Value")) {
        $FullRegistryPath = "HKCU:\$Path"
        if (-not (Test-Path $FullRegistryPath)) {
            New-Item -Path $FullRegistryPath -Force | Out-Null
        }
        Set-ItemProperty -Path $FullRegistryPath -Name $Name -Value $Value -Type DWord -Force
    }
}

# 1. Enforce macro signing policy (common)
Set-UserRegDWord "software\policies\microsoft\office\16.0\common\security" "vbawarnings" 3
Write-Host "[+] Digital signing for Office macros enforced." -ForegroundColor Green

# 2. Block macros from the Internet for key Office applications
$Apps = @("excel", "word", "powerpoint", "access", "visio")
foreach ($App in $Apps) {
    Set-UserRegDWord "software\policies\microsoft\office\16.0\$App\security" "blockcontentexecutionfrominternet" 1
}
Write-Host "[+] VBA macro blocks from Internet applied to Office applications." -ForegroundColor Green

# 3. Disable OLE Package execution in Outlook (Policies and Preferences branches)
Set-UserRegDWord "software\policies\microsoft\office\16.0\outlook\security" "ShowOLEPackageObj" 0
Set-UserRegDWord "software\microsoft\office\16.0\outlook\security" "ShowOLEPackageObj" 0
Write-Host "[+] Outlook OLE Package execution blocked." -ForegroundColor Green
