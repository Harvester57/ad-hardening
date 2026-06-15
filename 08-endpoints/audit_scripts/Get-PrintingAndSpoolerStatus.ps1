# Get-PrintingAndSpoolerStatus.ps1
# Description: Audits print spooler and printer security configurations on the local system.

Write-Host "--- Auditing Printing and Spooler Hardening ---" -ForegroundColor Cyan

$script:Vulnerable = $false

# Helper function to audit registry properties
function Test-RegistryValue {
    param(
        [string]$Path,
        [string]$Name,
        [object]$ExpectedValue
    )
    if (Test-Path $Path) {
        $Val = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        if ($null -ne $Val) {
            $Actual = $Val.$Name
            if ($Actual -eq $ExpectedValue) {
                Write-Host "  - Path: $Path | Value: $Name | Current: $Actual (Expected: $ExpectedValue)" -ForegroundColor Green
            } else {
                Write-Host "  [!] MISMATCH: Path: $Path | Value: $Name | Current: $Actual (Expected: $ExpectedValue)" -ForegroundColor Red
                $script:Vulnerable = $true
            }
        } else {
            Write-Host "  [!] MISSING VALUE: Path: $Path | Value: $Name (Expected: $ExpectedValue)" -ForegroundColor Red
            $script:Vulnerable = $true
        }
    } else {
        Write-Host "  [!] MISSING KEY: Path: $Path (Expected: $Name = $ExpectedValue)" -ForegroundColor Red
        $script:Vulnerable = $true
    }
}

# Audit base printer settings
$PrintersPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"
Test-RegistryValue -Path $PrintersPath -Name "RegisterSpoolerRemoteRpcEndPoint" -ExpectedValue 2
Test-RegistryValue -Path $PrintersPath -Name "RegisterSpoolerRemoteSubsystem" -ExpectedValue 0
Test-RegistryValue -Path $PrintersPath -Name "RedirectionguardPolicy" -ExpectedValue 1
Test-RegistryValue -Path $PrintersPath -Name "CopyFilesPolicy" -ExpectedValue 1

# Audit RPC settings
$PrintersRpcPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC"
Test-RegistryValue -Path $PrintersRpcPath -Name "RpcUseNamedPipeProtocol" -ExpectedValue 0
Test-RegistryValue -Path $PrintersRpcPath -Name "RpcAuthentication" -ExpectedValue 0
Test-RegistryValue -Path $PrintersRpcPath -Name "RpcProtocols" -ExpectedValue 5
Test-RegistryValue -Path $PrintersRpcPath -Name "ForceKerberosForRpc" -ExpectedValue 0
Test-RegistryValue -Path $PrintersRpcPath -Name "RpcTcpPort" -ExpectedValue 0

# Audit Print Control
$PrintControlPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Print"
Test-RegistryValue -Path $PrintControlPath -Name "RpcAuthnLevelPrivacyEnabled" -ExpectedValue 1

# Audit Point and Print
$PointPrintPath = "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
Test-RegistryValue -Path $PointPrintPath -Name "RestrictPointAndPrint" -ExpectedValue 1
Test-RegistryValue -Path $PointPrintPath -Name "NoWarningNoElevationOnInstall" -ExpectedValue 0
Test-RegistryValue -Path $PointPrintPath -Name "UpdatePromptSettings" -ExpectedValue 0

if ($script:Vulnerable) {
    Write-Host "Audit Result: VULNERABLE" -ForegroundColor Red
    exit 1
} else {
    Write-Host "Audit Result: SECURE" -ForegroundColor Green
    exit 0
}
