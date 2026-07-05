# Get-PawAuditAppinitdllsStatus.ps1
$script:Vulnerable = $false

# Audit Registry value: LoadAppInit_DLLs
$RegVal = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows" -Name "LoadAppInit_DLLs" -ErrorAction SilentlyContinue
if (-not $RegVal -or $RegVal.LoadAppInit_DLLs -ne 0) {
    $script:Vulnerable = $true
}

if ($script:Vulnerable) {
    Write-Output "Non-Compliant"
    exit 1
} else {
    Write-Output "Compliant"
    exit 0
}
