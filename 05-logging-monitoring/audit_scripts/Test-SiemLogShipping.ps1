# Test-SiemLogShipping.ps1
# Audits SIEM shipping agents, configuration permissions, and security.

Write-Host "--- Auditing SIEM Log Shipping Agents ---" -ForegroundColor Cyan

# 1. Audit Agent Services
$Services = @("winlogbeat", "WazuhSvc")
foreach ($SvcName in $Services) {
    $Svc = Get-Service -Name $SvcName -ErrorAction SilentlyContinue
    $Status = "Not Installed"
    if ($Svc) {
        $Status = $Svc.Status
    }
    $Color = if ($Status -eq "Running") { "Green" } else { "Yellow" }
    Write-Host "    - Agent Service '$($SvcName)': $($Status)" -ForegroundColor $Color
}

# 2. Audit Config File Access Permissions
$ConfigFiles = @(
    "C:\Program Files\Winlogbeat\winlogbeat.yml",
    "C:\Program Files (x86)\ossec-agent\ossec.conf"
)

foreach ($File in $ConfigFiles) {
    if (Test-Path $File) {
        $Acl = Get-Acl -Path $File
        $Rules = $Acl.Access
        $HasUnsafeAccess = $false
        
        foreach ($Rule in $Rules) {
            $Identity = $Rule.IdentityReference.Value
            $Type = $Rule.AccessControlType
            
            # Verify if users, authenticated users, or everyone has read/write
            if ($Type -eq "Allow" -and ($Identity -like "*Users" -or $Identity -like "*Authenticated Users" -or $Identity -like "*Everyone")) {
                $HasUnsafeAccess = $true
            }
        }
        
        $FileColor = if (-not $HasUnsafeAccess) { "Green" } else { "Red" }
        Write-Host "    - Configuration File: $($File) | UnsafeAccessAllowed=$($HasUnsafeAccess)" -ForegroundColor $FileColor
    } else {
        Write-Host "    - Configuration File: $($File) | Status: NOT FOUND" -ForegroundColor Yellow
    }
}
