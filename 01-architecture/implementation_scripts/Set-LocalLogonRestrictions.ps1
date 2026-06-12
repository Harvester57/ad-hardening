# Set-LocalLogonRestrictions.ps1
# Configures secedit User Rights Assignment to block domain administrative groups.

# 1. Define groups to block (Tier 0 admin groups)
$DenyGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins")

# 2. Translate group names to SID strings
$SIDs = foreach ($group in $DenyGroups) {
    try {
        $sid = (New-Object System.Security.Principal.NTAccount($group)).Translate([System.Security.Principal.SecurityIdentifier]).Value
        "*$sid"
    } catch {
        Write-Warning "Could not resolve SID for group: $group. Skipping."
    }
}

if ($SIDs.Count -eq 0) {
    Write-Error "No valid group SIDs resolved. Exiting."
    exit 1
}

# 3. Define the temporary paths for secedit config
$tempDir = [System.IO.Path]::GetTempPath()
$secConfigPath = Join-Path $tempDir "sec_config.inf"
$secDbPath = Join-Path $tempDir "sec_db.sdb"

# 4. Export current local security policy
secedit /export /cfg $secConfigPath /areas USER_RIGHTS /quiet

# 5. Modify exported config to inject our deny rules
$configContent = Get-Content -Path $secConfigPath
$NewContent = [System.Collections.Generic.List[string]]::new()
$InUserRights = $false

$PolicyEntries = @(
    "SeDenyInteractiveLogonRight",
    "SeDenyNetworkLogonRight",
    "SeDenyRemoteInteractiveLogonRight"
)

foreach ($line in $configContent) {
    if ($line -match '^\[Privilege Rights\]') {
        $InUserRights = $true
        $NewContent.Add($line)
        continue
    }
    if ($InUserRights -and $line -match '^\[') {
        $InUserRights = $false
    }
    
    # Filter out existing lines for the policies we configure
    $matched = $false
    foreach ($entry in $PolicyEntries) {
        if ($line -match "^$entry\s*=") {
            $matched = $true
            break
        }
    }
    
    if (-not $matched) {
        $NewContent.Add($line)
    }
}

# Insert new rules into [Privilege Rights] section
$InsertIndex = $NewContent.FindIndex({ $args[0] -match '^\[Privilege Rights\]' })
if ($InsertIndex -ge 0) {
    $Offset = 1
    $FormattedSIDs = $SIDs -join ","
    foreach ($policy in $PolicyEntries) {
        $NewContent.Insert($InsertIndex + $Offset, "$policy = $FormattedSIDs")
        $Offset++
    }
}

# Save new configuration
$NewContent | Out-File -FilePath $secConfigPath -Encoding utf16

# 6. Apply configuration using secedit
Write-Host "Applying User Rights Assignment restrictions via secedit..." -ForegroundColor Cyan
$process = Start-Process secedit -ArgumentList "/configure /db $secDbPath /cfg $secConfigPath /areas USER_RIGHTS /quiet" -Wait -NoNewWindow -PassThru

# Cleanup temporary database files
if (Test-Path $secConfigPath) { Remove-Item $secConfigPath -Force }
if (Test-Path $secDbPath) { Remove-Item $secDbPath -Force }

if ($process.ExitCode -eq 0) {
    Write-Host "Logon restrictions applied successfully." -ForegroundColor Green
} else {
    Write-Error "Failed to apply logon restrictions. Exit code: $($process.ExitCode)"
}
