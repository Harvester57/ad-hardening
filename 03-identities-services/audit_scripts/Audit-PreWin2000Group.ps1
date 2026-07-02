# Audit-PreWin2000Group.ps1
# Description: Audits the Pre-Windows 2000 Compatible Access group membership and local LSA registry configurations.

Import-Module ActiveDirectory

Write-Host "--- Auditing Pre-Windows 2000 Compatible Access Settings ---" -ForegroundColor Cyan

$GroupSid = "S-1-5-32-554"
$CriticalNonCompliantSids = @("S-1-1-0", "S-1-5-7") # Everyone, Anonymous Logon
$RestrictedNonCompliantSids = @("S-1-5-11")          # Authenticated Users (default in modern systems, high legacy impact if removed)
$Vulnerable = $false
$HasWarning = $false

# 1. Audit Group Membership
try {
    $Group = Get-ADGroup -Identity $GroupSid -Properties Members -ErrorAction Stop
    $MembersSids = New-Object System.Collections.Generic.List[string]

    foreach ($MemberDN in $Group.Members) {
        $MemberObj = Get-ADObject -Identity $MemberDN -ErrorAction SilentlyContinue
        if ($null -ne $MemberObj) {
            $MembersSids.Add($MemberObj.SID.Value) | Out-Null
        }
    }

    # Check for Critical SIDs (Everyone, Anonymous Logon)
    foreach ($Sid in $CriticalNonCompliantSids) {
        if ($MembersSids.Contains($Sid)) {
            $Vulnerable = $true
            $Name = ""
            if ($Sid -eq "S-1-1-0") { $Name = "Everyone" }
            elseif ($Sid -eq "S-1-5-7") { $Name = "Anonymous Logon" }

            Write-Host "VULNERABLE: '$($Name)' ($($Sid)) is a member of the Pre-Windows 2000 Compatible Access group." -ForegroundColor Red
        }
    }

    # Check for Authenticated Users (High legacy impact warning)
    foreach ($Sid in $RestrictedNonCompliantSids) {
        if ($MembersSids.Contains($Sid)) {
            $HasWarning = $true
            Write-Host "WARNING: 'Authenticated Users' ($($Sid)) is a member of the Pre-Windows 2000 Compatible Access group. (This is default in modern systems; remove with caution)." -ForegroundColor Yellow
        }
    }

    if (-not $Vulnerable -and -not $HasWarning) {
        Write-Host "Status: Compliant. Pre-Windows 2000 Compatible Access group membership is restricted." -ForegroundColor Green
    } elseif (-not $Vulnerable) {
        Write-Host "Status: Compliant (with warnings). Critical groups are removed, but legacy/default Authenticated Users remains." -ForegroundColor Green
    }
} catch {
    Write-Host "VULNERABLE: Could not query Pre-Windows 2000 Compatible Access group membership. Error: $($_.Exception.Message)" -ForegroundColor Red
}

# 2. Audit LSA Registry Security Settings
$LsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"

$Settings = @{
    "EveryoneIncludesAnonymous" = 0
    "RestrictAnonymous"         = 1
    "RestrictAnonymousSAM"      = 1
}

foreach ($Key in $Settings.Keys) {
    try {
        if (Test-Path $LsaPath) {
            $Value = Get-ItemPropertyValue -Path $LsaPath -Name $Key -ErrorAction Stop
            $TargetValue = $Settings[$Key]
            
            if ($Value -ne $TargetValue) {
                Write-Host "VULNERABLE: LSA Registry Key '$($Key)' is set to $($Value) (should be $($TargetValue))." -ForegroundColor Red
            } else {
                Write-Host "Status: Compliant. LSA Registry Key '$($Key)' is set to $($TargetValue)." -ForegroundColor Green
            }
        } else {
            Write-Host "VULNERABLE: LSA registry path does not exist." -ForegroundColor Red
        }
    } catch {
        Write-Host "VULNERABLE: Could not audit LSA key '$($Key)'. Error: $($_.Exception.Message)" -ForegroundColor Red
    }
}
