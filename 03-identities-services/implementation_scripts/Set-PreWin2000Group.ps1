# Set-PreWin2000Group.ps1
# Description: Restricts Pre-Windows 2000 Compatible Access group membership and configures LSA registry security keys.

Import-Module ActiveDirectory

Write-Host "Applying hardening requirement: Restrict Pre-Windows 2000 Compatible Access..." -ForegroundColor Cyan

$GroupSid = "S-1-5-32-554"
$NonCompliantSids = @("S-1-1-0", "S-1-5-7", "S-1-5-11")

# 1. Remediate Group Membership
try {
    $Group = Get-ADGroup -Identity $GroupSid -Properties Members -ErrorAction Stop
    $MembersToRemove = New-Object System.Collections.Generic.List[string]

    foreach ($MemberDN in $Group.Members) {
        $MemberObj = Get-ADObject -Identity $MemberDN -ErrorAction SilentlyContinue
        if ($null -ne $MemberObj) {
            $Sid = $MemberObj.SID.Value
            if ($NonCompliantSids -contains $Sid) {
                $MembersToRemove.Add($MemberDN) | Out-Null
            }
        }
    }

    if ($MembersToRemove.Count -gt 0) {
        foreach ($MemberDN in $MembersToRemove) {
            try {
                Remove-ADGroupMember -Identity $GroupSid -Members $MemberDN -Confirm:$false -ErrorAction Stop
                Write-Host "[+] Successfully removed '$($MemberDN)' from the group." -ForegroundColor Green
            } catch {
                Write-Host "[-] Failed to remove '$($MemberDN)'. Error: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    } else {
        Write-Host "[-] No non-compliant members found in Pre-Windows 2000 Compatible Access group." -ForegroundColor Yellow
    }
} catch {
    Write-Error "Failed to remediate Pre-Windows 2000 Compatible Access group membership. Error: $($_.Exception.Message)"
}

# 2. Remediate LSA Registry Settings
$LsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"

$Settings = @{
    "EveryoneIncludesAnonymous" = 0
    "RestrictAnonymous"         = 1
    "RestrictAnonymousSAM"      = 1
}

foreach ($Key in $Settings.Keys) {
    try {
        if (-not (Test-Path $LsaPath)) {
            New-Item -Path $LsaPath -Force | Out-Null
        }
        
        $TargetValue = $Settings[$Key]
        Set-ItemProperty -Path $LsaPath -Name $Key -Value $TargetValue -Type DWord -ErrorAction Stop
        Write-Host "[+] Registry Key '$($Key)' successfully set to $($TargetValue)." -ForegroundColor Green
    } catch {
        Write-Error "Failed to apply LSA Registry Key '$($Key)'. Error: $($_.Exception.Message)"
    }
}
