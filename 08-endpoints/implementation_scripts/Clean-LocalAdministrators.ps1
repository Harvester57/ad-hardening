# Clean-LocalAdministrators.ps1
# Removes unauthorized domain or local accounts from the local Administrators group and disables local account remote token filtering bypass.

Write-Host "--- Restricting Local Administrators Group ---" -ForegroundColor Cyan

# Define the list of authorized members
# The built-in Administrator account (RID 500) and authorized domain support groups.
$AuthorizedMembers = @("Administrator", "Workstation-Support-Admins")

$LocalAdmins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue

if ($LocalAdmins) {
    foreach ($Member in $LocalAdmins) {
        # Check if the member is not in the authorized list
        $Match = $false
        foreach ($Auth in $AuthorizedMembers) {
            # Check for exact matches or matches against SAM / SID formats
            if ($Member.Name -eq $Auth -or $Member.Name -like "*\$Auth" -or $Member.Name -eq "$env:COMPUTERNAME\$Auth") {
                $Match = $true
                break
            }
        }
        
        if (-not $Match) {
            Write-Host "[-] Removing unauthorized member: $($Member.Name) (Source: $($Member.PrincipalSource))" -ForegroundColor Yellow
            try {
                Remove-LocalGroupMember -Group "Administrators" -Member $Member.Name -ErrorAction Stop
                Write-Host "    Successfully removed: $($Member.Name)" -ForegroundColor Green
            } catch {
                Write-Error "    Failed to remove: $($Member.Name). Error: $($_.Exception.Message)"
            }
        } else {
            Write-Host "[+] Member authorized: $($Member.Name)" -ForegroundColor Green
        }
    }
} else {
    Write-Error "Could not retrieve members of local Administrators group."
}

# Enforce LocalAccountTokenFilterPolicy = 0
$RegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$ValueName = "LocalAccountTokenFilterPolicy"

try {
    if (-not (Test-Path $RegistryPath)) {
        New-Item -Path $RegistryPath -Force | Out-Null
    }
    Set-ItemProperty -Path $RegistryPath -Name $ValueName -Value 0 -Type DWord -Force | Out-Null
    Write-Host "[+] LocalAccountTokenFilterPolicy configured to 0." -ForegroundColor Green
} catch {
    Write-Error "Failed to configure LocalAccountTokenFilterPolicy. Error: $($_.Exception.Message)"
}
