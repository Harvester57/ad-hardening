# Test-LocalAdministrators.ps1
# Audits membership of the local Administrators group and checks local account remote token filtering bypass policy.

Write-Host "--- Auditing Local Administrators Group ---" -ForegroundColor Cyan

$LocalAdmins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue

if ($LocalAdmins) {
    Write-Host "[*] Current members of local Administrators group:" -ForegroundColor Yellow
    foreach ($Member in $LocalAdmins) {
        # Flag any domain user accounts that might have been added to administrators group
        $StatusColor = "Green"
        if ($Member.PrincipalSource -eq "ActiveDirectory" -and $Member.Name -notmatch "Workstation-Support-Admins") {
            $StatusColor = "Red"
            Write-Host "    - VULNERABLE: Domain Account '$($Member.Name)' has local admin rights." -ForegroundColor $StatusColor
        } else {
            Write-Host "    - Member: $($Member.Name) | Source: $($Member.PrincipalSource) | Class: $($Member.ObjectClass)" -ForegroundColor $StatusColor
        }
    }
} else {
    Write-Error "Failed to retrieve local Administrators group members."
}

# Audit LocalAccountTokenFilterPolicy
$RegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$ValueName = "LocalAccountTokenFilterPolicy"

if (Test-Path $RegistryPath) {
    $Val = (Get-ItemProperty -Path $RegistryPath -Name $ValueName -ErrorAction SilentlyContinue).$ValueName
    if ($Val -eq 0) {
        Write-Host "[+] LocalAccountTokenFilterPolicy is configured correctly (0)." -ForegroundColor Green
    } elseif ($null -eq $Val) {
        Write-Host "[-] LocalAccountTokenFilterPolicy is not explicitly set (Expected: 0)." -ForegroundColor Red
    } else {
        Write-Host "[-] LocalAccountTokenFilterPolicy is vulnerable: $Val (Expected: 0)." -ForegroundColor Red
    }
} else {
    Write-Host "[-] LocalAccountTokenFilterPolicy is not configured (Expected: 0)." -ForegroundColor Red
}
