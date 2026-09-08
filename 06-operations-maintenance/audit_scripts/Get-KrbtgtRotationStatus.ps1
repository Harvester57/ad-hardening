# Get-KrbtgtRotationStatus.ps1
# Description: Audits KRBTGT password age, kvno, replication convergence across all Domain Controllers, and RODC accounts.
# Target Engine: Windows PowerShell 5.1

Import-Module ActiveDirectory -ErrorAction Stop

Write-Host "--- Auditing KRBTGT Password Rotation Status ---" -ForegroundColor Cyan

# 1. Discover Domain and Authoritative PDC Emulator
try {
    $domain = Get-ADDomain -ErrorAction Stop
    $pdc = $domain.PDCEmulator
    Write-Host "[*] Domain: $($domain.DNSRoot)" -ForegroundColor Gray
    Write-Host "[*] Authoritative PDC Emulator: $pdc" -ForegroundColor Gray
} catch {
    Write-Error "Failed to query domain or PDC Emulator: $($_.Exception.Message)"
    return
}

# 2. Retrieve Kerberos Policy MaxTicketAge
$maxTicketAgeHours = 10
try {
    $kerbPolicy = Get-ADDefaultDomainPasswordPolicy -ErrorAction SilentlyContinue
    if ($kerbPolicy -and $kerbPolicy.MaxTicketAge) {
        $maxTicketAgeHours = [math]::Round($kerbPolicy.MaxTicketAge.TotalHours, 1)
    }
} catch {
    $maxTicketAgeHours = 10
}
Write-Host "[*] Configured Kerberos MaxTicketAge: $maxTicketAgeHours hours" -ForegroundColor Gray

# 3. Query Primary KRBTGT Object on PDC
$krbtgt = Get-ADUser -Identity "krbtgt" -Server $pdc -Properties PasswordLastSet, PasswordExpired, Enabled, "msDS-KeyVersionNumber", "msDS-SupportedEncryptionTypes" -ErrorAction SilentlyContinue

if (-not $krbtgt) {
    Write-Error "KRBTGT account not found in Active Directory."
    return
}

$passwordLastSet = $krbtgt.PasswordLastSet
$kvno = $krbtgt."msDS-KeyVersionNumber"
$encTypes = $krbtgt."msDS-SupportedEncryptionTypes"

Write-Host "    - Account Name: $($krbtgt.Name)" -ForegroundColor White
Write-Host "    - Enabled: $($krbtgt.Enabled)" -ForegroundColor White
Write-Host "    - Key Version Number (kvno): $kvno" -ForegroundColor White
Write-Host "    - Supported Encryption Types Bitmask: $encTypes" -ForegroundColor White

if ($null -ne $passwordLastSet) {
    $ageDays = (New-TimeSpan -Start $passwordLastSet -End (Get-Date)).Days
    $ageHours = (New-TimeSpan -Start $passwordLastSet -End (Get-Date)).TotalHours
    $stigThresholdDays = 180
    $anssiThresholdDays = 90

    Write-Host "    - Password Last Set: $passwordLastSet ($ageDays days ago / $([math]::Round($ageHours, 1)) hours ago)" -ForegroundColor White

    # Check if currently inside the two-step cooldown window
    if ($ageHours -lt $maxTicketAgeHours) {
        Write-Host "    - Cooldown Status: IN-PROGRESS (Step 1 executed $([math]::Round($ageHours, 1)) hours ago; wait until $maxTicketAgeHours hours have elapsed before executing Step 2)." -ForegroundColor Yellow
    }

    # Evaluate compliance thresholds
    if ($ageDays -gt $stigThresholdDays) {
        Write-Host "    - Compliance Status: FAILED - KRBTGT password has not been rotated in $ageDays days (DoD STIG threshold: $stigThresholdDays days)." -ForegroundColor Red
    } elseif ($ageDays -gt $anssiThresholdDays) {
        Write-Host "    - Compliance Status: WARNING - KRBTGT password age is $ageDays days (Exceeds ANSSI recommendation of $anssiThresholdDays days; compliant with STIG threshold of $stigThresholdDays days)." -ForegroundColor Yellow
    } else {
        Write-Host "    - Compliance Status: PASSED - KRBTGT password age is $ageDays days (Compliant with STIG and ANSSI baselines)." -ForegroundColor Green
    }
} else {
    Write-Host "    - Compliance Status: FAILED - PasswordLastSet attribute is null." -ForegroundColor Red
}

# 4. Audit Replication Consistency Across All Reachable DCs
Write-Host "`n[*] Auditing KRBTGT Replication Convergence Across Domain Controllers:" -ForegroundColor Cyan
$dcs = Get-ADDomainController -Filter * -ErrorAction SilentlyContinue
$dcResults = @()
$replicationDiscrepancy = $false

foreach ($dc in $dcs) {
    try {
        $dcKrbtgt = Get-ADUser -Identity "krbtgt" -Server $dc.HostName -Properties PasswordLastSet, "msDS-KeyVersionNumber" -ErrorAction Stop
        $match = ($dcKrbtgt.PasswordLastSet -eq $passwordLastSet) -and ($dcKrbtgt."msDS-KeyVersionNumber" -eq $kvno)
        if (-not $match) {
            $replicationDiscrepancy = $true
        }
        $dcResults += [PSCustomObject]@{
            DomainController = $dc.HostName
            Reachable        = $true
            PasswordLastSet  = $dcKrbtgt.PasswordLastSet
            Kvno             = $dcKrbtgt."msDS-KeyVersionNumber"
            InSync           = $match
        }
    } catch {
        $dcResults += [PSCustomObject]@{
            DomainController = $dc.HostName
            Reachable        = $false
            PasswordLastSet  = $null
            Kvno             = $null
            InSync           = $false
        }
    }
}

foreach ($res in $dcResults) {
    if ($res.Reachable -and $res.InSync) {
        Write-Host "    [OK] $($res.DomainController): kvno=$($res.Kvno), LastSet=$($res.PasswordLastSet)" -ForegroundColor Green
    } elseif ($res.Reachable -and -not $res.InSync) {
        Write-Host "    [MISMATCH] $($res.DomainController): kvno=$($res.Kvno), LastSet=$($res.PasswordLastSet) (Out of sync with PDC)" -ForegroundColor Red
    } else {
        Write-Host "    [UNREACHABLE] $($res.DomainController): Unable to query" -ForegroundColor Yellow
    }
}

if ($replicationDiscrepancy) {
    Write-Host "    [!] Warning: Replication discrepancy detected across Domain Controllers." -ForegroundColor Red
}

# 5. Audit Read-Only Domain Controller (RODC) KRBTGT Accounts
Write-Host "`n[*] Auditing Read-Only Domain Controller (RODC) KRBTGT Accounts:" -ForegroundColor Cyan
$rodcAccounts = Get-ADUser -Filter "Name -like 'krbtgt_*'" -Server $pdc -Properties PasswordLastSet, "msDS-KeyVersionNumber", Enabled -ErrorAction SilentlyContinue

if ($rodcAccounts -and $rodcAccounts.Count -gt 0) {
    Write-Host "    Found $($rodcAccounts.Count) RODC KRBTGT account(s):" -ForegroundColor Gray
    foreach ($rodc in $rodcAccounts) {
        $rodcAgeDays = "N/A"
        if ($rodc.PasswordLastSet) {
            $rodcAgeDays = (New-TimeSpan -Start $rodc.PasswordLastSet -End (Get-Date)).Days
        }
        Write-Host "    - $($rodc.SamAccountName): kvno=$($rodc.'msDS-KeyVersionNumber'), LastSet=$($rodc.PasswordLastSet) ($rodcAgeDays days ago), Enabled=$($rodc.Enabled)" -ForegroundColor White
    }
} else {
    Write-Host "    No Read-Only Domain Controller (RODC) accounts detected in this domain." -ForegroundColor Gray
}
