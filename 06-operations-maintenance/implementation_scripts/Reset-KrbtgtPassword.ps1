# Reset-KrbtgtPassword.ps1
# Description: Resets the KRBTGT account password on the PDC Emulator with a cryptographically secure 128-character password, enforces cooldown safety, and triggers AD replication.
# Target Engine: Windows PowerShell 5.1

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "High")]
param (
    [Parameter(Mandatory = $false)]
    [switch]$Force,

    [Parameter(Mandatory = $false)]
    [int]$MinCooldownHours = 10,

    [Parameter(Mandatory = $false)]
    [string]$Server
)

Write-Host "--- Applying Hardening Requirement: KRBTGT Password Rotation ---" -ForegroundColor Cyan

# 1. Verify Active Directory module
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "The ActiveDirectory PowerShell module is required to execute this script."
    return
}

Import-Module ActiveDirectory -ErrorAction Stop

# 2. Discover target Domain Controller (PDC Emulator)
try {
    $domain = Get-ADDomain -ErrorAction Stop
    $targetServer = $Server
    if (-not $targetServer) {
        $targetServer = $domain.PDCEmulator
    }
    Write-Host "[*] Target Domain: $($domain.DNSRoot)" -ForegroundColor Gray
    Write-Host "[*] Authoritative PDC Emulator: $targetServer" -ForegroundColor Gray
} catch {
    Write-Error "Failed to locate domain or PDC Emulator: $($_.Exception.Message)"
    return
}

# 3. Retrieve authoritative KRBTGT object
try {
    $krbtgt = Get-ADUser -Identity "krbtgt" -Server $targetServer -Properties PasswordLastSet, Enabled, "msDS-KeyVersionNumber", userAccountControl -ErrorAction Stop
    if (-not $krbtgt) {
        Write-Error "KRBTGT account not found on $targetServer."
        return
    }
} catch {
    Write-Error "Failed to retrieve KRBTGT account from $($targetServer): $($_.Exception.Message)"
    return
}

$lastSet = $krbtgt.PasswordLastSet
$currentKvno = $krbtgt."msDS-KeyVersionNumber"

Write-Host "[*] Current KRBTGT Password Last Set: $lastSet" -ForegroundColor Gray
Write-Host "[*] Current Key Version Number (kvno): $currentKvno" -ForegroundColor Gray

# 4. Enforce Cooldown Safety Check
if ($null -ne $lastSet) {
    $elapsedHours = (New-TimeSpan -Start $lastSet -End (Get-Date)).TotalHours
    if ($elapsedHours -lt $MinCooldownHours -and -not $Force) {
        $roundedHours = [math]::Round($elapsedHours, 1)
        Write-Warning "SAFETY INTERLOCK ENGAGED: The KRBTGT password was last set only $roundedHours hours ago."
        Write-Warning "Resetting KRBTGT again before the Kerberos ticket lifetime ($MinCooldownHours hours) has elapsed"
        Write-Warning "will purge the previous key from history and invalidate ALL active domain TGTs,"
        Write-Warning "causing enterprise-wide authentication failure for all users and services."
        Write-Warning "To override this interlock (e.g., during active incident containment), specify -Force."
        return
    }
}

# 5. Generate Cryptographically Secure 128-Character Password
$length = 128
$chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?"
$rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
$bytes = New-Object byte[] $length
$rng.GetBytes($bytes)

$securePassword = New-Object System.Security.SecureString
for ($i = 0; $i -lt $length; $i++) {
    $char = $chars[$bytes[$i] % $chars.Length]
    $securePassword.AppendChar($char)
}
$securePassword.MakeReadOnly()
$rng.Dispose()

# 6. Execute Password Reset via ShouldProcess
$confirmTarget = "KRBTGT account on $targetServer (Domain: $($domain.DNSRoot))"
if ($PSCmdlet.ShouldProcess($confirmTarget, "Reset KRBTGT account password and increment kvno")) {
    try {
        Set-ADAccountPassword -Identity $krbtgt -Server $targetServer -NewPassword $securePassword -Reset -ErrorAction Stop
        Write-Host "[+] KRBTGT password successfully reset on PDC Emulator ($targetServer)." -ForegroundColor Green

        # Re-query to verify kvno increment
        Start-Sleep -Seconds 2
        $updatedKrbtgt = Get-ADUser -Identity "krbtgt" -Server $targetServer -Properties PasswordLastSet, "msDS-KeyVersionNumber" -ErrorAction Stop
        Write-Host "[+] New Password Last Set: $($updatedKrbtgt.PasswordLastSet)" -ForegroundColor Green
        Write-Host "[+] New Key Version Number (kvno): $($updatedKrbtgt.'msDS-KeyVersionNumber')" -ForegroundColor Green

        # 7. Dispatch Active Directory Replication
        Write-Host "[*] Triggering Active Directory replication synchronization..." -ForegroundColor Cyan
        $repadmin = Get-Command -Name "repadmin.exe" -ErrorAction SilentlyContinue
        if ($repadmin) {
            & repadmin.exe /syncall /AdeP | Out-Null
            Write-Host "[+] Active Directory replication triggered across all domain partitions." -ForegroundColor Green
        } else {
            try {
                Sync-ADObject -Identity $krbtgt.DistinguishedName -Server $targetServer -ErrorAction SilentlyContinue
                Write-Host "[+] Sync-ADObject invoked for KRBTGT account." -ForegroundColor Green
            } catch {
                Write-Warning "Could not trigger replication automatically. Ensure replication runs across all domain controllers."
            }
        }

        Write-Host ""
        Write-Host "=========================================================================" -ForegroundColor Yellow
        Write-Host "[IMPORTANT] Two-Step KRBTGT Password Rotation Protocol:" -ForegroundColor Yellow
        Write-Host " 1. This reset constitutes Step 1 of the rotation cycle." -ForegroundColor Yellow
        Write-Host " 2. Active Directory retains the previous key in history (index 1) so" -ForegroundColor Yellow
        Write-Host "    existing valid Kerberos tickets continue to function until expiration." -ForegroundColor Yellow
        Write-Host " 3. You MUST WAIT at least $MinCooldownHours to 24 hours for all active tickets" -ForegroundColor Yellow
        Write-Host "    to renew and for replication to converge across all domain controllers." -ForegroundColor Yellow
        Write-Host " 4. After the cooldown period, run this script again to perform Step 2," -ForegroundColor Yellow
        Write-Host "    which purges the pre-rotation key and completely invalidates any" -ForegroundColor Yellow
        Write-Host "    historical Golden, Diamond, or forged Kerberos tickets." -ForegroundColor Yellow
        Write-Host "=========================================================================" -ForegroundColor Yellow
    } catch {
        Write-Error "Failed to reset KRBTGT password: $($_.Exception.Message)"
    }
}
