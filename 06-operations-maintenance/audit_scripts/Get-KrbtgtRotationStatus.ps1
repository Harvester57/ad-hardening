# Get-KrbtgtRotationStatus.ps1
# Description: Audits the password age of the krbtgt account.

Import-Module ActiveDirectory

Write-Host "--- Auditing KRBTGT Password Rotation Status ---" -ForegroundColor Cyan

$Krbtgt = Get-ADUser -Filter "Name -eq 'krbtgt'" -Properties PasswordLastSet, PasswordExpired, Enabled

if ($Krbtgt) {
    $PasswordLastSet = $Krbtgt.PasswordLastSet
    if ($null -ne $PasswordLastSet) {
        $AgeDays = (New-TimeSpan -Start $PasswordLastSet -End (Get-Date)).Days
        $MaxAgeDays = 180 # STIG requirement threshold
        
        Write-Host "    - Account Name: $($Krbtgt.Name)" -ForegroundColor White
        Write-Host "    - Enabled: $($Krbtgt.Enabled)" -ForegroundColor White
        Write-Host "    - Password Last Set: $PasswordLastSet ($AgeDays days ago)" -ForegroundColor White
        
        if ($AgeDays -gt $MaxAgeDays) {
            Write-Host "    - Status: WARNING - KRBTGT password has not been rotated in $AgeDays days (Threshold: $MaxAgeDays days)." -ForegroundColor Red
        } else {
            Write-Host "    - Status: OK - KRBTGT password was rotated recently ($AgeDays days ago)." -ForegroundColor Green
        }
    } else {
        Write-Host "    - Status: WARNING - PasswordLastSet is not set for the krbtgt account." -ForegroundColor Red
    }
} else {
    Write-Error "KRBTGT account not found in the Active Directory domain."
}
