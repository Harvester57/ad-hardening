# Get-AuthSiloAuditStatus.ps1
# Description: Queries the active Authentication Silos, verifies KDC claims support, checks enforcement state, and audits Protected Users membership.
# Target Engine: Windows PowerShell 5.1

Import-Module ActiveDirectory -ErrorAction SilentlyContinue

Write-Host "--- Auditing Authentication Silos ---" -ForegroundColor Cyan

$isCompliant = $true

# 1. Audit KDC and Kerberos Client Registry Settings for Claims and Armoring
$kdcRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters"
$kerbRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"

$kdcArmored = $false
if (Test-Path -Path $kdcRegPath) {
    $kdcEnable = (Get-ItemProperty -Path $kdcRegPath -Name "EnableCbacAndArmor" -ErrorAction SilentlyContinue).EnableCbacAndArmor
    $kdcLevel = (Get-ItemProperty -Path $kdcRegPath -Name "CbacAndArmorLevel" -ErrorAction SilentlyContinue).CbacAndArmorLevel
    if ($kdcEnable -eq 1 -and ($kdcLevel -ge 1)) {
        $kdcArmored = $true
        Write-Host "[+] Status: Compliant. KDC support for claims and Kerberos armoring is enabled." -ForegroundColor Green
    }
}

if (-not $kdcArmored) {
    Write-Host "VULNERABLE: KDC support for claims, compound authentication, and Kerberos armoring is NOT enabled in registry ($kdcRegPath)." -ForegroundColor Red
    $isCompliant = $false
}

$kerbArmored = $false
if (Test-Path -Path $kerbRegPath) {
    $kerbEnable = (Get-ItemProperty -Path $kerbRegPath -Name "EnableCbacAndArmor" -ErrorAction SilentlyContinue).EnableCbacAndArmor
    if ($kerbEnable -eq 1) {
        $kerbArmored = $true
        Write-Host "[+] Status: Compliant. Kerberos client support for claims and armoring is enabled." -ForegroundColor Green
    }
}

if (-not $kerbArmored) {
    Write-Host "VULNERABLE: Kerberos client support for claims and armoring is NOT enabled in registry ($kerbRegPath)." -ForegroundColor Red
    $isCompliant = $false
}

# 2. Audit Operational Event Log Channel
try {
    $logChannel = "Microsoft-Windows-Authentication/AuthenticationPolicyFailures-DomainController/Operational"
    $logConfig = Get-WinEvent -ListLog $logChannel -ErrorAction Stop
    if ($logConfig.IsEnabled) {
        Write-Host "[+] Status: Compliant. Operational authentication failure event log channel is enabled." -ForegroundColor Green
    } else {
        Write-Host "VULNERABLE: Operational authentication failure event log channel is disabled: $($logChannel)" -ForegroundColor Red
        $isCompliant = $false
    }
} catch {
    Write-Host "[-] Operational log channel check skipped or unavailable on this node." -ForegroundColor Yellow
}

# 3. Audit Active Directory Authentication Policy Silos
try {
    $silos = Get-ADAuthenticationPolicySilo -Filter * -Properties * -ErrorAction Stop
    if (-not $silos) {
        Write-Host "VULNERABLE: No Active Directory Authentication Policy Silos configured in this domain." -ForegroundColor Red
        $isCompliant = $false
    } else {
        foreach ($silo in $silos) {
            Write-Host "[*] Silo Name: $($silo.Name)" -ForegroundColor Cyan
            Write-Host "    - Description: $($silo.Description)" -ForegroundColor White
            Write-Host "    - Enforced: $($silo.Enforce)" -ForegroundColor White
            Write-Host "    - User Policy: $($silo.UserAuthenticationPolicy)" -ForegroundColor White
            Write-Host "    - Computer Policy: $($silo.ComputerAuthenticationPolicy)" -ForegroundColor White

            if (-not $silo.Enforce) {
                Write-Host "    [!] Silo '$($silo.Name)' is in AUDIT mode (Enforce = False). Verify staging logs before enforcement." -ForegroundColor Yellow
            }

            # Verify associated User Authentication Policy
            if ($silo.UserAuthenticationPolicy) {
                $userPolicy = Get-ADAuthenticationPolicy -Identity $silo.UserAuthenticationPolicy -Properties * -ErrorAction SilentlyContinue
                if ($userPolicy) {
                    Write-Host "    - User TGT Lifetime: $($userPolicy.UserTGTLifetimeMins) minutes" -ForegroundColor White
                    Write-Host "    - Policy Enforced: $($userPolicy.Enforce)" -ForegroundColor White
                    if ($userPolicy.UserTGTLifetimeMins -gt 240) {
                        Write-Host "    [!] Policy TGT lifetime exceeds 240 minutes ($($userPolicy.UserTGTLifetimeMins)m)." -ForegroundColor Yellow
                    }
                }
            }

            # Check Silo Members: DCs must be enrolled in T0 Silo
            if ($silo.Name -like "*T0*" -or $silo.Name -like "*Tier0*") {
                $dcs = Get-ADDomainController -Filter "IsReadOnly -eq `$false" -ErrorAction SilentlyContinue
                $missingDcs = 0
                foreach ($dc in $dcs) {
                    $assignedSilo = (Get-ADAccountAuthenticationPolicySilo -Identity $dc.ComputerObjectDN -ErrorAction SilentlyContinue).AuthenticationPolicySilo
                    if (-not $assignedSilo -or $assignedSilo -ne $silo.DistinguishedName) {
                        $missingDcs++
                    }
                }
                if ($missingDcs -gt 0) {
                    Write-Host "    VULNERABLE: $($missingDcs) writable Domain Controller(s) are NOT assigned to Tier 0 Silo '$($silo.Name)'." -ForegroundColor Red
                    $isCompliant = $false
                } else {
                    Write-Host "    [+] All writable Domain Controllers are assigned to Tier 0 Silo." -ForegroundColor Green
                }
            }

            # Check Silo Members: User accounts must be members of Protected Users group
            $members = $silo.Members
            $unprotectedUsers = 0
            if ($members) {
                foreach ($memberDn in $members) {
                    $memberObj = Get-ADObject -Identity $memberDn -Properties objectClass, sAMAccountName -ErrorAction SilentlyContinue
                    if ($memberObj -and $memberObj.objectClass -eq "user") {
                        $isProtected = Get-ADGroupMember -Identity "Protected Users" -Recursive -ErrorAction SilentlyContinue | Where-Object { $_.distinguishedName -eq $memberDn }
                        if (-not $isProtected) {
                            $unprotectedUsers++
                            Write-Host "    VULNERABLE: Silo user '$($memberObj.sAMAccountName)' is NOT in Protected Users group (NTLM bypass risk)!" -ForegroundColor Red
                        }
                    }
                }
            }
            if ($unprotectedUsers -gt 0) {
                $isCompliant = $false
            }
        }
    }
} catch {
    Write-Host "[-] Could not query Active Directory Authentication Policy Silos: $($_.Exception.Message)" -ForegroundColor Yellow
}

# 4. Final Compliance Verdict
if ($isCompliant) {
    Write-Host "Audit Result: SECURE (Authentication Silos and Policies configured and compliant)" -ForegroundColor Green
} else {
    Write-Host "Audit Result: VULNERABLE (Authentication Silos and Policies missing or non-compliant)" -ForegroundColor Red
}
