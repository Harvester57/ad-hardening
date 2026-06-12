# Audit-MachineAccountQuota.ps1
# Description: Audits the domain-wide machine account quota attribute and local Add workstations to domain user right assignment.

Import-Module ActiveDirectory

Write-Host "--- Auditing Machine Account Quota Settings ---" -ForegroundColor Cyan

# 1. Audit domain-wide ms-DS-MachineAccountQuota
try {
    $Domain = Get-ADDomain -ErrorAction Stop
    $Quota = $Domain.MachineAccountQuota

    if ($Quota -ne 0) {
        Write-Host "VULNERABLE: Domain-wide ms-DS-MachineAccountQuota is set to $($Quota) (should be 0)." -ForegroundColor Red
    } else {
        Write-Host "Status: Compliant. Domain-wide ms-DS-MachineAccountQuota is set to 0." -ForegroundColor Green
    }
} catch {
    Write-Host "VULNERABLE: Could not audit ms-DS-MachineAccountQuota. Error: $($_.Exception.Message)" -ForegroundColor Red
}

# 2. Audit local User Rights Assignment for SeMachineAccountPrivilege
try {
    $SecCfg = "$($env:temp)\auditpolicy.inf"
    secedit /export /cfg $SecCfg /quiet

    if (Test-Path $SecCfg) {
        $cfgContent = Get-Content -Path $SecCfg
        $privilege = $cfgContent | Where-Object { $_ -like "SeMachineAccountPrivilege*" }

        if ($privilege) {
            $parts = $privilege -split "="
            if ($parts.Count -eq 2) {
                $value = $parts[1].Trim()
                if ($value -eq "*S-1-5-32-544") {
                    Write-Host "Status: Compliant. SeMachineAccountPrivilege is restricted to Administrators." -ForegroundColor Green
                } elseif ($value -eq "") {
                    Write-Host "Status: Compliant. SeMachineAccountPrivilege is empty (no one has the privilege)." -ForegroundColor Green
                } else {
                    Write-Host "VULNERABLE: SeMachineAccountPrivilege is assigned to: $($value) (should be restricted to Administrators or empty)." -ForegroundColor Red
                }
            } else {
                Write-Host "VULNERABLE: Could not parse SeMachineAccountPrivilege line: $($privilege)" -ForegroundColor Red
            }
        } else {
            Write-Host "VULNERABLE: SeMachineAccountPrivilege line not defined in exported local policy (defaults to Authenticated Users)." -ForegroundColor Red
        }
        Remove-Item -Path $SecCfg -Force
    } else {
        Write-Host "VULNERABLE: Could not export local security policy database using secedit." -ForegroundColor Red
    }
} catch {
    Write-Host "VULNERABLE: Could not audit SeMachineAccountPrivilege. Error: $($_.Exception.Message)" -ForegroundColor Red
}
