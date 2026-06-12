# Set-MachineAccountQuota.ps1
# Description: Sets the domain-wide machine account quota to 0 and restricts the local Add workstations to domain user right to Administrators.

Import-Module ActiveDirectory

Write-Host "Applying hardening requirement: Disable Machine Account Quota..." -ForegroundColor Cyan

# 1. Remediate domain-wide ms-DS-MachineAccountQuota
try {
    $Domain = Get-ADDomain -ErrorAction Stop
    if ($Domain.MachineAccountQuota -ne 0) {
        Set-ADDomain -Identity $Domain.DistinguishedName -Replace @{ "ms-DS-MachineAccountQuota" = 0 } -ErrorAction Stop
        Write-Host "[+] Domain-wide ms-DS-MachineAccountQuota successfully set to 0." -ForegroundColor Green
    } else {
        Write-Host "[-] Domain-wide ms-DS-MachineAccountQuota is already set to 0." -ForegroundColor Yellow
    }
} catch {
    Write-Error "Failed to set ms-DS-MachineAccountQuota. Error: $($_.Exception.Message)"
}

# 2. Remediate local User Rights Assignment (SeMachineAccountPrivilege)
try {
    $SecDb = "$($env:temp)\localpolicy.sdb"
    $SecCfg = "$($env:temp)\localpolicy.inf"
    
    # Export current security policy
    secedit /export /cfg $SecCfg /quiet
    
    if (Test-Path $SecCfg) {
        $cfgContent = Get-Content -Path $SecCfg
        $newCfg = New-Object System.Collections.Generic.List[string]
        $hasPrivilege = $false
        
        foreach ($line in $cfgContent) {
            if ($line -like "SeMachineAccountPrivilege*") {
                $line = "SeMachineAccountPrivilege = *S-1-5-32-544"
                $hasPrivilege = $true
            }
            $newCfg.Add($line) | Out-Null
        }
        
        if (-not $hasPrivilege) {
            # Add to [Privilege Rights] section
            $privIndex = $newCfg.IndexOf("[Privilege Rights]")
            if ($privIndex -ge 0) {
                $newCfg.Insert($privIndex + 1, "SeMachineAccountPrivilege = *S-1-5-32-544")
            } else {
                # Fallback: append section and value
                $newCfg.Add("[Privilege Rights]") | Out-Null
                $newCfg.Add("SeMachineAccountPrivilege = *S-1-5-32-544") | Out-Null
            }
        }
        
        # Save updated configuration
        $newCfg | Set-Content -Path $SecCfg
        
        # Configure local security policy
        secedit /configure /db $SecDb /cfg $SecCfg /areas USER_RIGHTS /quiet
        
        # Cleanup temporary files
        Remove-Item -Path $SecCfg -Force
        Remove-Item -Path $SecDb -Force
        
        Write-Host "[+] Local User Rights Assignment SeMachineAccountPrivilege successfully restricted to Administrators (*S-1-5-32-544)." -ForegroundColor Green
    } else {
        Write-Error "Failed to export local security policy for remediation."
    }
} catch {
    Write-Error "Failed to configure SeMachineAccountPrivilege. Error: $($_.Exception.Message)"
}
