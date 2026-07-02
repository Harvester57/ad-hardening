# Get-SYSVOLHoneypotStatus.ps1
# Description: Checks the configuration status of the SYSVOL Decoy XML Honeypot.
# Target Engine: Windows PowerShell 5.1

Write-Host "--- Auditing SYSVOL Decoy XML Honeypot Configuration ---" -ForegroundColor Cyan
$script:Vulnerable = $false

$RegPath = "HKLM:\SOFTWARE\ADHardening\SYSVOLHoneypot"

if (Test-Path $RegPath) {
    $DecoyGuid = (Get-ItemProperty -Path $RegPath -Name "DecoyGuid" -ErrorAction SilentlyContinue).DecoyGuid
    $DecoyPath = (Get-ItemProperty -Path $RegPath -Name "DecoyPath" -ErrorAction SilentlyContinue).DecoyPath
    
    if (-not $DecoyGuid) {
        Write-Host "[-] Decoy GPO GUID is missing in the registry." -ForegroundColor Red
        $script:Vulnerable = $true
    }
    
    if (-not $DecoyPath) {
        Write-Host "[-] Decoy file path is missing in the registry." -ForegroundColor Red
        $script:Vulnerable = $true
    } else {
        if (-not (Test-Path $DecoyPath)) {
            Write-Host "[-] Decoy XML file does not exist at registered path: $DecoyPath" -ForegroundColor Red
            $script:Vulnerable = $true
        } else {
            Write-Host "[+] Decoy XML file found: $DecoyPath" -ForegroundColor Green
            
            # Check Deny ACL rule
            $Acl = Get-Acl -Path $DecoyPath
            $HasDenyRule = $false
            foreach ($rule in $Acl.GetAccessRules($true, $false, [System.Security.Principal.NTAccount])) {
                if ($rule.IdentityReference.Value -eq "Everyone" -and $rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Deny) {
                    $HasDenyRule = $true
                    break
                }
            }
            
            if ($HasDenyRule) {
                Write-Host "    - Everyone Deny Read rule: CONFIGURED" -ForegroundColor White
            } else {
                Write-Host "    - Everyone Deny Read rule: NOT CONFIGURED" -ForegroundColor Red
                $script:Vulnerable = $true
            }
            
            # Check Audit failure rule (SACL)
            $AclAudit = Get-Acl -Path $DecoyPath -Audit
            $HasAuditRule = $false
            foreach ($rule in $AclAudit.GetAuditRules($true, $false, [System.Security.Principal.NTAccount])) {
                if ($rule.IdentityReference.Value -eq "Everyone" -and $rule.AuditFlags -eq [System.Security.AccessControl.AuditFlags]::Failure) {
                    $HasAuditRule = $true
                    break
                }
            }
            
            if ($HasAuditRule) {
                Write-Host "    - Everyone Failure Audit rule: CONFIGURED" -ForegroundColor White
            } else {
                Write-Host "    - Everyone Failure Audit rule: NOT CONFIGURED" -ForegroundColor Red
                $script:Vulnerable = $true
            }
        }
    }
} else {
    Write-Host "[-] Decoy registry key not found under HKLM:\SOFTWARE\ADHardening\SYSVOLHoneypot" -ForegroundColor Red
    $script:Vulnerable = $true
}

if ($script:Vulnerable) {
    Write-Host "Audit Result: VULNERABLE" -ForegroundColor Red
    exit 1
} else {
    Write-Host "Audit Result: SECURE" -ForegroundColor Green
    exit 0
}
