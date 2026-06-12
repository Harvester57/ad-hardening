# Set-SiemLogShipping.ps1
# Secures Winlogbeat and Wazuh log shipping configuration file ACLs.

Write-Host "--- Hardening SIEM Shipping Agent Configurations ---" -ForegroundColor Cyan

$ConfigFiles = @(
    "C:\Program Files\Winlogbeat\winlogbeat.yml",
    "C:\Program Files (x86)\ossec-agent\ossec.conf"
)

foreach ($File in $ConfigFiles) {
    if (Test-Path $File) {
        Write-Host "[+] Applying hardened NTFS permissions to $($File)..." -ForegroundColor Gray
        
        # Get ACL
        $Acl = Get-Acl -Path $File
        # Disable inheritance and copy existing rules
        $Acl.SetAccessRuleProtection($true, $true)
        Set-Acl -Path $File -AclObject $Acl
        
        # Refresh ACL
        $Acl = Get-Acl -Path $File
        $Rules = $Acl.Access
        
        # Remove any access rules for Users, Authenticated Users, Everyone
        foreach ($Rule in $Rules) {
            $Identity = $Rule.IdentityReference.Value
            if ($Identity -like "*Users" -or $Identity -like "*Authenticated Users" -or $Identity -like "*Everyone") {
                $Acl.RemoveAccessRule($Rule) | Out-Null
            }
        }
        
        # Explicitly ensure Administrators and SYSTEM have Full Control
        $FullRights = [System.Security.AccessControl.FileSystemRights]::FullControl
        $InheritanceFlags = [System.Security.AccessControl.InheritanceFlags]::None
        $PropagationFlags = [System.Security.AccessControl.PropagationFlags]::None
        $AccessType = [System.Security.AccessControl.AccessControlType]::Allow
        
        $AdminRule = New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators", $FullRights, $InheritanceFlags, $PropagationFlags, $AccessType)
        $SystemRule = New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM", $FullRights, $InheritanceFlags, $PropagationFlags, $AccessType)
        
        $Acl.AddAccessRule($AdminRule)
        $Acl.AddAccessRule($SystemRule)
        
        Set-Acl -Path $File -AclObject $Acl
        Write-Host "    Permissions successfully secured for $($File)." -ForegroundColor Green
    } else {
        Write-Verbose "    File $($File) not found, skipping."
    }
}
