# Get-WindowsFirewallStatus.ps1
# Description: Audits Windows Defender Firewall profile configurations and outbound block rules for known LOLBins.

Write-Host "--- Auditing Windows Defender Firewall Configuration ---" -ForegroundColor Cyan

$script:Vulnerable = $false

# Helper function to audit firewall profiles
function Test-FirewallProfile ($ProfileName, $ExpectMergeLocal, $ExpectMergeIPsec) {
    $FWProfile = Get-NetFirewallProfile -Profile $ProfileName -ErrorAction SilentlyContinue
    if ($null -eq $FWProfile) {
        Write-Host "    - Profile '$ProfileName' NOT FOUND" -ForegroundColor Red
        $script:Vulnerable = $true
        return
    }
    
    $EnabledColor = if ($FWProfile.Enabled -eq $true) { "Green" } else { "Red" }
    $InboundColor = if ($FWProfile.DefaultInboundAction -eq "Block") { "Green" } else { "Red" }
    $OutboundColor = if ($FWProfile.DefaultOutboundAction -eq "Allow") { "Green" } else { "Red" }
    $NotifyColor = if ($FWProfile.NotifyOnListen -eq $false) { "Green" } else { "Red" }
    
    Write-Host "  * Profile: $ProfileName" -ForegroundColor Gray
    Write-Host "    - Enabled: $($FWProfile.Enabled) (Expected: True)" -ForegroundColor $EnabledColor
    Write-Host "    - DefaultInboundAction: $($FWProfile.DefaultInboundAction) (Expected: Block)" -ForegroundColor $InboundColor
    Write-Host "    - DefaultOutboundAction: $($FWProfile.DefaultOutboundAction) (Expected: Allow)" -ForegroundColor $OutboundColor
    Write-Host "    - NotifyOnListen: $($FWProfile.NotifyOnListen) (Expected: False)" -ForegroundColor $NotifyColor
    
    # Check log configurations
    $LogPath = "$env:windir\System32\logfiles\firewall\$($ProfileName.ToLower())fw.log"
    $LogPathColor = if ($FWProfile.LogFileName -eq $LogPath) { "Green" } else { "Red" }
    $LogSizeColor = if ($FWProfile.LogMaxSizeKilobytes -ge 16384) { "Green" } else { "Red" }
    $LogBlockedColor = if ($FWProfile.LogBlocked -eq $true) { "Green" } else { "Red" }
    $LogAllowedColor = if ($FWProfile.LogAllowed -eq $false) { "Green" } else { "Red" }
    
    Write-Host "    - LogFileName: $($FWProfile.LogFileName) (Expected: $LogPath)" -ForegroundColor $LogPathColor
    Write-Host "    - LogMaxSizeKilobytes: $($FWProfile.LogMaxSizeKilobytes) (Expected: >= 16384)" -ForegroundColor $LogSizeColor
    Write-Host "    - LogBlocked: $($FWProfile.LogBlocked) (Expected: True)" -ForegroundColor $LogBlockedColor
    Write-Host "    - LogAllowed: $($FWProfile.LogAllowed) (Expected: False)" -ForegroundColor $LogAllowedColor
    
    if ($FWProfile.Enabled -ne $true -or $FWProfile.DefaultInboundAction -ne "Block" -or $FWProfile.NotifyOnListen -ne $false -or $FWProfile.LogFileName -ne $LogPath -or $FWProfile.LogMaxSizeKilobytes -lt 16384 -or $FWProfile.LogBlocked -ne $true -or $FWProfile.LogAllowed -ne $false) {
        $script:Vulnerable = $true
    }
    
    if ($null -ne $ExpectMergeLocal) {
        $MergeLocalColor = if ($FWProfile.AllowLocalPolicyMerge -eq $ExpectMergeLocal) { "Green" } else { "Red" }
        Write-Host "    - AllowLocalPolicyMerge: $($FWProfile.AllowLocalPolicyMerge) (Expected: $ExpectMergeLocal)" -ForegroundColor $MergeLocalColor
        if ($FWProfile.AllowLocalPolicyMerge -ne $ExpectMergeLocal) { $script:Vulnerable = $true }
    }
    if ($null -ne $ExpectMergeIPsec) {
        $MergeIPsecColor = if ($FWProfile.AllowLocalIPsecPolicyMerge -eq $ExpectMergeIPsec) { "Green" } else { "Red" }
        Write-Host "    - AllowLocalIPsecPolicyMerge: $($FWProfile.AllowLocalIPsecPolicyMerge) (Expected: $ExpectMergeIPsec)" -ForegroundColor $MergeIPsecColor
        if ($FWProfile.AllowLocalIPsecPolicyMerge -ne $ExpectMergeIPsec) { $script:Vulnerable = $true }
    }
}

Write-Host "Auditing profiles..." -ForegroundColor Gray
Test-FirewallProfile -ProfileName "Domain" -ExpectMergeLocal $false -ExpectMergeIPsec $false
Test-FirewallProfile -ProfileName "Private" -ExpectMergeLocal $false -ExpectMergeIPsec $false
Test-FirewallProfile -ProfileName "Public" -ExpectMergeLocal $false -ExpectMergeIPsec $false

# Audit outbound rules for known LOLBins
$Lolbins = @(
    @{ Name = "mshta.exe (x64)"; Path = "%SystemRoot%\System32\mshta.exe" },
    @{ Name = "mshta.exe (x86)"; Path = "%SystemRoot%\SysWOW64\mshta.exe" },
    @{ Name = "certutil.exe (x64)"; Path = "%SystemRoot%\System32\certutil.exe" },
    @{ Name = "certutil.exe (x86)"; Path = "%SystemRoot%\SysWOW64\certutil.exe" },
    @{ Name = "bitsadmin.exe (x64)"; Path = "%SystemRoot%\System32\bitsadmin.exe" },
    @{ Name = "bitsadmin.exe (x86)"; Path = "%SystemRoot%\SysWOW64\bitsadmin.exe" },
    @{ Name = "regsvr32.exe (x64)"; Path = "%SystemRoot%\System32\regsvr32.exe" },
    @{ Name = "regsvr32.exe (x86)"; Path = "%SystemRoot%\SysWOW64\regsvr32.exe" },
    @{ Name = "rundll32.exe (x64)"; Path = "%SystemRoot%\System32\rundll32.exe" },
    @{ Name = "rundll32.exe (x86)"; Path = "%SystemRoot%\SysWOW64\rundll32.exe" },
    @{ Name = "cscript.exe (x64)"; Path = "%SystemRoot%\System32\cscript.exe" },
    @{ Name = "cscript.exe (x86)"; Path = "%SystemRoot%\SysWOW64\cscript.exe" },
    @{ Name = "wscript.exe (x64)"; Path = "%SystemRoot%\System32\wscript.exe" },
    @{ Name = "wscript.exe (x86)"; Path = "%SystemRoot%\SysWOW64\wscript.exe" },
    @{ Name = "hh.exe (x64)"; Path = "%SystemRoot%\hh.exe" },
    @{ Name = "hh.exe (x86)"; Path = "%SystemRoot%\SysWOW64\hh.exe" },
    @{ Name = "calc.exe (x64)"; Path = "%SystemRoot%\System32\calc.exe" },
    @{ Name = "calc.exe (x86)"; Path = "%SystemRoot%\SysWOW64\calc.exe" },
    @{ Name = "notepad.exe (x64)"; Path = "%SystemRoot%\System32\notepad.exe" },
    @{ Name = "notepad.exe (x86)"; Path = "%SystemRoot%\SysWOW64\notepad.exe" },
    @{ Name = "conhost.exe (x64)"; Path = "%SystemRoot%\System32\conhost.exe" },
    @{ Name = "conhost.exe (x86)"; Path = "%SystemRoot%\SysWOW64\conhost.exe" },
    @{ Name = "RunScriptHelper.exe (x64)"; Path = "%SystemRoot%\System32\RunScriptHelper.exe" },
    @{ Name = "RunScriptHelper.exe (x86)"; Path = "%SystemRoot%\SysWOW64\RunScriptHelper.exe" }
)

Write-Host "Auditing outbound firewall rules for known LOLBins..." -ForegroundColor Gray

foreach ($Bin in $Lolbins) {
    $DisplayName = "Hardening: Block Outbound $($Bin.Name)"
    $Rule = Get-NetFirewallRule -DisplayName $DisplayName -ErrorAction SilentlyContinue
    $Color = "Red"
    
    if ($null -ne $Rule) {
        $ProgFilter = Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $Rule -ErrorAction SilentlyContinue
        $ProgPath = "None"
        if ($null -ne $ProgFilter) {
            $ProgPath = $ProgFilter.Program
        }
        
        if ($Rule.Enabled -eq $true -and $Rule.Direction -eq "Outbound" -and $Rule.Action -eq "Block" -and $ProgPath -eq $Bin.Path) {
            $Color = "Green"
            Write-Host "    - Firewall Rule: $DisplayName | Enabled: True | Action: Block | Program: $ProgPath (Compliant)" -ForegroundColor $Color
        } else {
            $script:Vulnerable = $true
            Write-Host "    - Firewall Rule: $DisplayName | Enabled: $($Rule.Enabled) | Action: $($Rule.Action) | Program: $ProgPath (Non-Compliant)" -ForegroundColor $Color
        }
    } else {
        $script:Vulnerable = $true
        Write-Host "    - Firewall Rule: $DisplayName | NOT FOUND (Non-Compliant)" -ForegroundColor $Color
    }
}

if ($script:Vulnerable) {
    Write-Host "Audit Result: VULNERABLE" -ForegroundColor Red
    exit 1
} else {
    Write-Host "Audit Result: SECURE" -ForegroundColor Green
    exit 0
}
