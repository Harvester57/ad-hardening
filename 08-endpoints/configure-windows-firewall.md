# [REQ-END-022] Configure Windows Defender Firewall and Block LOLBins

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers.
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional, Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Paths**:
    * `Computer Configuration\Policies\Windows Settings\Security Settings\Windows Defender Firewall with Advanced Security\Windows Defender Firewall with Advanced Security`
  * **Registry Locations**:
    * `HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile`
    * `HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile`
    * `HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile`
    * `HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules`

---

## Rationale
Windows Defender Firewall is the primary host-based security control protecting endpoints from unauthorized incoming network connections and regulating outgoing network behaviors. A secure baseline requires enabling the firewall on all profiles, setting inbound connections to block by default, disabling notification prompts that can be bypassed by users, and implementing detailed auditing/logging to monitor network anomalies.

Additionally:
1. **Outbound LOLBins Blocking**: Malicious actors frequently abuse built-in Windows administrative utilities (known as Living Off the Land Binaries, or LOLBins) to download malicious payloads, exfiltrate sensitive data, and communicate with external command-and-control (C2) servers. Blocking outbound network communication for binaries that have no legitimate business requirement to connect to external networks (such as `mshta.exe`, `certutil.exe`, `bitsadmin.exe`, `regsvr32.exe`, `rundll32.exe`, `cscript.exe`, `wscript.exe`, and `hh.exe`) significantly mitigates these threat vectors.

---

## Legacy Impact & Compatibility
* **Legitimate Administrative Scripts**: Outbound rules will block administrative scripts, third-party software deployment installers, or internal software update tools that execute using `cscript.exe`, `wscript.exe`, or `mshta.exe` and require access to network resources. Proper scoping or exemptions based on authorized source paths or networks should be tested.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

#### 1. Configure Profile States and Logging
1. Open the **Group Policy Management Console** (`gpmc.msc`) on a domain controller or management workstation.
2. Edit the target endpoints GPO (e.g., `GPO_Hardening_Endpoints`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Windows Defender Firewall with Advanced Security\Windows Defender Firewall with Advanced Security`
4. Right-click **Windows Defender Firewall with Advanced Security** and select **Properties**.
5. Configure the **Domain Profile** tab:
   * **Firewall state**: `On (recommended)`
   * **Inbound connections**: `Block (default)`
   * **Outbound connections**: `Allow (default)`
   * Click **Customize...** under **Settings**:
     * **Display a notification**: `No`
     * **Apply local firewall rules**: `No`
     * **Apply local connection security rules**: `No`
   * Click **Customize...** under **Logging**:
     * **Name**: `%SystemRoot%\System32\logfiles\firewall\domainfw.log`
     * **Size limit (KB)**: `16384`
     * **Log dropped packets**: `Yes`
     * **Log successful connections**: `No`
6. Configure the **Private Profile** tab:
   * **Firewall state**: `On (recommended)`
   * **Inbound connections**: `Block (default)`
   * **Outbound connections**: `Allow (default)`
   * Click **Customize...** under **Settings**:
     * **Display a notification**: `No`
     * **Apply local firewall rules**: `No`
     * **Apply local connection security rules**: `No`
   * Click **Customize...** under **Logging**:
     * **Name**: `%SystemRoot%\System32\logfiles\firewall\privatefw.log`
     * **Size limit (KB)**: `16384`
     * **Log dropped packets**: `Yes`
     * **Log successful connections**: `No`
7. Configure the **Public Profile** tab:
   * **Firewall state**: `On (recommended)`
   * **Inbound connections**: `Block (default)`
   * **Outbound connections**: `Allow (default)`
   * Click **Customize...** under **Settings**:
     * **Display a notification**: `No`
     * **Apply local firewall rules**: `No`
     * **Apply local connection security rules**: `No`
   * Click **Customize...** under **Logging**:
     * **Name**: `%SystemRoot%\System32\logfiles\firewall\publicfw.log`
     * **Size limit (KB)**: `16384`
     * **Log dropped packets**: `Yes`
     * **Log successful connections**: `No`

#### 2. Create Outbound Rules for Known LOLBins
1. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Windows Defender Firewall with Advanced Security\Windows Defender Firewall with Advanced Security\Outbound Rules`
2. Create a new rule for each target LOLBin binary (e.g., mshta.exe, certutil.exe, bitsadmin.exe, regsvr32.exe, rundll32.exe, cscript.exe, wscript.exe, hh.exe, calc.exe, notepad.exe, conhost.exe, RunScriptHelper.exe):
   * Right-click **Outbound Rules** and select **New Rule...**
   * **Rule Type**: `Program`
   * **Program**: Choose `This program path` and enter the path matching the binary (both x64 and x86 paths if applicable, e.g., `%SystemRoot%\System32\mshta.exe` and `%SystemRoot%\SysWOW64\mshta.exe`).
   * **Action**: `Block the connection`
   * **Profile**: Select `Domain`, `Private`, and `Public`.
   * **Name**: Specify a descriptive name (e.g., `Hardening: Block Outbound mshta.exe (x64)`).

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following scripts locally to configure Windows Defender Firewall profiles, logging parameters, merge settings, and outbound LOLBins rules.

[Download Script: Configure-WindowsFirewall.ps1](implementation_scripts/Configure-WindowsFirewall.ps1)

```powershell
# Configure-WindowsFirewall.ps1
# Description: Configures Windows Defender Firewall profiles (Domain, Private, Public) and blocks outbound traffic for known LOLBins.

Write-Host "Configuring Windows Defender Firewall profiles..." -ForegroundColor Cyan

# 1. Configure profiles
$FWProfiles = @("Domain", "Private", "Public")
foreach ($FWProfile in $FWProfiles) {
    $LogFile = "$env:windir\System32\logfiles\firewall\$($FWProfile.ToLower())fw.log"
    
    Set-NetFirewallProfile -Profile $FWProfile `
        -Enabled True `
        -DefaultInboundAction Block `
        -DefaultOutboundAction Allow `
        -NotifyOnListen False `
        -AllowLocalPolicyMerge False `
        -AllowLocalIPsecPolicyMerge False `
        -LogFileName $LogFile `
        -LogMaxSizeKilobytes 16384 `
        -LogBlocked True `
        -LogAllowed False | Out-Null
    Write-Host "[+] Profile '$FWProfile' configured with logging and defaults." -ForegroundColor Green
}

# 2. Block outbound traffic for known LOLBins
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

Write-Host "Configuring outbound firewall block rules for known LOLBins..." -ForegroundColor Cyan

foreach ($Bin in $Lolbins) {
    $DisplayName = "Hardening: Block Outbound $($Bin.Name)"
    $Existing = Get-NetFirewallRule -DisplayName $DisplayName -ErrorAction SilentlyContinue
    if ($null -eq $Existing) {
        New-NetFirewallRule -DisplayName $DisplayName `
            -Name $DisplayName `
            -Direction Outbound `
            -Action Block `
            -Program $Bin.Path `
            -Profile Any `
            -Enabled True | Out-Null
        Write-Host "[+] Outbound block rule created for $($Bin.Name)." -ForegroundColor Green
    } else {
        Set-NetFirewallRule -DisplayName $DisplayName -Action Block -Enabled True | Out-Null
        Write-Host "[~] Outbound block rule for $($Bin.Name) already exists, updated state to Enabled/Block." -ForegroundColor Gray
    }
}

Write-Host "Firewall profiles and LOLBins outbound rules configured successfully." -ForegroundColor Green
```

*To verify the settings have been applied:*

[Download Script: Get-WindowsFirewallStatus.ps1](audit_scripts/Get-WindowsFirewallStatus.ps1)

```powershell
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
```

---

## Sources & Compliance References
* **CIS Microsoft Windows Client Benchmark**: Section 9.1 (Domain Profile), Section 9.2 (Private Profile), Section 9.3 (Public Profile)
* **ANSSI Active Directory Hardening Guide**: Recommendations on host-based firewalls and protocol filtering
* **Microsoft Security Baselines**: Windows Defender Firewall recommendations
