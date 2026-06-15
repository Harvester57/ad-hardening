# Configure-WindowsFirewall.ps1
# Description: Configures Windows Defender Firewall profiles (Domain, Private, Public) and blocks outbound traffic for known LOLBins.

Write-Host "Configuring Windows Defender Firewall profiles..." -ForegroundColor Cyan

# 1. Configure profiles
$FWProfiles = @("Domain", "Private", "Public")
foreach ($FWProfile in $FWProfiles) {
    $LogFile = "$env:windir\System32\logfiles\firewall\$($FWProfile.ToLower())fw.log"
    
    if ($Profile -eq "Public") {
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
            -LogAllowed True | Out-Null
    } else {
        Set-NetFirewallProfile -Profile $FWProfile `
            -Enabled True `
            -DefaultInboundAction Block `
            -DefaultOutboundAction Allow `
            -NotifyOnListen False `
            -LogFileName $LogFile `
            -LogMaxSizeKilobytes 16384 `
            -LogBlocked True `
            -LogAllowed True | Out-Null
    }
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
    @{ Name = "hh.exe (x86)"; Path = "%SystemRoot%\SysWOW64\hh.exe" }
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
