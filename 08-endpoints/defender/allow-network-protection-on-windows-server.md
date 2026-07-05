# [REQ-END-063] Allow Network Protection on Windows Server

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers.
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional, Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\Windows Defender Exploit Guard\Network Protection`
  * **Registry Location**:
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection`
      * `AllowNetworkProtectionOnWinServer` = `1` (REG_DWORD)

---

## Rationale
Network Protection blocks processes from accessing malicious domains, phishing sites, and host IP ranges. Allowing Network Protection on Windows Server ensures that member servers running server workloads possess the same IP filter protections as client platforms.

---

## Legacy Impact & Compatibility
Unrecognized or legacy client-server connections to custom web resources may be filtered. Exclusions must be mapped under DFE.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Navigate to: Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\Windows Defender Exploit Guard\Network Protection
2. Set 'This setting controls whether Network Protection is allowed to be configured into block or audit mode on Windows Server' to 'Enabled'

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-DefenderNetworkProtectionServer.ps1](../implementation_scripts/Configure-DefenderNetworkProtectionServer.ps1)

```powershell
# Configure-DefenderNetworkProtectionServer.ps1
$NetProtPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection"
if (-not (Test-Path $NetProtPath)) { New-Item -Path $NetProtPath -Force | Out-Null }
Set-ItemProperty -Path $NetProtPath -Name "AllowNetworkProtectionOnWinServer" -Value 1 -Type DWord -Force
```

*To audit the hardening status:*
[Download Script: Get-DefenderNetworkProtectionServerStatus.ps1](../audit_scripts/Get-DefenderNetworkProtectionServerStatus.ps1)

```powershell
# Get-DefenderNetworkProtectionServerStatus.ps1
$Reg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" -Name "AllowNetworkProtectionOnWinServer" -ErrorAction SilentlyContinue
if ($Reg -and $Reg.AllowNetworkProtectionOnWinServer -eq 1) {
    Write-Output "Compliant"
    exit 0
} else {
    Write-Output "Non-Compliant"
    exit 1
}
```

---

## Sources & Compliance References
* **CIS Microsoft Windows 10 Benchmark**: Section 18.9 (Windows Defender Antivirus configuration parameters)
* **ANSSI Active Directory Hardening Guide**: Protective controls baselines on client workstations
