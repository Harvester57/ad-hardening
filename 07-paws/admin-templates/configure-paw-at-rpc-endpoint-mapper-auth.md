# [REQ-PAW-180] Administrative Templates: Enable RPC Endpoint Mapper Client Authentication for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration.
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc\EnableAuthEpResolution` = `1`

---

## Rationale
The RPC Endpoint Mapper listens on TCP port 135 to resolve dynamic server endpoints for RPC interfaces. Enabling client authentication forces clients to authenticate to the Endpoint Mapper before obtaining endpoint addresses, preventing unauthenticated network adversaries from performing RPC reconnaissance and MITM endpoint redirection.

---

## Legacy Impact & Compatibility
* **Operational Impact**: Legacy pre-Windows Server 2003 or third-party UNIX RPC clients incapable of authenticating to the Endpoint Mapper will fail to resolve RPC endpoints.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to PAWs Organizational Unit (e.g., `GPO_Hardening_PAW`).
3. Configure the following policies:

* Navigate to: `Computer Configuration\Policies\Administrative Templates\System\Remote Procedure Call`
  * **Enable RPC Endpoint Mapper Client Authentication**: Set to `Enabled`

4. Link the GPO to the appropriate Organizational Unit and verify replication.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the administrative template registry values:

[Download Script: Configure-PawAtRpcEndpointMapperAuth.ps1](../implementation_scripts/Configure-PawAtRpcEndpointMapperAuth.ps1)

```powershell
#Configure-PawAtRpcEndpointMapperAuth.ps1
# Description: Configures Administrative Templates: Enable RPC Endpoint Mapper Client Authentication for PAWs.

Write-Host "Configuring Administrative Templates: Enable RPC Endpoint Mapper Client Authentication for PAWs..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" -Name "EnableAuthEpResolution" -Value 1 -Type DWord -Force

Write-Host "[+] Administrative Templates: Enable RPC Endpoint Mapper Client Authentication for PAWs applied successfully." -ForegroundColor Green
```

*To verify the configuration:*

[Download Script: Get-PawAtRpcEndpointMapperAuthStatus.ps1](../audit_scripts/Get-PawAtRpcEndpointMapperAuthStatus.ps1)

```powershell
#Get-PawAtRpcEndpointMapperAuthStatus.ps1
# Description: Audits Administrative Templates: Enable RPC Endpoint Mapper Client Authentication for PAWs.

Write-Host "--- Auditing Administrative Templates: Enable RPC Endpoint Mapper Client Authentication for PAWs ---" -ForegroundColor Cyan
$script:Vulnerable = $false

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc"
$ValueName = "EnableAuthEpResolution"
$ExpectedValue = 1
if (Test-Path -Path $TargetKey) {
    $Prop = Get-ItemProperty -Path $TargetKey -Name $ValueName -ErrorAction SilentlyContinue
    if ($null -ne $Prop) {
        $Actual = $Prop.$ValueName
        if ($Actual -eq $ExpectedValue) {
            Write-Host "  [+] $ValueName = $($Actual) (Secure)" -ForegroundColor Green
        } else {
            Write-Host "  [!] MISMATCH: $ValueName = $($Actual) (Expected: $($ExpectedValue))" -ForegroundColor Red
            $script:Vulnerable = $true
        }
    } else {
        Write-Host "  [!] MISSING VALUE: $ValueName (Expected: $($ExpectedValue))" -ForegroundColor Red
        $script:Vulnerable = $true
    }
} else {
    Write-Host "  [!] MISSING KEY: $TargetKey" -ForegroundColor Red
    $script:Vulnerable = $true
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
* **CIS Benchmark**: CIS Microsoft Windows Client Benchmark: Section 18.9.36.1; ANSSI R34
* **ANSSI Active Directory Hardening Guide**: Baseline security parameters for managed Windows environments
* **Microsoft Security Baseline**: Recommended administrative template and component restrictions
