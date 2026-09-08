# [REQ-PAW-169] Administrative Templates: Configure NetBT Node Type and Name Release for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration.
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * `HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\NodeType` = `2`
  * `HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\NoNameReleaseOnDemand` = `1`

---

## Rationale
Configuring NetBT NodeType to P-node (Point-to-Point) forces name resolution via unicast WINS rather than broadcast, preventing unauthenticated network adversaries from responding to NetBIOS broadcasts or poisoning name resolution caches. Forcing the system to ignore unauthenticated NetBIOS name release requests prevents denial-of-service attacks that force the computer to relinquish its registered network identity.

---

## Legacy Impact & Compatibility
* **Operational Impact**: Environments relying purely on unrouted broadcast-based NetBIOS name resolution without DNS or WINS will experience resolution failures.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to PAWs Organizational Unit (e.g., `GPO_Hardening_PAW`).
3. Configure the following policies:

* Navigate to: `Computer Configuration\Policies\Administrative Templates\Network\TCPIP Settings\Parameters`
  * **NetBT NodeType configuration**: Set to `Enabled` (P-node (recommended))
* Navigate to: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
  * **MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers**: Set to `Enabled`

4. Link the GPO to the appropriate Organizational Unit and verify replication.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the administrative template registry values:

[Download Script: Configure-PawAtNetbtNodetype.ps1](../implementation_scripts/Configure-PawAtNetbtNodetype.ps1)

```powershell
#Configure-PawAtNetbtNodetype.ps1
# Description: Configures Administrative Templates: Configure NetBT Node Type and Name Release for PAWs.

Write-Host "Configuring Administrative Templates: Configure NetBT Node Type and Name Release for PAWs..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters")) {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -Name "NodeType" -Value 2 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -Name "NoNameReleaseOnDemand" -Value 1 -Type DWord -Force

Write-Host "[+] Administrative Templates: Configure NetBT Node Type and Name Release for PAWs applied successfully." -ForegroundColor Green
```

*To verify the configuration:*

[Download Script: Get-PawAtNetbtNodetypeStatus.ps1](../audit_scripts/Get-PawAtNetbtNodetypeStatus.ps1)

```powershell
#Get-PawAtNetbtNodetypeStatus.ps1
# Description: Audits Administrative Templates: Configure NetBT Node Type and Name Release for PAWs.

Write-Host "--- Auditing Administrative Templates: Configure NetBT Node Type and Name Release for PAWs ---" -ForegroundColor Cyan
$script:Vulnerable = $false

$TargetKey = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters"
$ValueName = "NodeType"
$ExpectedValue = 2
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

$TargetKey = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters"
$ValueName = "NoNameReleaseOnDemand"
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
* **CIS Benchmark**: CIS Microsoft Windows Client Benchmark: Section 18.4.7, Section 18.5.7
* **ANSSI Active Directory Hardening Guide**: Baseline security parameters for managed Windows environments
* **Microsoft Security Baseline**: Recommended administrative template and component restrictions
