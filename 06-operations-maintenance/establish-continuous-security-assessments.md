# [REQ-OPS-010] Establish Continuous Security Assessments

## Target Scope
* **Applicable Systems**: Active Directory Domain Services, Management Workstations
* **Operating Systems**: Windows Server 2016+, Windows 10/11 Enterprise

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**: Administrative diagnostic tools configuration and execution plan

---

## Rationale
Active Directory configurations naturally drift over time as a result of administrative changes, new trust relationships, and changing group policies. Administrators must actively search for misconfigurations, weak permissions, and signs of compromise.

In isolated, air-gapped networks, online security analysis services cannot be reached. Therefore:
1. **Periodic Scans**: Execute security audits locally using offline-compatible tools (such as PingCastle, BloodHound/SharpHound, or ORADAD).
2. **Directory Health Monitoring**: Run PingCastle monthly to generate local XML/HTML reports indicating domain vulnerabilities and tracking AD configuration health.
3. **Lateral Movement Auditing**: Execute SharpHound quarterly to construct lateral movement path graphs, enabling defenders to identify complex trust relationships or delegation chains leading to Tier 0 compromise.
4. **Data Isolation**: Transfer the diagnostic reports and export ZIPs out of production to secure, offline assessment platforms to limit exposure of sensitive configuration data.

---

## Legacy Impact & Compatibility
* **LDAP & Domain Controller Load**: SharpHound queries Active Directory via LDAP and SAMR protocols, which can generate thousands of queries depending on the directory's size. Schedule directory-wide collectors during low-activity windows to avoid latency.
* **Security Alarm Generation**: SharpHound and PingCastle execution looks like reconnaissance activity and can trigger alerts in local Antivirus or Endpoint Detection and Response (EDR) agents. Administrators must coordinate scans with security operations teams and authorize the diagnostic binaries.
* **Data Sensitivity**: BloodHound export ZIPs and PingCastle reports contain highly sensitive structural details of the directory. These files must be stored with strict access controls (Domain Admins only) and purged from administrative workstations after completion.

---

## Implementation Steps

### Option A: Manual Diagnostic Tool Execution

#### 1. Running PingCastle Audits
1. Place `PingCastle.exe` in a secure local diagnostic directory (e.g., `C:\Diagnostics`).
2. Open a Command Prompt as Administrator on a domain-joined workstation.
3. Run the following command to generate the HTML report and XML output:
   ```cmd
   PingCastle.exe --server target.domain.local --level level_Default --xml --no_update
   ```
4. Collect the generated files from the directory and transfer them to a secure analysis terminal.

#### 2. Running BloodHound/SharpHound Collectors
1. Place the `SharpHound.exe` collector binary in the diagnostic directory.
2. Open a Command Prompt as Administrator on a domain-joined workstation.
3. Run the collector using standard active directory enumeration methods:
   ```cmd
   SharpHound.exe --CollectionMethods All --Domain target.domain.local --ZipFileName AD_BloodHound_Export.zip
   ```
4. Copy the resulting zip file to the offline BloodHound graph database dashboard to query and audit lateral movement paths.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Use the following PowerShell script to automate the execution of both PingCastle and SharpHound collectors inside a specified diagnostic workspace.

[Download Script: Start-OfflineAssessments.ps1](implementation_scripts/Start-OfflineAssessments.ps1)

```powershell
# Start-OfflineAssessments.ps1
# Description: Triggers a PingCastle security audit scan and SharpHound data collection.

param (
    [string]$DiagnosticsPath = "C:\Diagnostics",
    [string]$DomainName = "target.domain.local"
)

Write-Host "--- Starting AD Hardening Offline Assessment Scans ---" -ForegroundColor Cyan

if (-not (Test-Path $DiagnosticsPath)) {
    New-Item -Path $DiagnosticsPath -ItemType Directory -Force | Out-Null
}

$PingCastlePath = Join-Path $DiagnosticsPath "PingCastle.exe"
$SharpHoundPath = Join-Path $DiagnosticsPath "SharpHound.exe"

# 1. Execute PingCastle
if (Test-Path $PingCastlePath) {
    Write-Host "[+] Executing PingCastle..." -ForegroundColor Yellow
    $params = @(
        "--server", $DomainName,
        "--level", "level_Default",
        "--xml",
        "--no_update",
        "--output", $DiagnosticsPath
    )
    Start-Process -FilePath $PingCastlePath -ArgumentList $params -Wait -NoNewWindow
    Write-Host "[+] PingCastle scan complete." -ForegroundColor Green
} else {
    Write-Error "PingCastle.exe not found at $PingCastlePath. Please place the binary to execute."
}

# 2. Execute SharpHound
if (Test-Path $SharpHoundPath) {
    Write-Host "[+] Executing SharpHound..." -ForegroundColor Yellow
    $zipName = "AD_BloodHound_Export_" + (Get-Date -Format "yyyyMMdd") + ".zip"
    $zipPath = Join-Path $DiagnosticsPath $zipName
    
    $params = @(
        "--CollectionMethods", "All",
        "--Domain", $DomainName,
        "--ZipFileName", $zipPath
    )
    Start-Process -FilePath $SharpHoundPath -ArgumentList $params -Wait -NoNewWindow
    Write-Host "[+] SharpHound collection complete. Saved to: $zipPath" -ForegroundColor Green
} else {
    Write-Error "SharpHound.exe not found at $SharpHoundPath. Please place the binary to execute."
}
```

*To verify that diagnostic tools and recent reports exist on the auditing system:*

[Download Script: Get-OfflineAssessmentStatus.ps1](audit_scripts/Get-OfflineAssessmentStatus.ps1)

```powershell
# Get-OfflineAssessmentStatus.ps1
# Description: Audits the presence of PingCastle and SharpHound tools and the age of recent reports.

Write-Host "--- Auditing Active Directory Security Assessment Tools ---" -ForegroundColor Cyan

$DiagnosticsPath = "C:\Diagnostics" # Common diagnostics path
$PingCastlePath = Join-Path $DiagnosticsPath "PingCastle.exe"
$SharpHoundPath = Join-Path $DiagnosticsPath "SharpHound.exe"
$ReportAgeDays = 30

$Compliant = $true

# 1. Check PingCastle
if (Test-Path $PingCastlePath) {
    Write-Host "[+] PingCastle executable found: $PingCastlePath" -ForegroundColor Green
    
    # Check if reports have been generated in the last 30 days
    $reports = Get-ChildItem -Path $DiagnosticsPath -Filter "*pingcastle*.xml" -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -ge (Get-Date).AddDays(-$ReportAgeDays) }
    if ($reports) {
        Write-Host "    [+] Found $($reports.Count) recent PingCastle report(s) (within last $ReportAgeDays days)." -ForegroundColor Green
    } else {
        Write-Warning "    [-] No recent PingCastle report found (older than $ReportAgeDays days)."
        $Compliant = $false
    }
} else {
    Write-Warning "[-] PingCastle executable NOT found at: $PingCastlePath"
    $Compliant = $false
}

# 2. Check SharpHound
if (Test-Path $SharpHoundPath) {
    Write-Host "[+] SharpHound executable found: $SharpHoundPath" -ForegroundColor Green
    
    # Check if data exports exist
    $exports = Get-ChildItem -Path $DiagnosticsPath -Filter "*BloodHound*.zip" -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -ge (Get-Date).AddDays(-$ReportAgeDays) }
    if ($exports) {
        Write-Host "    [+] Found $($exports.Count) recent SharpHound export(s) (within last $ReportAgeDays days)." -ForegroundColor Green
    } else {
        Write-Warning "    [-] No recent SharpHound export found (older than $ReportAgeDays days)."
        $Compliant = $false
    }
} else {
    Write-Warning "[-] SharpHound executable NOT found at: $SharpHoundPath"
    $Compliant = $false
}

if ($Compliant) {
    Write-Host "`nStatus: Compliant. Diagnostics tools and recent reports are present." -ForegroundColor Green
    exit 0
} else {
    Write-Host "`nStatus: Non-Compliant. Action required." -ForegroundColor Red
    exit 1
}
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Recommendation R57 (Perform continuous security assessments and audits)
* **CIS Microsoft Windows Server 2016 Benchmark v2.0.0**: Section 18.9 (Administrative tools and logging controls)
