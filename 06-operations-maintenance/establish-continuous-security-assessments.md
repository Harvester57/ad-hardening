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
1. **Periodic Scans**: Execute security audits locally using offline-compatible tools (such as PingCastle, BloodHound/SharpHound, Locksmith, or ORADAD).
2. **Directory Health Monitoring**: Run PingCastle monthly to generate local XML/HTML reports indicating domain vulnerabilities and tracking AD configuration health.
3. **Lateral Movement Auditing**: Execute SharpHound quarterly to construct lateral movement path graphs, enabling defenders to identify complex trust relationships or delegation chains leading to Tier 0 compromise.
4. **Active Directory Certificate Services Auditing**: Run Locksmith monthly to identify misconfigured certificate templates, insecure enrollment settings, and potential AD CS privilege escalation paths.
5. **Data Isolation**: Transfer the diagnostic reports, CSV exports, and export ZIPs out of production to secure, offline assessment platforms to limit exposure of sensitive configuration data.

---

## Legacy Impact & Compatibility
* **LDAP & Domain Controller Load**: SharpHound queries Active Directory via LDAP and SAMR protocols, which can generate thousands of queries depending on the directory's size. Schedule directory-wide collectors during low-activity windows to avoid latency.
* **Security Alarm Generation**: SharpHound, Locksmith, and PingCastle execution looks like reconnaissance activity and can trigger alerts in local Antivirus or Endpoint Detection and Response (EDR) agents. Administrators must coordinate scans with security operations teams and authorize the diagnostic tools.
* **Data Sensitivity**: BloodHound export ZIPs, PingCastle reports, and Locksmith CSV exports contain highly sensitive structural details of the directory. These files must be stored with strict access controls (Domain Admins only) and purged from administrative workstations after completion.

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

#### 3. Running Locksmith Audits (AD CS)
1. Download the `Invoke-Locksmith.ps1` script from the official repository and place it in the diagnostic directory (e.g., `C:\Diagnostics`).
2. Open PowerShell as Administrator on a domain-joined workstation.
3. Run the script using the CSV export mode (Mode 2) to audit AD CS and save findings:
```powershell
Set-Location -Path C:\Diagnostics
.\Invoke-Locksmith.ps1 -Mode 2
```
4. Copy the generated `ADCSIssues.CSV` report to a secure analysis terminal for offline review.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Use the following PowerShell script to automate the execution of PingCastle, SharpHound, and Locksmith collectors inside a specified diagnostic workspace.

[Download Script: Start-OfflineAssessments.ps1](implementation_scripts/Start-OfflineAssessments.ps1)

```powershell
# Start-OfflineAssessments.ps1
# Description: Triggers PingCastle, SharpHound, and Locksmith security audit scans.

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
$LocksmithPath = Join-Path $DiagnosticsPath "Invoke-Locksmith.ps1"

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

# 3. Execute Locksmith
if (Test-Path $LocksmithPath) {
    Write-Host "[+] Executing Locksmith..." -ForegroundColor Yellow
    $originalLocation = Get-Location
    Set-Location -Path $DiagnosticsPath
    try {
        & $LocksmithPath -Mode 2
        Write-Host ("[+] Locksmith scan complete. Saved to: " + (Join-Path $DiagnosticsPath "ADCSIssues.CSV")) -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to execute Locksmith: $($_.Exception.Message)"
    }
    finally {
        Set-Location -Path $originalLocation
    }
} else {
    Write-Error "Invoke-Locksmith.ps1 not found at $LocksmithPath. Please place the script to execute."
}
```

*To verify that diagnostic tools and recent reports exist on the auditing system:*

[Download Script: Get-OfflineAssessmentStatus.ps1](audit_scripts/Get-OfflineAssessmentStatus.ps1)

```powershell
# Get-OfflineAssessmentStatus.ps1
# Description: Audits the presence of PingCastle, SharpHound, and Locksmith tools and the age of recent reports.

Write-Host "--- Auditing Active Directory Security Assessment Tools ---" -ForegroundColor Cyan

$DiagnosticsPath = "C:\Diagnostics" # Common diagnostics path
$PingCastlePath = Join-Path $DiagnosticsPath "PingCastle.exe"
$SharpHoundPath = Join-Path $DiagnosticsPath "SharpHound.exe"
$LocksmithPath = Join-Path $DiagnosticsPath "Invoke-Locksmith.ps1"
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

# 3. Check Locksmith
if (Test-Path $LocksmithPath) {
    Write-Host "[+] Locksmith script found: $LocksmithPath" -ForegroundColor Green
    
    # Check if Locksmith CSV output exists and was generated in the last 30 days
    $locksmithReport = Get-ChildItem -Path $DiagnosticsPath -Filter "ADCSIssues.CSV" -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -ge (Get-Date).AddDays(-$ReportAgeDays) }
    if ($locksmithReport) {
        Write-Host "    [+] Found recent Locksmith report (within last $ReportAgeDays days)." -ForegroundColor Green
    } else {
        Write-Warning "    [-] No recent Locksmith report (ADCSIssues.CSV) found (older than $ReportAgeDays days)."
        $Compliant = $false
    }
} else {
    Write-Warning "[-] Locksmith script (Invoke-Locksmith.ps1) NOT found at: $LocksmithPath"
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
* **Locksmith Repository**: [Trimarc Locksmith AD CS Auditing Tool](https://github.com/jakehildreth/Locksmith)
