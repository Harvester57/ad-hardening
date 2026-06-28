# [REQ-OPS-009] Implement Offline Patch Management via WSUS

## Target Scope
* **Applicable Systems**: Dedicated WSUS Update Servers (Tier 0 & Tier 1/2)
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**: Offline update synchronization and media transfer procedure

---

## Rationale
Keeping Domain Controllers, member servers, and clients patched is critical to resolve OS and RPC vulnerabilities. In isolated, air-gapped networks, direct connection to Microsoft Update servers is impossible, requiring all patches to be imported offline.

Establishing an offline WSUS sync protocol:
1. **Prevents Network exposure**: Domain Controllers and administrative hosts do not require access to external network zones.
2. **Maintains Integrity**: Allows checking update metadata and approvals in a controlled sandbox environment before propagating them to production.
3. **Automates Distribution**: Uses standard WSUS client policies to distribute approved updates locally with minimal network overhead.

### WSUS Import/Export Protocol

<div class="wsus-flow-container">
  <div class="wsus-step-card online-wsus">
    <div class="wsus-step-badge">1. Online WSUS</div>
    <div class="wsus-step-content">
      <h4>Online WSUS Server</h4>
      <p class="wsus-step-desc">Synchronizes with Microsoft Update to retrieve metadata and patch binaries.</p>
      <div class="wsus-action-list">
        <span class="wsus-action-tag">wsusutil export</span>
        <span class="wsus-action-tag">WSUSContent Copy</span>
      </div>
    </div>
  </div>
  <div class="wsus-flow-arrow">
    <div class="arrow-line"></div>
    <div class="arrow-label">Physical Transfer</div>
  </div>
  <div class="wsus-step-card media-transfer">
    <div class="wsus-step-badge">2. Media</div>
    <div class="wsus-step-content">
      <h4>Encrypted Media</h4>
      <p class="wsus-step-desc">Transport encrypted external storage (USB/DVD) physically to air-gapped system.</p>
      <div class="wsus-action-list">
        <span class="wsus-action-tag">Sneakernet</span>
      </div>
    </div>
  </div>
  <div class="wsus-flow-arrow">
    <div class="arrow-line"></div>
    <div class="arrow-label">Import / Sync</div>
  </div>
  <div class="wsus-step-card offline-wsus">
    <div class="wsus-step-badge">3. Offline WSUS</div>
    <div class="wsus-step-content">
      <h4>Offline WSUS Server</h4>
      <p class="wsus-step-desc">Imports update metadata and patch binaries, then deploys them locally to DCs and Member Servers.</p>
      <div class="wsus-action-list">
        <span class="wsus-action-tag">wsusutil import</span>
        <span class="wsus-action-tag">Local Push</span>
      </div>
    </div>
  </div>
</div>

---

## Legacy Impact & Compatibility
* **Operational Overhead**: Performing sneakernet synchronization requires regular manual intervention by administrators to export updates on internet-connected networks, perform virus scans, write to encrypted media, and import onto the air-gapped WSUS server.
* **Storage Requirements**: Storing full update files on a WSUS server requires substantial storage space (typically several hundred gigabytes for multiple operating systems and products).
* **Time Drift**: There will be a latency between when patches are released and when they are imported and deployed to air-gapped systems. High-severity patches must be prioritized during scheduled transfer windows.

---

## Implementation Steps

### WSUS Categories & Classifications Configuration
Before performing the import/export process, both the online (source) and offline (destination) WSUS servers must be configured with identical Products and Classifications. If the destination server does not have the corresponding categories enabled, the imported update metadata for those categories will be ignored.

#### 1. Graphical User Interface (GUI) Configuration
On both the online and offline WSUS administration consoles:
1. Open the **Windows Server Update Services** console (`wsus.msc`).
2. Expand the server name and click on **Options** -> **Products and Classifications**.
3. In the **Products** tab, ensure the exact operating systems present in the environment are selected:
   * **Windows Server 2016**
   * **Windows Server 2019**
   * **Windows Server 2022**
   * **Windows 10**
   * **Windows 11**
4. In the **Classifications** tab, ensure the following classifications are selected:
   * **Critical Updates**
   * **Security Updates**
   * **Definition Updates** (mandatory if distributing Windows Defender signatures)
   * **Update Rollups** (standard cumulative updates)
5. Click **Apply** and then click **OK**.

#### 2. PowerShell Configuration
Run the following PowerShell commands as Administrator on both WSUS servers to align Categories and Classifications programmatically:

```powershell
# Import WSUS module
Import-Module UpdateServices

Write-Host "--- Aligning WSUS Categories & Classifications ---" -ForegroundColor Cyan

# Define targets
$TargetClassifications = @("Critical Updates", "Security Updates", "Definition Updates", "Update Rollups")
$TargetProducts = @("Windows Server 2016", "Windows Server 2019", "Windows Server 2022", "Windows 10", "Windows 11")

# Enable Classifications
Write-Host "[+] Configuring WSUS Classifications..." -ForegroundColor Gray
Get-WsusClassification | Where-Object { $TargetClassifications -contains $_.Classification.Title } | Set-WsusClassification

# Enable Products
Write-Host "[+] Configuring WSUS Products..." -ForegroundColor Gray
Get-WsusProduct | Where-Object { $TargetProducts -contains $_.Product.Title } | Set-WsusProduct

Write-Host "[+] WSUS categories and classifications updated successfully." -ForegroundColor Green
```

---

### Option A: Command-line Execution (wsusutil)

#### 1. On the Internet-Connected WSUS Server
1. Wait for standard synchronization to complete, or force a sync.
2. Open a Command Prompt as Administrator.
3. Export the WSUS metadata file:
   ```cmd
   wsusutil.exe export C:\export\metadata.xml.gz C:\export\export.log
   ```
4. Copy the metadata file (`metadata.xml.gz`) and the entire `WSUSContent` directory (containing the update binaries) onto an encrypted and scanned storage medium.

#### 2. On the Air-Gapped WSUS Server
1. Connect the transfer storage medium and copy the files to a local staging directory (e.g., `C:\import`).
2. Open a Command Prompt as Administrator.
3. Import the update metadata:
   ```cmd
   wsusutil.exe import C:\import\metadata.xml.gz C:\import\import.log
   ```
4. Copy the update binary files from the storage medium into the WSUS content directory of the air-gapped server.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Use the following PowerShell script to programmatically import WSUS metadata from a specified location using the native WSUS utility.

[Download Script: Invoke-OfflineWsusImport.ps1](implementation_scripts/Invoke-OfflineWsusImport.ps1)

```powershell
# Invoke-OfflineWsusImport.ps1
# Description: Imports WSUS update metadata from an offline backup file.

param (
    [Parameter(Mandatory = $true)]
    [string]$MetadataPath,
    
    [Parameter(Mandatory = $true)]
    [string]$LogPath
)

Write-Host "--- Performing Offline WSUS Import ---" -ForegroundColor Cyan

if (-not (Test-Path $MetadataPath)) {
    Write-Error "Metadata file not found at: $MetadataPath"
    exit 1
}

# Run wsusutil import
$WsusUtil = "C:\Program Files\Update Services\Tools\wsusutil.exe"
if (-not (Test-Path $WsusUtil)) {
    Write-Error "wsusutil.exe not found at default location."
    exit 1
}

Write-Host "[+] Running wsusutil import..." -ForegroundColor Yellow
$Process = Start-Process -FilePath $WsusUtil -ArgumentList "import `"$MetadataPath`" `"$LogPath`"" -Wait -NoNewWindow -PassThru

if ($Process.ExitCode -eq 0) {
    Write-Host "[+] Offline WSUS Import completed successfully." -ForegroundColor Green
} else {
    Write-Error "wsusutil import failed with exit code $($Process.ExitCode)."
    exit 1
}
```

*To verify synchronization state of the local WSUS server:*

[Download Script: Get-OfflineWsusSyncStatus.ps1](audit_scripts/Get-OfflineWsusSyncStatus.ps1)

```powershell
# Get-OfflineWsusSyncStatus.ps1
# Description: Checks the synchronization history of the local WSUS server.

Import-Module UpdateServices -ErrorAction SilentlyContinue

Write-Host "--- Auditing WSUS Offline Synchronization Status ---" -ForegroundColor Cyan

try {
    # Connect to the local WSUS server
    $wsus = [Microsoft.UpdateServices.Administration.AdminProxy]::GetUpdateServer()
    $history = $wsus.GetSubscription().GetSynchronizationHistory()
    
    if ($history.Count -gt 0) {
        $lastSync = $history[0]
        Write-Host "[+] Last WSUS Sync Time: $($lastSync.EndTime)" -ForegroundColor Green
        Write-Host "[+] Last WSUS Sync Result: $($lastSync.Result)" -ForegroundColor Green
        if ($lastSync.Result -eq "Succeeded") {
            exit 0
        } else {
            Write-Warning "Last WSUS Sync did not succeed."
            exit 1
        }
    } else {
        Write-Host "[-] No WSUS synchronization history found." -ForegroundColor Red
        exit 1
    }
} catch {
    Write-Host "[-] Failed to retrieve WSUS synchronization history. Ensure the WSUS role is installed and services are running." -ForegroundColor Red
    exit 1
}
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Section 3.6.2 (Windows Server Update Services)
* **ANSSI Remediation of Active Directory Tier 0 Guide**: Section 7 (Page 46)
