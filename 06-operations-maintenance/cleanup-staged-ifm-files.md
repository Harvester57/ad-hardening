# [REQ-OPS-013] Clean Up Staged Install From Media (IFM) Data

## Target Scope
* **Applicable Systems**: Domain Controllers, Member Servers
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**: Administrative Standards / Scheduled Tasks

---

## Rationale
The Install From Media (IFM) feature allows administrators to promote a new Domain Controller using an offline backup dataset rather than copying the entire Active Directory database over the network. 

To generate this dataset, administrators run the `ntdsutil` tool (e.g., `ntdsutil "ac i ntds" "ifm" "create full c:\Staging" q q`). This process generates a staging folder containing:
1. The Active Directory database file (`ntds.dit`).
2. Copies of the `SYSTEM` and `SECURITY` registry hives (which contain the boot key needed to decrypt the database file).

If these staged IFM folders are left behind on member servers, administrative shares, or staging volumes, any user or attacker who compromises that machine can copy the files and extract all Active Directory password hashes offline. Securing active directory requires ensuring that temporary IFM datasets are deleted immediately after the new Domain Controller is promoted.

---

## Legacy Impact & Compatibility
* **Operational Readiness**: The only operational impact is that the IFM data is no longer available on the staging host. If another Domain Controller needs to be promoted using IFM, a new dataset must be generated.
* **Service Interruption**: This cleanup process has zero impact on active Active Directory services.

---

## Implementation Steps

### Option A: Manual Search and Deletion (GUI)

To manually locate and clean up staged IFM folders:
1. Log on to the staging Member Server or Domain Controller with administrative privileges.
2. Open **File Explorer** and search all local disk volumes (e.g., `C:\`, `D:\`) for files named `ntds.dit`.
3. Verify the location of each found file:
   * **Domain Controllers**: The authorized directory is the Active Directory database path (typically `C:\Windows\NTDS\ntds.dit` as specified in the registry value `DSA Database file` under `HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters`).
   * **Member Servers**: There are no authorized directories. Any instance of `ntds.dit` is unauthorized.
4. If an unauthorized `ntds.dit` file is located:
   * Select the folder containing the `ntds.dit` file (which usually also contains a `registry` sub-folder).
   * Delete the folder and clear it from the Recycle Bin.

---

### Option B: PowerShell & Remediation (Non-GPO / Script-based)

Use these scripts to audit and automatically delete staged IFM datasets.

[Download Script: Remove-StagedIFM.ps1](implementation_scripts/Remove-StagedIFM.ps1)

```powershell
# Remove-StagedIFM.ps1
# Description: Searches for unauthorized copies of ntds.dit and deletes them.
# Target Engine: Windows PowerShell 5.1

Write-Host "Applying hardening requirement: Clean Up Staged IFM Data..." -ForegroundColor Cyan

# 1. Resolve standard active directory database path (only applicable to DCs)
$StandardDir = $null
$StandardAdPath = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "DSA Database file" -ErrorAction SilentlyContinue)."DSA Database file"
if ($StandardAdPath) {
    $StandardDir = [System.IO.Path]::GetDirectoryName($StandardAdPath)
}

# 2. Recursive search function excluding standard heavy system directories
function Search-UnauthorizedDIT ($SearchPath) {
    if (-not (Test-Path $SearchPath)) { return @() }
    
    $Found = @()
    $Items = Get-ChildItem -Path $SearchPath -ErrorAction SilentlyContinue
    foreach ($Item in $Items) {
        if ($Item.Attributes -match "Directory") {
            # Skip system/program directories to optimize speed
            if ($Item.Name -match "^(Windows|Program Files|Program Files \(x86\)|\$Recycle\.Bin|System Volume Information|AppData)$") {
                continue
            }
            $Found += Search-UnauthorizedDIT $Item.FullName
        } elseif ($Item.Name -ieq "ntds.dit") {
            # Skip authorized DC database folder
            if ($null -ne $StandardDir -and $Item.DirectoryName -eq $StandardDir) {
                continue
            }
            $Found += $Item.FullName
        }
    }
    return $Found
}

# 3. Scan all local drives
$Drives = Get-PSDrive -PSProvider FileSystem
$VulnerableFiles = @()

foreach ($Drive in $Drives) {
    $Root = $Drive.Root
    Write-Host "[*] Scanning drive $Root for unauthorized ntds.dit files..." -ForegroundColor Gray
    $VulnerableFiles += Search-UnauthorizedDIT $Root
}

# 4. Delete unauthorized directories
if ($VulnerableFiles.Count -gt 0) {
    Write-Host "[-] Found $($VulnerableFiles.Count) unauthorized ntds.dit file(s)." -ForegroundColor Yellow
    foreach ($File in $VulnerableFiles) {
        $FolderToDelete = [System.IO.Path]::GetDirectoryName($File)
        Write-Host "[-] Deleting staging directory: $FolderToDelete" -ForegroundColor Yellow
        try {
            Remove-Item -Path $FolderToDelete -Recurse -Force -ErrorAction Stop
            Write-Host "[+] Directory $FolderToDelete successfully deleted." -ForegroundColor Green
        } catch {
            Write-Error "Failed to delete directory: $FolderToDelete. Error: $($_.Exception.Message)"
        }
    }
} else {
    Write-Host "[+] No unauthorized staged ntds.dit files found on local drives." -ForegroundColor Green
}
```

*To audit the system for staged IFM directories:*

[Download Script: Get-StagedIFMStatus.ps1](audit_scripts/Get-StagedIFMStatus.ps1)

```powershell
# Get-StagedIFMStatus.ps1
# Description: Audits local drives for unauthorized staged ntds.dit databases.
# Target Engine: Windows PowerShell 5.1

Write-Host "--- Auditing Staged IFM Data ---" -ForegroundColor Cyan

# 1. Resolve standard active directory database path (only applicable to DCs)
$StandardDir = $null
$StandardAdPath = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "DSA Database file" -ErrorAction SilentlyContinue)."DSA Database file"
if ($StandardAdPath) {
    $StandardDir = [System.IO.Path]::GetDirectoryName($StandardAdPath)
}

# 2. Recursive search function
function Search-UnauthorizedDIT ($SearchPath) {
    if (-not (Test-Path $SearchPath)) { return @() }
    
    $Found = @()
    $Items = Get-ChildItem -Path $SearchPath -ErrorAction SilentlyContinue
    foreach ($Item in $Items) {
        if ($Item.Attributes -match "Directory") {
            # Skip system/program directories to optimize speed
            if ($Item.Name -match "^(Windows|Program Files|Program Files \(x86\)|\$Recycle\.Bin|System Volume Information|AppData)$") {
                continue
            }
            $Found += Search-UnauthorizedDIT $Item.FullName
        } elseif ($Item.Name -ieq "ntds.dit") {
            # Skip authorized DC database folder
            if ($null -ne $StandardDir -and $Item.DirectoryName -eq $StandardDir) {
                continue
            }
            $Found += $Item.FullName
        }
    }
    return $Found
}

# 3. Scan local drives
$Drives = Get-PSDrive -PSProvider FileSystem
$VulnerableFiles = @()

foreach ($Drive in $Drives) {
    $Root = $Drive.Root
    $VulnerableFiles += Search-UnauthorizedDIT $Root
}

# 4. Evaluate status
if ($VulnerableFiles.Count -gt 0) {
    foreach ($File in $VulnerableFiles) {
        Write-Host "[!] VULNERABLE: Unauthorized ntds.dit database found at: $File" -ForegroundColor Red
    }
    exit 1
} else {
    Write-Host "[+] Secure: No unauthorized staged ntds.dit database files found." -ForegroundColor Green
    exit 0
}
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Recommendations on protecting domain backups and credentials storage
* **Microsoft Security Guidance**: Active Directory Install From Media (IFM) Security best practices
