# Hardening Requirement: Migrate SYSVOL Replication to DFSR

## Target Scope
* **Applicable Systems**: Domain Controllers
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**: Domain Controller replication system attributes (managed via `dfsrmig.exe` tool and the DFSR service)

---

## Rationale
Active Directory domain environments rely on replication to synchronize GPO templates and scripts stored in the `SYSVOL` share across all Domain Controllers. Historically, this replication was managed by the File Replication Service (FRS). 

However, FRS is obsolete, does not support modern transport-layer security features, and is prone to replication database corruption. 

Migrating to Distributed File System Replication (DFSR):
1. **Ensures Replication Integrity**: DFSR uses remote differential compression algorithms and hash validation to verify that files are replicated securely and without corruption.
2. **Minimizes Attack Surface**: Transitioning to DFSR allows security administrators to completely disable and deprecate the legacy, insecure FRS service and its associated RPC endpoints.
3. **Improves Diagnostics**: DFSR provides comprehensive logging, system health auditing, and diagnostic reports, allowing quick identification of synchronization failures.

---

## Legacy Impact & Compatibility
* **Replication Health Requirement**: Prior to migration, Active Directory and file replication must be fully synchronized and healthy. Any existing replication errors will prevent successful migration and can lead to domain-wide split-brain scenarios.
* **One-Way Committal**: The final stage of the migration (State 3: Eliminated) is permanent. FRS databases are deleted, and it is impossible to roll back to FRS without restoring Domain Controllers from backups.
* **System Requirements**: All Domain Controllers in the domain must run Windows Server 2008 or later, and the Domain Functional Level (DFL) must be raised to at least Windows Server 2008.

---

## Implementation Steps

### Option A: Manual Step-by-Step Migration Command Line

The migration process consists of transitioning the domain through four replication states (from State 0 to State 3) using the `dfsrmig` command line tool on a writable Domain Controller (typically the PDC Emulator).

1. **Verify Current State**:
   Open an elevated command prompt on the DC and run:
   `dfsrmig /getglobalstate`
   *Expected starting output*: `Current DFSR global state: 'Start'` (State 0).

2. **Transition to Prepared State (State 1)**:
   This state creates a clone of the `SYSVOL` folder named `SYSVOL_DFSR` and begins DFSR replication in the background while keeping the original `SYSVOL` folder active via FRS.
   `dfsrmig /setglobalstate 1`

3. **Verify State 1 Reachability**:
   Query all Domain Controllers to ensure they have successfully transitioned to the Prepared state:
   `dfsrmig /getmigrationstate`
   *Do not proceed to the next step until the output confirms*: `All Domain Controllers have migrated successfully to the Global state ('Prepared')`.

4. **Transition to Redirected State (State 2)**:
   This state redirects the active `SYSVOL` network share mapping to point to the new `SYSVOL_DFSR` folder replicated by DFSR. FRS continues replication in the background for backward compatibility/rollback capability.
   `dfsrmig /setglobalstate 2`

5. **Verify State 2 Reachability**:
   Query the status to confirm all DCs have successfully redirected:
   `dfsrmig /getmigrationstate`
   *Do not proceed until the output confirms*: `All Domain Controllers have migrated successfully to the Global state ('Redirected')`.

6. **Transition to Eliminated State (State 3)**:
   This final stage commits the migration. It deletes the original `SYSVOL` directory, stops and disables the FRS service, and deletes the FRS replication configuration from Active Directory.
   `dfsrmig /setglobalstate 3`

7. **Verify State 3 Committal**:
   Confirm the migration is complete:
   `dfsrmig /getmigrationstate`
   *Expected Output*: `All Domain Controllers have migrated successfully to the Global state ('Eliminated')`.

---

### Option B: PowerShell Migration Status Auditing

Use this PowerShell script to monitor the progress of the DFSR migration across all Domain Controllers in the forest.

```powershell
# Get-SYSVOLDfsrMigrationStatus.ps1
# Description: Checks the current SYSVOL replication migration state.

Import-Module ActiveDirectory

Write-Host "--- Auditing SYSVOL DFSR Migration Status ---" -ForegroundColor Cyan

# Check if the FRS service is still running on this DC
$FrsService = Get-Service -Name "NtFrs" -ErrorAction SilentlyContinue

if ($null -ne $FrsService) {
    Write-Host "[*] FRS Service State: $($FrsService.Status)" -ForegroundColor White
} else {
    Write-Host "[+] FRS Service is not installed (expected in modern server configurations)." -ForegroundColor Green
}

# Run dfsrmig validation checks
$DfsMigOutput = & dfsrmig.exe /getglobalstate 2>&1

if ($DfsMigOutput -like "*Eliminated*") {
    Write-Host "[+] SYSVOL migration to DFSR is complete and finalized (State 3: Eliminated)." -ForegroundColor Green
} else {
    Write-Host "[-] WARNING: SYSVOL replication is not fully migrated to DFSR." -ForegroundColor Red
    Write-Host "    Current Status: $DfsMigOutput" -ForegroundColor Yellow
}
```

*To verify active DFSR health on the server:*
```powershell
# Get-DfsrHealthStatus.ps1
# Description: Checks the event logs for DFSR replication errors.

Write-Host "Checking DFSR replication event logs..." -ForegroundColor Cyan

$DfsrEvents = Get-WinEvent -LogName "DFS Replication" -MaxEvents 10 -ErrorAction SilentlyContinue

if ($DfsrEvents) {
    foreach ($Event in $DfsrEvents) {
        $EventColor = if ($Event.LevelDisplayName -eq "Error") { "Red" } else { "White" }
        Write-Host "[$($Event.TimeCreated)] [$($Event.LevelDisplayName)] ID: $($Event.Id) - $($Event.Message)" -ForegroundColor $EventColor
    }
} else {
    Write-Host "[+] No recent DFSR events or errors detected." -ForegroundColor Green
}
```

---

## Sources & Compliance References
* **ANSSI Remediation of Active Directory Tier 0 Guide**: Section 5.e (Page 31)
* **ANSSI AD Hardening Guide**: Section 3.1.1 (Niveaux fonctionnels)
* **Microsoft Security Guidance**: Migrate SYSVOL Replication to DFS Replication (DFSR) Guide
