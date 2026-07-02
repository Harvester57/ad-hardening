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
