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
