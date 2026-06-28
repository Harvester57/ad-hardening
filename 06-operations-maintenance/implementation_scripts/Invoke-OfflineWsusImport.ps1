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
