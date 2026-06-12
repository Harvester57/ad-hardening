# Test-AutoPlay.ps1
# Audits local system registry parameters for AutoPlay status.

Write-Host "--- Auditing AutoPlay Configuration ---" -ForegroundColor Cyan

$ExplorerPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$PolExplorerPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"

$NoDriveAuto = Get-ItemProperty -Path $ExplorerPath -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue
$NoAutoCmd = Get-ItemProperty -Path $ExplorerPath -Name "NoAutorun" -ErrorAction SilentlyContinue
$NoNonVol = Get-ItemProperty -Path $PolExplorerPath -Name "NoAutoplayfornonVolume" -ErrorAction SilentlyContinue

$NoDriveVal = if ($NoDriveAuto) { $NoDriveAuto.NoDriveTypeAutoRun } else { 0 }
$NoAutoVal = if ($NoAutoCmd) { $NoAutoCmd.NoAutorun } else { 0 }
$NoNonVolVal = if ($NoNonVol) { $NoNonVol.NoAutoplayfornonVolume } else { 0 }

$NoDriveColor = if ($NoDriveVal -eq 255) { "Green" } else { "Red" }
$NoAutoColor = if ($NoAutoVal -eq 1) { "Green" } else { "Red" }
$NoNonVolColor = if ($NoNonVolVal -eq 1) { "Green" } else { "Red" }

Write-Host "    - NoDriveTypeAutoRun: $NoDriveVal (Required = 255 to disable all drives)" -ForegroundColor $NoDriveColor
Write-Host "    - NoAutorun: $NoAutoVal (Required = 1)" -ForegroundColor $NoAutoColor
Write-Host "    - NoAutoplayfornonVolume: $NoNonVolVal (Required = 1)" -ForegroundColor $NoNonVolColor
