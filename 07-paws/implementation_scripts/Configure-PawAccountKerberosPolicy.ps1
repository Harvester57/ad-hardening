# Configure-PawAccountKerberosPolicy.ps1
Write-Host "Configuring PAW Kerberos policy..." -ForegroundColor Cyan

$SecTempDir = Join-Path $env:TEMP "PAWKerberosSecTemplate"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }

$CfgFile = Join-Path $SecTempDir "paw_kerberos.cfg"
$DbFile = Join-Path $SecTempDir "paw_kerberos.sdb"
$LogFile = Join-Path $SecTempDir "paw_kerberos.log"

$Process = Start-Process secedit -ArgumentList "/export /cfg `"$CfgFile`"" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -ne 0) { Throw "Failed to export current security template." }

$ConfigText = Get-Content -Path $CfgFile -Raw
if ($ConfigText -notmatch "\[Kerberos Policy\]") {
    $ConfigText += "`r`n[Kerberos Policy]`r`n"
}

$Lines = $ConfigText -split "`r?`n"
$NewLines = @()
$InKerb = $false

$KerbSettings = @{
    "MaxServiceTicketAge"  = 600
    "MaxTicketAge"         = 10
    "MaxRenewAge"          = 7
    "MaxClockSkew"         = 5
    "TicketValidateClient" = 1
}

foreach ($Line in $Lines) {
    if ($Line -match "^\[(.*)\]$") {
        if ($Matches[1] -eq "Kerberos Policy") { $InKerb = $true } else { $InKerb = $false }
    }
    if ($InKerb) {
        $IsManaged = $false
        foreach ($Key in $KerbSettings.Keys) {
            if ($Line -match "^\s*$($Key)\s*=") { $IsManaged = $true; break }
        }
        if (-not $IsManaged) { $NewLines += $Line }
    } else {
        $NewLines += $Line
    }
}

$FinalLines = @()
foreach ($Line in $NewLines) {
    $FinalLines += $Line
    if ($Line -eq "[Kerberos Policy]") {
        foreach ($Key in $KerbSettings.Keys) {
            $Val = $KerbSettings[$Key]
            $FinalLines += "$($Key) = $($Val)"
        }
    }
}

$FinalLines -join "`r`n" | Out-File -FilePath $CfgFile -Encoding ascii -Force
$Proc = Start-Process secedit -ArgumentList "/configure /db `"$DbFile`" /cfg `"$CfgFile`" /areas SECURITYPOLICY /log `"$LogFile`"" -Wait -NoNewWindow -PassThru
if ($Proc.ExitCode -ne 0) { Throw "Failed to apply SecEdit Kerberos policy." }

Remove-Item -Path $SecTempDir -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "PAW Kerberos policy applied successfully." -ForegroundColor Green
