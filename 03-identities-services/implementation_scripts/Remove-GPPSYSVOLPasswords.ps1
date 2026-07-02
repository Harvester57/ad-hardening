# Remove-GPPSYSVOLPasswords.ps1
# Description: Removes cpassword attributes from Group Policy Preference XML files in SYSVOL and backs up original files.
# Target Engine: Windows PowerShell 5.1

Write-Host "--- Remediation: Cleaning Up GPP cpassword Credentials in SYSVOL ---" -ForegroundColor Cyan

# Retrieve local SYSVOL path from registry
$SysvolReg = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "Sysvol" -ErrorAction SilentlyContinue
if (-not $SysvolReg) {
    Write-Host "[*] SYSVOL registry path not found. Checking standard share path..." -ForegroundColor Yellow
    $SysvolPath = "C:\Windows\SYSVOL\sysvol"
} else {
    $SysvolPath = $SysvolReg.Sysvol
}

if (-not (Test-Path -Path $SysvolPath)) {
    Write-Host "[-] SYSVOL folder not found at path: $SysvolPath. Nothing to remediate." -ForegroundColor Red
    exit 0
}

# 1. Scan and remediate GPP XML files
$GppXmls = Get-ChildItem -Path $SysvolPath -Filter *.xml -Recurse -File -ErrorAction SilentlyContinue

foreach ($file in $GppXmls) {
    $content = Get-Content -Path $file.FullName -Raw -ErrorAction SilentlyContinue
    if ($content -and $content.Contains("cpassword")) {
        Write-Host "[*] Found GPP file with cpassword: $($file.FullName)" -ForegroundColor Yellow
        
        # Create Backup
        $Timestamp = Get-Date -Format "yyyyMMddHHmmss"
        $BackupPath = "$($file.FullName).bak_$Timestamp"
        Copy-Item -Path $file.FullName -Destination $BackupPath -Force -ErrorAction SilentlyContinue
        Write-Host "    [+] Created backup at: $BackupPath" -ForegroundColor Gray

        # Load XML
        [xml]$xml = New-Object System.Xml.XmlDocument
        try {
            $xml.Load($file.FullName)
            
            # Find all elements with cpassword attribute using XPath
            $Nodes = $xml.SelectNodes("//*[@cpassword]")
            if ($Nodes.Count -gt 0) {
                foreach ($Node in $Nodes) {
                    Write-Host "    [+] Stripping cpassword attribute from XML node: $($Node.Name)" -ForegroundColor White
                    $Node.RemoveAttribute("cpassword")
                    # If username exists, log it to help administrator identify what was affected
                    if ($Node.Attributes["username"]) {
                        Write-Host "    [!] Note: Node was configured for username '$($Node.Attributes["username"].Value)'" -ForegroundColor Yellow
                    }
                }
                $xml.Save($file.FullName)
                Write-Host "    [+] Successfully stripped cpassword from: $($file.FullName)" -ForegroundColor Green
            }
        }
        catch {
            Write-Host "    [-] Failed to parse or save XML: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

# 2. Alert for scripts (Do not auto-remediate script files to prevent code syntax breakage)
$ScriptFiles = Get-ChildItem -Path $SysvolPath -Include *.vbs, *.ps1, *.bat, *.cmd -Recurse -File -ErrorAction SilentlyContinue
$CredentialPattern = '(?i)\b(password|pwd|adminpwd|syspwd|adminpassword|localadminpwd)\s*=\s*["''][^"'']+\b'

foreach ($file in $ScriptFiles) {
    # Skip our own audit and implementation scripts
    if ($file.Name -like "*Get-GPPSYSVOLPasswords*" -or $file.Name -like "*Remove-GPPSYSVOLPasswords*" -or $file.Name -like "*SYSVOLHoneypot*") {
        continue
    }

    $content = Get-Content -Path $file.FullName -Raw -ErrorAction SilentlyContinue
    if ($content -and $content -match $CredentialPattern) {
        Write-Host "[WARNING] Script contains hardcoded credential pattern: $($file.FullName)" -ForegroundColor Red
        Write-Host "          Manual intervention is required. Review and delete/rotate credentials in this script." -ForegroundColor Yellow
    }
}

Write-Host "[+] SYSVOL password remediation processing completed." -ForegroundColor Green
