# Get-GPPSYSVOLPasswords.ps1
# Description: Audits the SYSVOL directory for legacy Group Policy Preference files containing cpassword values and scripts containing cleartext credentials.
# Target Engine: Windows PowerShell 5.1

Write-Host "--- Auditing SYSVOL for Group Policy Preference and Script Passwords ---" -ForegroundColor Cyan
$script:Vulnerable = $false

# Retrieve local SYSVOL path from registry
$SysvolReg = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "Sysvol" -ErrorAction SilentlyContinue
if (-not $SysvolReg) {
    Write-Host "[*] SYSVOL registry path not found. Checking standard share path..." -ForegroundColor Yellow
    $SysvolPath = "C:\Windows\SYSVOL\sysvol"
} else {
    $SysvolPath = $SysvolReg.Sysvol
}

if (-not (Test-Path -Path $SysvolPath)) {
    Write-Host "[-] SYSVOL folder not found at path: $SysvolPath" -ForegroundColor Red
    exit 0 # Not a Domain Controller or SYSVOL not configured, nothing to audit
}

Write-Host "[*] Scanning SYSVOL directory: $SysvolPath" -ForegroundColor White

# 1. Scan for XML files containing 'cpassword'
$GppXmls = Get-ChildItem -Path $SysvolPath -Filter *.xml -Recurse -File -ErrorAction SilentlyContinue
foreach ($file in $GppXmls) {
    # Read the file content safely
    $content = Get-Content -Path $file.FullName -Raw -ErrorAction SilentlyContinue
    if ($content -and $content.Contains("cpassword")) {
        Write-Host "[!] VULNERABLE: Group Policy Preference file contains cpassword attribute: $($file.FullName)" -ForegroundColor Red
        $script:Vulnerable = $true
    }
}

# 2. Scan for script files containing cleartext credentials
# Scripts: .vbs, .ps1, .bat, .cmd
$ScriptFiles = Get-ChildItem -Path $SysvolPath -Include *.vbs, *.ps1, *.bat, *.cmd -Recurse -File -ErrorAction SilentlyContinue

# Regex pattern for credentials (e.g. password=, pwd=, adminpwd=)
$CredentialPattern = '(?i)\b(password|pwd|adminpwd|syspwd|adminpassword|localadminpwd)\s*=\s*["''][^"'']+\b'

foreach ($file in $ScriptFiles) {
    # Check if the file is our own audit or implementation scripts (skip those)
    if ($file.Name -like "*Get-GPPSYSVOLPasswords*" -or $file.Name -like "*Remove-GPPSYSVOLPasswords*" -or $file.Name -like "*SYSVOLHoneypot*") {
        continue
    }
    
    $content = Get-Content -Path $file.FullName -Raw -ErrorAction SilentlyContinue
    if ($content -and $content -match $CredentialPattern) {
        Write-Host "[!] VULNERABLE: Script file contains potential cleartext password: $($file.FullName)" -ForegroundColor Red
        $script:Vulnerable = $true
    }
}

if ($script:Vulnerable) {
    Write-Host "Audit Result: VULNERABLE" -ForegroundColor Red
    exit 1
} else {
    Write-Host "[+] No Group Policy Preference passwords or cleartext scripts found in SYSVOL." -ForegroundColor Green
    Write-Host "Audit Result: SECURE" -ForegroundColor Green
    exit 0
}
