# New-KdsKey.ps1
# Description: Generates a new KDS Root Key.

Import-Module Kds

Write-Host "Creating new KDS Root Key..." -ForegroundColor Cyan

# Create new KDS key effective immediately (backdated by 10 hours to bypass replication delay)
$NewKey = Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10)) -ErrorAction Stop

if ($null -ne $NewKey) {
    Write-Host "[+] New KDS Root Key created successfully. Key ID: $NewKey" -ForegroundColor Green
}
