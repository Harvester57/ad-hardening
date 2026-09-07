# Get-PeernetStatus.ps1
# Description: Audits registry configuration of Microsoft Peer-to-Peer Networking Services on Domain Controllers.

Write-Host "--- Auditing Microsoft Peer-to-Peer Networking Services Status ---" -ForegroundColor Cyan

$PeernetPath = "HKLM:\SOFTWARE\Policies\Microsoft\Peernet"
$ExpectedValue = 1

if (Test-Path -Path $PeernetPath) {
    $Reg = Get-ItemProperty -Path $PeernetPath -ErrorAction SilentlyContinue
    $CurrentValue = $Reg.Disabled

    if ($CurrentValue -eq $ExpectedValue) {
        Write-Host "    [+] Peernet Disabled: $($CurrentValue) (Expected: $($ExpectedValue))" -ForegroundColor Green
        exit 0
    } else {
        Write-Host "    [!] Peernet Disabled: $($CurrentValue) (Expected: $($ExpectedValue))" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "    [!] Peernet Registry Path NOT FOUND" -ForegroundColor Red
    exit 1
}
