# Get-DefenderSmartScreenStatus.ps1
$Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
if (Test-Path $Path) {
    $Enable = Get-ItemProperty -Path $Path -Name "EnableSmartScreen" -ErrorAction SilentlyContinue
    $Level = Get-ItemProperty -Path $Path -Name "ShellSmartScreenLevel" -ErrorAction SilentlyContinue
    if ($Enable -and $Enable.EnableSmartScreen -eq 1 -and $Level -and $Level.ShellSmartScreenLevel -eq "Block") {
        Write-Output "Compliant"
        exit 0
    }
}
Write-Output "Non-Compliant"
exit 1
