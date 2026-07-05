# Get-PawDefenderLocalExclusionsStatus.ps1
$Pref = Get-MpPreference
$Reg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableLocalAdminMerge" -ErrorAction SilentlyContinue
$RegHide = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "HideExclusionsFromLocalAdmins" -ErrorAction SilentlyContinue
$RegConfig = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions" -Name "DisableLocalAdminConfiguration" -ErrorAction SilentlyContinue
if (($Pref.DisableLocalAdminMerge -eq $true -or ($Reg -and $Reg.DisableLocalAdminMerge -eq 1)) -and
    ($RegHide -and $RegHide.HideExclusionsFromLocalAdmins -eq 1) -and
    ($RegConfig -and $RegConfig.DisableLocalAdminConfiguration -eq 1)) {
    Write-Output "Compliant"
    exit 0
} else {
    Write-Output "Non-Compliant"
    exit 1
}
