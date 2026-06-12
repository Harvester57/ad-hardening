# Import-ThirdPartyTemplate.ps1
# Description: Copies a specified ADMX and ADML template to the Central Store.

Import-Module ActiveDirectory

Write-Host "Applying hardening requirement: Copy GPO Templates to Central Store..." -ForegroundColor Cyan

# Define local source paths for templates (to be populated by administrator)
$SourceAdmx = "C:\SourceTemplates\msedge.admx"
$SourceAdml = "C:\SourceTemplates\en-US\msedge.adml"

try {
    $Domain = Get-ADDomain -ErrorAction Stop
    $CentralStorePath = "\\$($Domain.DNSRoot)\SYSVOL\$($Domain.DNSRoot)\Policies\PolicyDefinitions"
    
    if (-not (Test-Path -Path $CentralStorePath)) {
        Write-Error "GPO Central Store is not initialized. Please establish the Central Store first."
        exit 1
    }
    
    if ((Test-Path -Path $SourceAdmx) -and (Test-Path -Path $SourceAdml)) {
        # Copy ADMX file
        Copy-Item -Path $SourceAdmx -Destination $CentralStorePath -Force -ErrorAction Stop
        Write-Host "[+] Copied ADMX: $(Split-Path $SourceAdmx -Leaf) to Central Store." -ForegroundColor Green
        
        # Copy ADML file to matching subfolder
        $LangDir = Join-Path $CentralStorePath "en-US"
        if (-not (Test-Path -Path $LangDir)) {
            New-Item -ItemType Directory -Path $LangDir -Force -ErrorAction Stop | Out-Null
        }
        Copy-Item -Path $SourceAdml -Destination $LangDir -Force -ErrorAction Stop
        Write-Host "[+] Copied ADML: $(Split-Path $SourceAdml -Leaf) to Central Store en-US subfolder." -ForegroundColor Green
    } else {
        Write-Warning "Source template files not found at specified paths. Please ensure templates are downloaded locally."
    }
} catch {
    Write-Error "Failed to copy template files. Error: $($_.Exception.Message)"
}
