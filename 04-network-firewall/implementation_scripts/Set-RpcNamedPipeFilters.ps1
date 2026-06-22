# Set-RpcNamedPipeFilters.ps1
# Description: Generates and imports RPC filters to block remote management over SMB named pipes.

Write-Host "Applying hardening requirement: Configure RPC Named Pipe Filters..." -ForegroundColor Cyan

# Define the path where the filters file will be written
$FilterFilePath = Join-Path $env:TEMP "RpcNamedPipesFilters.txt"

# Write the netsh RPC filter commands
$FilterContent = @"
rpc filter
add rule layer=um actiontype=block filterkey=d0c7640c-9355-4e52-8335-c12835559c10
add condition field=protocol matchtype=equal data=ncacn_np
add condition field=if_uuid matchtype=equal data=367ABB81-9844-35F1-AD32-98F038001003
add filter

add rule layer=um actiontype=block filterkey=a43b9dd2-0866-4476-89dc-2e9b200762af
add condition field=protocol matchtype=equal data=ncacn_np
add condition field=if_uuid matchtype=equal data=86D35949-83C9-4044-B424-DB363231FD0C
add filter

add rule layer=um actiontype=block filterkey=13518c11-e3d8-4f62-9461-eda11beb540a
add condition field=if_uuid matchtype=equal data=1FF70682-0A51-30E8-076D-740BE8CEE98B
add filter

add rule layer=um actiontype=block filterkey=1c079a18-e91f-4698-9868-68a121490636
add condition field=if_uuid matchtype=equal data=378E52B0-C0A9-11CF-822D-00AA0051E40F
add filter

add rule layer=um actiontype=block filterkey=dedffabf-db89-4177-be77-1954aa2c0b95
add condition field=protocol matchtype=equal data=ncacn_np
add condition field=if_uuid matchtype=equal data=f6beaff7-1e19-4fbb-9f8f-b89e2018337c
add filter

add rule layer=um actiontype=block filterkey=f7f68868-5f50-4cda-a18c-6a7a549652e7
add condition field=if_uuid matchtype=equal data=82273FDC-E32A-18C3-3F78-827929DC23EA
add filter

add rule layer=um actiontype=permit filterkey=43873c58-e130-4ffb-8858-d259a673a917
add condition field=if_uuid matchtype=equal data=4FC742E0-4A10-11CF-8273-00AA004AE673
add condition field=remote_user_token matchtype=equal data=D:(A;;CC;;;DA)
add filter

add rule layer=um actiontype=block filterkey=0a239867-73db-45e6-b287-d006fe3c8b18
add condition field=if_uuid matchtype=equal data=4FC742E0-4A10-11CF-8273-00AA004AE673
add filter

add rule layer=um actiontype=block filterkey=7966512a-f2f4-4cb1-812d-d967ab83d28a
add condition field=protocol matchtype=equal data=ncacn_np
add condition field=if_uuid matchtype=equal data=12345678-1234-ABCD-EF00-0123456789AB
add filter

add rule layer=um actiontype=permit filterkey=d71d00db-3eef-4935-bedf-20cf628abd9e
add condition field=if_uuid matchtype=equal data=c681d488-d850-11d0-8c52-00c04fd90f7e
add condition field=auth_type matchtype=equal data=16
add condition field=auth_level matchtype=equal data=6
add filter

add rule layer=um actiontype=block filterkey=3a4cce27-a7fa-4248-b8b8-ef6439a2c0ff
add condition field=if_uuid matchtype=equal data=c681d488-d850-11d0-8c52-00c04fd90f7e
add filter

add rule layer=um actiontype=permit filterkey=c5cf8020-c83c-4803-9241-8c7f3b10171f
add condition field=if_uuid matchtype=equal data=df1941c5-fe89-4e79-bf10-463657acf44d
add condition field=auth_type matchtype=equal data=16
add condition field=auth_level matchtype=equal data=6
add filter

add rule layer=um actiontype=block filterkey=9ad23a91-085d-4f99-ae15-85e0ad801278
add condition field=if_uuid matchtype=equal data=df1941c5-fe89-4e79-bf10-463657acf44d
add filter

add rule layer=um actiontype=block filterkey=50754fe4-aa2d-42ff-8196-e90ea8fd2527
add condition field=protocol matchtype=equal data=ncacn_np
add condition field=if_uuid matchtype=equal data=50abc2a4-574d-40b3-9d66-ee4fd5fba076
add filter
add rule layer=um actiontype=block filterkey=644291ca-9530-4066-b654-e7b838ebdc06
add condition field=if_uuid matchtype=equal data=17FC11E9-C258-4B8D-8D07-2F4125156244
add filter

add rule layer=um actiontype=block filterkey=5270da6b-67a8-4cbf-8b2c-fa5d0abcb975
add condition field=protocol matchtype=equal data=ncacn_np
add condition field=if_uuid matchtype=equal data=a8e0653c-2744-4389-a61d-7373df8b2292
add filter
"@

# Write filters to temp file
Set-Content -Path $FilterFilePath -Value $FilterContent -Encoding Ascii
Write-Host "[+] Generated RPC filters file at: $FilterFilePath" -ForegroundColor Gray

# Import using netsh (requires elevation)
Write-Host "[+] Importing RPC filters using Netsh..." -ForegroundColor Gray
$Proc = Start-Process -FilePath "netsh.exe" -ArgumentList "rpc filter import `"$FilterFilePath`"" -Wait -NoNewWindow -PassThru

if ($Proc.ExitCode -eq 0) {
    Write-Host "[+] RPC filters imported successfully." -ForegroundColor Green
} else {
    Write-Error "[-] Failed to import RPC filters. Netsh exit code: $($Proc.ExitCode)."
}

# Clean up temp file
if (Test-Path $FilterFilePath) {
    Remove-Item -Path $FilterFilePath -Force | Out-Null
}
