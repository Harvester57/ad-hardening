# [REQ-NET-012] Configure RPC Filters for Named Pipes

## Target Scope
* **Applicable Systems**: Domain Controllers, Member Servers.
* **Operating Systems**: Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Startup Script Location**: Computer Configuration\Policies\Windows Settings\Scripts (Startup)
  * **Netsh Configuration File**: `RpcNamedPipesFilters.txt` (imported via `netsh.exe -f RpcNamedPipesFilters.txt`)

---

## Rationale
Active Directory domains heavily rely on the Server Message Block (SMB) protocol (TCP 445) for distributing group policies and replication via the SYSVOL and NETLOGON file shares. Therefore, SMB cannot simply be blocked at the network level on domain controllers.

However, adversaries and common hacktools (e.g., PSExec, Mimikatz) abuse this exposure. They establish connections to SMB named pipes (such as `\PIPE\svcctl` for the Service Control Manager or `\PIPE\samr` for the Security Account Manager) to remotely execute code, manipulate services, or query administrative APIs.

Implementing Windows Firewall **RPC Filters** solves this vulnerability:
1. **Granular Control over Named Pipes**: Unlike standard L3/L4 firewall rules which can only allow or block all of TCP 445, RPC Filters inspect the RPC interface UUID inside the SMB payload.
2. **Selective Blocking**: Filters can block administrative RPC interfaces (like Service Control Manager `[MS-SCMR]`, Task Scheduler `[MS-TSCH]`, and Terminal Services runtime) over the `ncacn_np` (named pipe) transport, while leaving standard file sharing and replication functional.
3. **Exploit Containment**: By blocking interfaces like the Terminal Services runtime or MimiCom (Mimikatz interface), lateral movement and remote code execution techniques are contained.

---

## Legacy Impact & Compatibility
* **Remote Administration Impact**: Applying these filters will block remote administration of services (`sc.exe`), scheduled tasks (`schtasks.exe`), and event logs from unauthorized remote member servers using named pipes. Administrators must use secure TCP/IP management protocols (such as PowerShell Remoting/WinRM or remote MMC consoles utilizing ncacn_ip_tcp transport) from authorized PAWs.
* **GPO Startup Dependencies**: Since Windows does not provide a standard GPO interface for RPC Filters, they must be imported via startup scripts.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

#### 1. Create the RPC Filters Definition File
Create a text file named `RpcNamedPipesFilters.txt` with the following content:
```text
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
```

#### 2. Deploy via GPO Startup Script
1. Save `RpcNamedPipesFilters.txt` inside the GPO's Startup folder.
2. Create a batch script `Import-RpcFilters.bat` containing:
   ```cmd
   @echo off
   netsh.exe -f "%~dp0RpcNamedPipesFilters.txt"
   ```
3. Set the batch script as a Startup Script in the GPO targeting Domain Controllers under:
   `Computer Configuration\Policies\Windows Settings\Scripts (Startup)`

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following scripts locally to import and query RPC named pipe filters.

#### Remediation Script:
[Download Script: Set-RpcNamedPipeFilters.ps1](implementation_scripts/Set-RpcNamedPipeFilters.ps1)

```powershell
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
```

#### Audit Script:
[Download Script: Test-RpcNamedPipeFilters.ps1](audit_scripts/Test-RpcNamedPipeFilters.ps1)

```powershell
# Test-RpcNamedPipeFilters.ps1
# Description: Audits active RPC filters configuration using Netsh queries.

Write-Host "Auditing RPC filters configuration..." -ForegroundColor Cyan

# Query RPC filters
$filters = netsh rpc filter show filter

# Check for presence of SCM block rule filterkey, Mimikatz block rule filterkey, or MS-FSRVP block rule filterkey
$scmFound = $false
$mimiFound = $false
$fsrvpFound = $false

foreach ($line in $filters) {
    if ($line -like "*d0c7640c-9355-4e52-8335-c12835559c10*") {
        $scmFound = $true
    }
    if ($line -like "*644291ca-9530-4066-b654-e7b838ebdc06*") {
        $mimiFound = $true
    }
    if ($line -like "*5270da6b-67a8-4cbf-8b2c-fa5d0abcb975*") {
        $fsrvpFound = $true
    }
}

if ($scmFound -and $mimiFound -and $fsrvpFound) {
    Write-Host "[+] RPC Filters for named pipes are active (SCM, Mimikatz, and MS-FSRVP filterkeys found)." -ForegroundColor Green
    Write-Host "Audit result: COMPLIANT" -ForegroundColor Green
} else {
    Write-Host "[!] NON-COMPLIANT: Core RPC named pipe filters are missing or inactive." -ForegroundColor Red
    if (-not $scmFound) {
        Write-Host "    - Missing SCM Named Pipe Filter (d0c7640c-9355-4e52-8335-c12835559c10)" -ForegroundColor Yellow
    }
    if (-not $mimiFound) {
        Write-Host "    - Missing Mimikatz Filter (644291ca-9530-4066-b654-e7b838ebdc06)" -ForegroundColor Yellow
    }
    if (-not $fsrvpFound) {
        Write-Host "    - Missing MS-FSRVP ShadowCoerce Filter (5270da6b-67a8-4cbf-8b2c-fa5d0abcb975)" -ForegroundColor Yellow
    }
    Write-Host "Audit result: NON-COMPLIANT" -ForegroundColor Red
}
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Recommendation R7 (Filtering and IPsec on Domain Controllers), Recommendation R8 (Administration network subnets / filtering rules)
* **CIS Benchmark**: Section 19 (Windows Defender Firewall with Advanced Security)
* **DSInternals AD Firewall Guide (Michael Grafnetter)**: [Active Directory Firewall - Domain Controller Firewall](https://firewall.dsinternals.com/ADDS/)
