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
Active Directory domains heavily rely on the Server Message Block (SMB) protocol (TCP 445) for distributing group policies and replication via the SYSVOL and NETLOGON file shares. Because every joined domain member requires access to these shares, TCP port 445 cannot simply be blocked at the network perimeter or host firewall level on Domain Controllers.

However, adversaries and post-exploitation frameworks (such as Impacket PsExec, SMBExec, AExec, Coercer, PetitPotam, and Mimikatz) routinely abuse this open SMB surface. Windows Remote Procedure Call (RPC) supports two primary transport protocols:
1. **RPC over TCP/IP (`ncacn_ip_tcp`)**: Binds each service dynamically (or to configured static ports) across ephemeral TCP ports (49152-65535).
2. **RPC over Named Pipes (`ncacn_np`)**: Multiplexes RPC requests directly through SMB named pipes over TCP port 445.

Standard Layer 3 and Layer 4 firewall rules can only permit or block the entire TCP port 445. If TCP 445 is permitted, an attacker with network access can connect to sensitive SMB named pipes (such as `\PIPE\svcctl` or `\PIPE\atsvc`) to execute remote code or trigger authentication coercion without ever needing access to dynamic RPC ports.

### Windows Firewall RPC Filtering Architecture

Windows Defender Firewall includes an advanced, lesser-known subsystem known as **RPC Filters**. RPC Filters operate at the User Mode Application Layer (`layer=um`) and inspect the Remote Procedure Call headers inside the network payload:
* **Interface Inspection (`if_uuid`)**: Evaluates the 128-bit UUID of the RPC interface being requested.
* **Protocol Transports (`protocol`)**: Distinguishes between RPC over SMB Named Pipes (`ncacn_np`) and direct TCP/IP (`ncacn_ip_tcp`).
* **Authentication Strength (`auth_type`, `auth_level`)**: Enforces minimum authentication security (e.g. Kerberos `auth_type=16`) and encryption privacy (Packet Privacy `auth_level=6`).
* **User Identity Tokens (`remote_user_token`)**: Enforces Security Descriptor Definition Language (SDDL) access checks to restrict specific RPC interfaces exclusively to authorized security principals (such as Domain Admins `DA`).

By applying RPC Filters, administrators can surgically block or restrict administrative RPC interfaces over named pipes (`ncacn_np`) while keeping core Active Directory replication, SYSVOL access, and file sharing fully operational.

---

### Master Reference Table: Named Pipes and RPC Interfaces

The following table details all 16 RPC filter rules implemented in the remediation script and GPO configuration file, including their Filter Keys, Interface UUIDs, SMB Named Pipe bindings, filtering actions, and the threat vectors they mitigate:

| # | Filter Key | RPC Interface UUID | Protocol / MS Specification | SMB Named Pipe | Action & Conditions | Mitigated Threat Vector / Attack Vector |
|---|---|---|---|---|---|---|
| 1 | `d0c7640c-9355-4e52-8335-c12835559c10` | `367ABB81-9844-35F1-AD32-98F038001003` | [MS-SCMR]: Service Control Manager Remote Protocol | `\PIPE\svcctl` | `block` (`protocol = ncacn_np`) | Remote service creation and lateral movement via SMB (e.g., PsExec, SMBExec, `sc.exe`). |
| 2 | `a43b9dd2-0866-4476-89dc-2e9b200762af` | `86D35949-83C9-4044-B424-DB363231FD0C` | [MS-TSCH]: Task Scheduler Service Remoting Protocol | `\PIPE\atsvc` | `block` (`protocol = ncacn_np`) | Remote scheduled task creation and lateral movement over SMB (e.g., Impacket `atexec`, `schtasks.exe`). |
| 3 | `13518c11-e3d8-4f62-9461-eda11beb540a` | `1FF70682-0A51-30E8-076D-740BE8CEE98B` | [MS-TSCH]: Task Scheduler Legacy AT Interface 1 | `\PIPE\atsvc` | `block` (All transports) | Obsolete legacy `at.exe` job scheduling interface across all network transports. |
| 4 | `1c079a18-e91f-4698-9868-68a121490636` | `378E52B0-C0A9-11CF-822D-00AA0051E40F` | [MS-TSCH]: Task Scheduler Legacy AT Interface 2 | `\PIPE\atsvc` | `block` (All transports) | Obsolete legacy `at.exe` auxiliary scheduling interface across all network transports. |
| 5 | `dedffabf-db89-4177-be77-1954aa2c0b95` | `f6beaff7-1e19-4fbb-9f8f-b89e2018337c` | [MS-EVEN6]: EventLog Remoting Protocol Version 6.0 | `\PIPE\eventlog` | `block` (`protocol = ncacn_np`) | Remote event log querying, tampering, and clearing over SMB named pipes (`wevtutil.exe`). |
| 6 | `f7f68868-5f50-4cda-a18c-6a7a549652e7` | `82273FDC-E32A-18C3-3F78-827929DC23EA` | [MS-EVEN]: EventLog Remoting Protocol (Legacy) | `\PIPE\eventlog` | `block` (All transports) | Legacy EventLog interface used for NTLM authentication coercion (`ElfrOpenBELW`) and CVE-2025-29969 RCE. |
| 7 | `43873c58-e130-4ffb-8858-d259a673a917` | `4FC742E0-4A10-11CF-8273-00AA004AE673` | [MS-DFSNM]: Distributed File System Namespace Management | `\PIPE\netdfs` | `permit` (`remote_user_token = D:(A;;CC;;;DA)`) | Authorizes DFS namespace configuration strictly for Domain Admins (`DA`). |
| 8 | `0a239867-73db-45e6-b287-d006fe3c8b18` | `4FC742E0-4A10-11CF-8273-00AA004AE673` | [MS-DFSNM]: Distributed File System Namespace Management | `\PIPE\netdfs` | `block` (All transports) | Blocks unprivileged DFS namespace management, neutralizing DFSCoerce NTLM coercion (`NetrDfsRemoveStdRoot`). |
| 9 | `7966512a-f2f4-4cb1-812d-d967ab83d28a` | `12345678-1234-ABCD-EF00-0123456789AB` | [MS-RPRN]: Print System Remote Protocol | `\PIPE\spoolss` | `block` (`protocol = ncacn_np`) | Blocks Print Spooler RPC over named pipes, preventing PrinterBug / SpoolSample NTLM coercion. |
| 10 | `d71d00db-3eef-4935-bedf-20cf628abd9e` | `c681d488-d850-11d0-8c52-00c04fd90f7e` | [MS-EFSR]: Encrypting File System Remote Protocol | `\PIPE\lsarpc` | `permit` (`auth_type = 16 & auth_level = 6`) | Permits EFSRPC via `lsarpc` only if Kerberos-authenticated (`16`) and encrypted via Packet Privacy (`6`). |
| 11 | `3a4cce27-a7fa-4248-b8b8-ef6439a2c0ff` | `c681d488-d850-11d0-8c52-00c04fd90f7e` | [MS-EFSR]: Encrypting File System Remote Protocol | `\PIPE\lsarpc` | `block` (All transports) | Blocks unencrypted, anonymous, and NTLM-authenticated EFSRPC calls over `lsarpc` (PetitPotam). |
| 12 | `c5cf8020-c83c-4803-9241-8c7f3b10171f` | `df1941c5-fe89-4e79-bf10-463657acf44d` | [MS-EFSR]: Encrypting File System Remote Protocol | `\PIPE\efsrpc` | `permit` (`auth_type = 16 & auth_level = 6`) | Permits EFSRPC via `efsrpc` only if Kerberos-authenticated (`16`) and encrypted via Packet Privacy (`6`). |
| 13 | `9ad23a91-085d-4f99-ae15-85e0ad801278` | `df1941c5-fe89-4e79-bf10-463657acf44d` | [MS-EFSR]: Encrypting File System Remote Protocol | `\PIPE\efsrpc` | `block` (All transports) | Blocks unencrypted, anonymous, and NTLM-authenticated EFSRPC calls over `efsrpc` (PetitPotam). |
| 14 | `50754fe4-aa2d-42ff-8196-e90ea8fd2527` | `50abc2a4-574d-40b3-9d66-ee4fd5fba076` | [MS-DNSP]: Domain Name Service (DNS) Server Management | `\PIPE\DNSSERVER` | `block` (`protocol = ncacn_np`) | Blocks remote DNS server management over named pipes, preventing `ServerLevelPluginDll` DLL injection / RCE. |
| 15 | `644291ca-9530-4066-b654-e7b838ebdc06` | `17FC11E9-C258-4B8D-8D07-2F4125156244` | MimiCom (Mimikatz Remote C2 / Administration Interface) | Any / Custom Pipe | `block` (All transports) | Blocks the default Mimikatz C2 and remote execution RPC interface across all network transports. |
| 16 | `5270da6b-67a8-4cbf-8b2c-fa5d0abcb975` | `a8e0653c-2744-4389-a61d-7373df8b2292` | [MS-FSRVP]: File Server Remote VSS Protocol | `\PIPE\FssagentRpc` | `block` (`protocol = ncacn_np`) | Blocks File Server VSS Agent Service over SMB named pipes, mitigating ShadowCoerce NTLM coercion. |

---

### Protocol-Specific Hardening Analysis

#### 1. Service Control Manager ([MS-SCMR]) & Task Scheduler ([MS-TSCH])
The Service Control Manager (`367ABB81-9844-35F1-AD32-98F038001003`) and Task Scheduler (`86D35949-83C9-4044-B424-DB363231FD0C`) are the primary mechanisms leveraged by lateral movement utilities such as PsExec and Impacket. Standard Windows management utilities (`services.msc`, `sc.exe`, `taskschd.msc`, `schtasks.exe`) negotiate direct TCP/IP RPC connections (`ncacn_ip_tcp`) by default. Conversely, offensive tools bind to named pipes (`\PIPE\svcctl` and `\PIPE\atsvc`) because SMB port 445 is almost universally open. Blocking `ncacn_np` for these interfaces cuts off common lateral movement paths without affecting legitimate administration from PAWs. Additionally, legacy `at.exe` interfaces (`1FF70682...` and `378E52B0...`) are completely deprecated and blocked across all transports.

#### 2. Event Log Remoting Protocols ([MS-EVEN6] & [MS-EVEN])
Modern Windows Event Log management operates via `[MS-EVEN6]` (`F6BEAFF7-1E19-4FBB-9F8F-B89E2018337C`). Blocking this over `ncacn_np` prevents attackers from using SMB to tamper with or clear Security event logs. Furthermore, the legacy `[MS-EVEN]` interface (`82273FDC-E32A-18C3-3F78-827929DC23EA`) is bound to `\PIPE\eventlog`. This legacy interface has been repeatedly abused for unauthenticated NTLM relay coercion (e.g. `ElfrOpenBELW`) and was targeted by remote code execution vulnerability **CVE-2025-29969**. Blocking this interface unconditionally across all transports completely neutralizes these attack vectors.

#### 3. DFS Namespace Management ([MS-DFSNM])
The DFS Namespace Management protocol (`4FC742E0-4A10-11CF-8273-00AA004AE673`) is exposed via `\PIPE\netdfs`. Attack tools like DFSCoerce trigger forced authentication back to attacker listeners by calling APIs such as `NetrDfsRemoveStdRoot`. By implementing an explicit permit rule with `remote_user_token = D:(A;;CC;;;DA)` followed by an unconditional block rule, only authenticated Domain Admins can invoke DFS namespace APIs, denying access to standard domain users and unauthenticated callers.

#### 4. Print System Remote Protocol ([MS-RPRN])
Exposed on `\PIPE\spoolss` (`12345678-1234-ABCD-EF00-0123456789AB`), the Print Spooler interface is famously abused by PrinterBug / SpoolSample (`RpcRemoteFindFirstPrinterChangeNotificationEx`) to force Domain Controllers to authenticate to arbitrary hosts. While Domain Controllers should disable the Print Spooler service altogether ([REQ-DC-008]), applying this filter rule provides defense-in-depth on member servers or in environments where the service cannot be stopped immediately.

#### 5. Encrypting File System Remote Protocol ([MS-EFSR])
The EFSRPC protocol is exposed on two named pipes: `\PIPE\lsarpc` (`c681d488-d850-11d0-8c52-00c04fd90f7e`) and `\PIPE\efsrpc` (`df1941c5-fe89-4e79-bf10-463657acf44d`). This interface is the root cause of PetitPotam coercion attacks. The hardening policy allows EFSRPC calls only when they satisfy two strict cryptographic conditions:
* `auth_type = 16`: Authentication must use **Kerberos** (negotiated SPNEGO/Kerberos), blocking NTLM-relayed sessions.
* `auth_level = 6`: The session must use **Packet Privacy** (`RPC_C_AUTHN_LEVEL_PKT_PRIVACY`), requiring end-to-end encryption.
Calls failing either condition hit the subsequent block rules and are dropped.

#### 6. Domain Name Service Server Management ([MS-DNSP])
The DNS management interface (`50abc2a4-574d-40b3-9d66-ee4fd5fba076`) exposed over `\PIPE\DNSSERVER` allows configuring DNS service parameters. An attacker with administrative credentials or specific delegated rights can abuse the `ServerLevelPluginDll` feature over SMB to load an arbitrary DLL into the DNS service process, resulting in SYSTEM code execution. Blocking this interface over `ncacn_np` forces DNS management through TCP/IP RPC or PowerShell from authorized administration consoles.

#### 7. File Server Remote VSS Protocol ([MS-FSRVP])
Exposed over `\PIPE\FssagentRpc` (`a8e0653c-2744-4389-a61d-7373df8b2292`), MS-FSRVP was vulnerable to the ShadowCoerce coercion attack. While patched in KB5015527, blocking this interface over `ncacn_np` guarantees that any dormant or revived shadow copy coercion primitives cannot be triggered over SMB named pipes.

---

## Legacy Impact & Compatibility
* **Remote Administration Impact**: Applying these filters will block remote administration of services (`sc.exe`), scheduled tasks (`schtasks.exe`), and event logs when executed from remote member servers using named pipe transports. Administrators must connect using secure TCP/IP management transports (`ncacn_ip_tcp`), PowerShell Remoting (WinRM), or remote MMC consoles hosted on authorized PAWs.
* **GPO Startup Dependencies**: Windows does not provide a native GPO Graphical User Interface (GUI) node for configuring Windows Firewall RPC Filters. Therefore, these filters must be deployed via Netsh definition files imported during computer startup scripts.
* **Firewall Filter Engine Persistence**: Netsh RPC filters are maintained in the Windows Filtering Platform (WFP) engine. To ensure rules remain active after system updates and reboots, the import script must run on every startup.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

#### 1. Create the RPC Filters Definition File
Create a text file named `RpcNamedPipesFilters.txt` containing the following Netsh commands:

```text
rpc filter

# [MS-SCMR] Block Service Control Manager over SMB named pipes (\PIPE\svcctl)
add rule layer=um actiontype=block filterkey=d0c7640c-9355-4e52-8335-c12835559c10
add condition field=protocol matchtype=equal data=ncacn_np
add condition field=if_uuid matchtype=equal data=367ABB81-9844-35F1-AD32-98F038001003
add filter

# [MS-TSCH] Block Task Scheduler Remoting over SMB named pipes (\PIPE\atsvc)
add rule layer=um actiontype=block filterkey=a43b9dd2-0866-4476-89dc-2e9b200762af
add condition field=protocol matchtype=equal data=ncacn_np
add condition field=if_uuid matchtype=equal data=86D35949-83C9-4044-B424-DB363231FD0C
add filter

# [MS-TSCH] Block Task Scheduler Legacy at.exe interface 1 (All transports)
add rule layer=um actiontype=block filterkey=13518c11-e3d8-4f62-9461-eda11beb540a
add condition field=if_uuid matchtype=equal data=1FF70682-0A51-30E8-076D-740BE8CEE98B
add filter

# [MS-TSCH] Block Task Scheduler Legacy at.exe interface 2 (All transports)
add rule layer=um actiontype=block filterkey=1c079a18-e91f-4698-9868-68a121490636
add condition field=if_uuid matchtype=equal data=378E52B0-C0A9-11CF-822D-00AA0051E40F
add filter

# [MS-EVEN6] Block EventLog v6.0 Remoting over SMB named pipes (\PIPE\eventlog)
add rule layer=um actiontype=block filterkey=dedffabf-db89-4177-be77-1954aa2c0b95
add condition field=protocol matchtype=equal data=ncacn_np
add condition field=if_uuid matchtype=equal data=f6beaff7-1e19-4fbb-9f8f-b89e2018337c
add filter

# [MS-EVEN] Block Legacy EventLog Remoting Protocol (All transports)
add rule layer=um actiontype=block filterkey=f7f68868-5f50-4cda-a18c-6a7a549652e7
add condition field=if_uuid matchtype=equal data=82273FDC-E32A-18C3-3F78-827929DC23EA
add filter

# [MS-DFSNM] Permit DFS Namespace Management exclusively for Domain Admins (\PIPE\netdfs)
add rule layer=um actiontype=permit filterkey=43873c58-e130-4ffb-8858-d259a673a917
add condition field=if_uuid matchtype=equal data=4FC742E0-4A10-11CF-8273-00AA004AE673
add condition field=remote_user_token matchtype=equal data=D:(A;;CC;;;DA)
add filter

# [MS-DFSNM] Block DFS Namespace Management for all other users
add rule layer=um actiontype=block filterkey=0a239867-73db-45e6-b287-d006fe3c8b18
add condition field=if_uuid matchtype=equal data=4FC742E0-4A10-11CF-8273-00AA004AE673
add filter

# [MS-RPRN] Block Print System Remote Protocol over SMB named pipes (\PIPE\spoolss)
add rule layer=um actiontype=block filterkey=7966512a-f2f4-4cb1-812d-d967ab83d28a
add condition field=protocol matchtype=equal data=ncacn_np
add condition field=if_uuid matchtype=equal data=12345678-1234-ABCD-EF00-0123456789AB
add filter

# [MS-EFSR] Permit EFSRPC via lsarpc only if Kerberos-authenticated and encrypted
add rule layer=um actiontype=permit filterkey=d71d00db-3eef-4935-bedf-20cf628abd9e
add condition field=if_uuid matchtype=equal data=c681d488-d850-11d0-8c52-00c04fd90f7e
add condition field=auth_type matchtype=equal data=16
add condition field=auth_level matchtype=equal data=6
add filter

# [MS-EFSR] Block unencrypted or unauthenticated EFSRPC via lsarpc
add rule layer=um actiontype=block filterkey=3a4cce27-a7fa-4248-b8b8-ef6439a2c0ff
add condition field=if_uuid matchtype=equal data=c681d488-d850-11d0-8c52-00c04fd90f7e
add filter

# [MS-EFSR] Permit EFSRPC via efsrpc only if Kerberos-authenticated and encrypted
add rule layer=um actiontype=permit filterkey=c5cf8020-c83c-4803-9241-8c7f3b10171f
add condition field=if_uuid matchtype=equal data=df1941c5-fe89-4e79-bf10-463657acf44d
add condition field=auth_type matchtype=equal data=16
add condition field=auth_level matchtype=equal data=6
add filter

# [MS-EFSR] Block unencrypted or unauthenticated EFSRPC via efsrpc
add rule layer=um actiontype=block filterkey=9ad23a91-085d-4f99-ae15-85e0ad801278
add condition field=if_uuid matchtype=equal data=df1941c5-fe89-4e79-bf10-463657acf44d
add filter

# [MS-DNSP] Block DNS Server Management over SMB named pipes (\PIPE\DNSSERVER)
add rule layer=um actiontype=block filterkey=50754fe4-aa2d-42ff-8196-e90ea8fd2527
add condition field=protocol matchtype=equal data=ncacn_np
add condition field=if_uuid matchtype=equal data=50abc2a4-574d-40b3-9d66-ee4fd5fba076
add filter

# Block default Mimikatz MimiCom C2 interface (All transports)
add rule layer=um actiontype=block filterkey=644291ca-9530-4066-b654-e7b838ebdc06
add condition field=if_uuid matchtype=equal data=17FC11E9-C258-4B8D-8D07-2F4125156244
add filter

# [MS-FSRVP] Block File Server Remote VSS Protocol over SMB named pipes (\PIPE\FssagentRpc)
add rule layer=um actiontype=block filterkey=5270da6b-67a8-4cbf-8b2c-fa5d0abcb975
add condition field=protocol matchtype=equal data=ncacn_np
add condition field=if_uuid matchtype=equal data=a8e0653c-2744-4389-a61d-7373df8b2292
add filter
```

#### 2. Deploy via GPO Startup Script
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the target Domain Controllers hardening GPO.
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Scripts (Startup)`
4. Save `RpcNamedPipesFilters.txt` inside the GPO's Startup folder.
5. Create a batch script named `Import-RpcFilters.bat` in the same directory:
   ```cmd
   @echo off
   rem Import Windows Firewall RPC Named Pipe filters
   netsh.exe -f "%~dp0RpcNamedPipesFilters.txt"
   ```
6. Add `Import-RpcFilters.bat` to the GPO Startup Scripts list.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following scripts locally to deploy or verify the RPC named pipe filters.

#### Remediation Script:
[Download Script: Set-RpcNamedPipeFilters.ps1](implementation_scripts/Set-RpcNamedPipeFilters.ps1)

```powershell
# Set-RpcNamedPipeFilters.ps1
# Description: Generates and imports RPC filters to block remote management and coercion over SMB named pipes.

Write-Host "Applying hardening requirement: Configure RPC Named Pipe Filters..." -ForegroundColor Cyan

# Define the path where the filters file will be written
$FilterFilePath = Join-Path $env:TEMP "RpcNamedPipesFilters.txt"

# Write the netsh RPC filter commands
$FilterContent = @"
rpc filter

# [MS-SCMR] Block Service Control Manager over SMB named pipes (\PIPE\svcctl)
add rule layer=um actiontype=block filterkey=d0c7640c-9355-4e52-8335-c12835559c10
add condition field=protocol matchtype=equal data=ncacn_np
add condition field=if_uuid matchtype=equal data=367ABB81-9844-35F1-AD32-98F038001003
add filter

# [MS-TSCH] Block Task Scheduler Remoting over SMB named pipes (\PIPE\atsvc)
add rule layer=um actiontype=block filterkey=a43b9dd2-0866-4476-89dc-2e9b200762af
add condition field=protocol matchtype=equal data=ncacn_np
add condition field=if_uuid matchtype=equal data=86D35949-83C9-4044-B424-DB363231FD0C
add filter

# [MS-TSCH] Block Task Scheduler Legacy at.exe interface 1 (All transports)
add rule layer=um actiontype=block filterkey=13518c11-e3d8-4f62-9461-eda11beb540a
add condition field=if_uuid matchtype=equal data=1FF70682-0A51-30E8-076D-740BE8CEE98B
add filter

# [MS-TSCH] Block Task Scheduler Legacy at.exe interface 2 (All transports)
add rule layer=um actiontype=block filterkey=1c079a18-e91f-4698-9868-68a121490636
add condition field=if_uuid matchtype=equal data=378E52B0-C0A9-11CF-822D-00AA0051E40F
add filter

# [MS-EVEN6] Block EventLog v6.0 Remoting over SMB named pipes (\PIPE\eventlog)
add rule layer=um actiontype=block filterkey=dedffabf-db89-4177-be77-1954aa2c0b95
add condition field=protocol matchtype=equal data=ncacn_np
add condition field=if_uuid matchtype=equal data=f6beaff7-1e19-4fbb-9f8f-b89e2018337c
add filter

# [MS-EVEN] Block Legacy EventLog Remoting Protocol (All transports)
add rule layer=um actiontype=block filterkey=f7f68868-5f50-4cda-a18c-6a7a549652e7
add condition field=if_uuid matchtype=equal data=82273FDC-E32A-18C3-3F78-827929DC23EA
add filter

# [MS-DFSNM] Permit DFS Namespace Management exclusively for Domain Admins (\PIPE\netdfs)
add rule layer=um actiontype=permit filterkey=43873c58-e130-4ffb-8858-d259a673a917
add condition field=if_uuid matchtype=equal data=4FC742E0-4A10-11CF-8273-00AA004AE673
add condition field=remote_user_token matchtype=equal data=D:(A;;CC;;;DA)
add filter

# [MS-DFSNM] Block DFS Namespace Management for all other users
add rule layer=um actiontype=block filterkey=0a239867-73db-45e6-b287-d006fe3c8b18
add condition field=if_uuid matchtype=equal data=4FC742E0-4A10-11CF-8273-00AA004AE673
add filter

# [MS-RPRN] Block Print System Remote Protocol over SMB named pipes (\PIPE\spoolss)
add rule layer=um actiontype=block filterkey=7966512a-f2f4-4cb1-812d-d967ab83d28a
add condition field=protocol matchtype=equal data=ncacn_np
add condition field=if_uuid matchtype=equal data=12345678-1234-ABCD-EF00-0123456789AB
add filter

# [MS-EFSR] Permit EFSRPC via lsarpc only if Kerberos-authenticated and encrypted
add rule layer=um actiontype=permit filterkey=d71d00db-3eef-4935-bedf-20cf628abd9e
add condition field=if_uuid matchtype=equal data=c681d488-d850-11d0-8c52-00c04fd90f7e
add condition field=auth_type matchtype=equal data=16
add condition field=auth_level matchtype=equal data=6
add filter

# [MS-EFSR] Block unencrypted or unauthenticated EFSRPC via lsarpc
add rule layer=um actiontype=block filterkey=3a4cce27-a7fa-4248-b8b8-ef6439a2c0ff
add condition field=if_uuid matchtype=equal data=c681d488-d850-11d0-8c52-00c04fd90f7e
add filter

# [MS-EFSR] Permit EFSRPC via efsrpc only if Kerberos-authenticated and encrypted
add rule layer=um actiontype=permit filterkey=c5cf8020-c83c-4803-9241-8c7f3b10171f
add condition field=if_uuid matchtype=equal data=df1941c5-fe89-4e79-bf10-463657acf44d
add condition field=auth_type matchtype=equal data=16
add condition field=auth_level matchtype=equal data=6
add filter

# [MS-EFSR] Block unencrypted or unauthenticated EFSRPC via efsrpc
add rule layer=um actiontype=block filterkey=9ad23a91-085d-4f99-ae15-85e0ad801278
add condition field=if_uuid matchtype=equal data=df1941c5-fe89-4e79-bf10-463657acf44d
add filter

# [MS-DNSP] Block DNS Server Management over SMB named pipes (\PIPE\DNSSERVER)
add rule layer=um actiontype=block filterkey=50754fe4-aa2d-42ff-8196-e90ea8fd2527
add condition field=protocol matchtype=equal data=ncacn_np
add condition field=if_uuid matchtype=equal data=50abc2a4-574d-40b3-9d66-ee4fd5fba076
add filter

# Block default Mimikatz MimiCom C2 interface (All transports)
add rule layer=um actiontype=block filterkey=644291ca-9530-4066-b654-e7b838ebdc06
add condition field=if_uuid matchtype=equal data=17FC11E9-C258-4B8D-8D07-2F4125156244
add filter

# [MS-FSRVP] Block File Server Remote VSS Protocol over SMB named pipes (\PIPE\FssagentRpc)
add rule layer=um actiontype=block filterkey=5270da6b-67a8-4cbf-8b2c-fa5d0abcb975
add condition field=protocol matchtype=equal data=ncacn_np
add condition field=if_uuid matchtype=equal data=a8e0653c-2744-4389-a61d-7373df8b2292
add filter
"@

# Write filters to temp file
Set-Content -Path $FilterFilePath -Value $FilterContent -Encoding Ascii
Write-Host "[+] Generated RPC filters definition file at: $FilterFilePath" -ForegroundColor Gray

# Import filters using netsh (requires administrative elevation)
Write-Host "[+] Importing RPC filters using Netsh..." -ForegroundColor Gray
$Proc = Start-Process -FilePath "netsh.exe" -ArgumentList "-f `"$FilterFilePath`"" -Wait -NoNewWindow -PassThru

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

# Query active RPC filters
$filters = netsh.exe rpc filter show filter

# Define expected RPC filter rules with their metadata
$expectedRules = @(
    @{ FilterKey = "d0c7640c-9355-4e52-8335-c12835559c10"; Name = "MS-SCMR Service Control Manager (Block ncacn_np)"; Pipe = "\PIPE\svcctl" }
    @{ FilterKey = "a43b9dd2-0866-4476-89dc-2e9b200762af"; Name = "MS-TSCH Task Scheduler Remoting (Block ncacn_np)"; Pipe = "\PIPE\atsvc" }
    @{ FilterKey = "13518c11-e3d8-4f62-9461-eda11beb540a"; Name = "MS-TSCH Task Scheduler Legacy AT 1 (Block All)"; Pipe = "\PIPE\atsvc" }
    @{ FilterKey = "1c079a18-e91f-4698-9868-68a121490636"; Name = "MS-TSCH Task Scheduler Legacy AT 2 (Block All)"; Pipe = "\PIPE\atsvc" }
    @{ FilterKey = "dedffabf-db89-4177-be77-1954aa2c0b95"; Name = "MS-EVEN6 EventLog v6.0 Remoting (Block ncacn_np)"; Pipe = "\PIPE\eventlog" }
    @{ FilterKey = "f7f68868-5f50-4cda-a18c-6a7a549652e7"; Name = "MS-EVEN EventLog Legacy (Block All)"; Pipe = "\PIPE\eventlog" }
    @{ FilterKey = "43873c58-e130-4ffb-8858-d259a673a917"; Name = "MS-DFSNM DFS Namespace Mgmt (Permit Domain Admins)"; Pipe = "\PIPE\netdfs" }
    @{ FilterKey = "0a239867-73db-45e6-b287-d006fe3c8b18"; Name = "MS-DFSNM DFS Namespace Mgmt (Block Others)"; Pipe = "\PIPE\netdfs" }
    @{ FilterKey = "7966512a-f2f4-4cb1-812d-d967ab83d28a"; Name = "MS-RPRN Print System Remote (Block ncacn_np)"; Pipe = "\PIPE\spoolss" }
    @{ FilterKey = "d71d00db-3eef-4935-bedf-20cf628abd9e"; Name = "MS-EFSR via lsarpc (Permit Kerberos Encrypted)"; Pipe = "\PIPE\lsarpc" }
    @{ FilterKey = "3a4cce27-a7fa-4248-b8b8-ef6439a2c0ff"; Name = "MS-EFSR via lsarpc (Block Others)"; Pipe = "\PIPE\lsarpc" }
    @{ FilterKey = "c5cf8020-c83c-4803-9241-8c7f3b10171f"; Name = "MS-EFSR via efsrpc (Permit Kerberos Encrypted)"; Pipe = "\PIPE\efsrpc" }
    @{ FilterKey = "9ad23a91-085d-4f99-ae15-85e0ad801278"; Name = "MS-EFSR via efsrpc (Block Others)"; Pipe = "\PIPE\efsrpc" }
    @{ FilterKey = "50754fe4-aa2d-42ff-8196-e90ea8fd2527"; Name = "MS-DNSP DNS Server Remote Mgmt (Block ncacn_np)"; Pipe = "\PIPE\DNSSERVER" }
    @{ FilterKey = "644291ca-9530-4066-b654-e7b838ebdc06"; Name = "MimiCom Mimikatz Remote C2 (Block All)"; Pipe = "Any" }
    @{ FilterKey = "5270da6b-67a8-4cbf-8b2c-fa5d0abcb975"; Name = "MS-FSRVP File Server Remote VSS (Block ncacn_np)"; Pipe = "\PIPE\FssagentRpc" }
)

$missingFilters = @()
$activeFiltersCount = 0

# Join netsh output into a single string for fast and case-insensitive matching
$rawFiltersOutput = ($filters -join "`n").ToLowerInvariant()

foreach ($rule in $expectedRules) {
    $targetKey = $rule.FilterKey.ToLowerInvariant()
    if ($rawFiltersOutput.Contains($targetKey)) {
        $activeFiltersCount++
        Write-Host "[+] Active: $($rule.Name) [Key: $($rule.FilterKey)]" -ForegroundColor Green
    } else {
        $missingFilters += $rule
        Write-Host "[-] Missing: $($rule.Name) [Key: $($rule.FilterKey)]" -ForegroundColor Yellow
    }
}

Write-Host "`nSummary: $activeFiltersCount of $($expectedRules.Count) expected RPC filters are active." -ForegroundColor Cyan

if ($missingFilters.Count -eq 0) {
    Write-Host "[+] All 16 RPC named pipe filters are active and enforced." -ForegroundColor Green
    Write-Host "Audit result: COMPLIANT" -ForegroundColor Green
} else {
    Write-Host "[!] NON-COMPLIANT: $($missingFilters.Count) RPC named pipe filter rule(s) are missing or inactive." -ForegroundColor Red
    Write-Host "Audit result: NON-COMPLIANT" -ForegroundColor Red
}
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Recommendation R7 (Filtering and IPsec on Domain Controllers), Recommendation R8 (Administration network subnets / filtering rules)
* **CIS Benchmark**: Section 19 (Windows Defender Firewall with Advanced Security)
* **DSInternals AD Firewall Guide (Michael Grafnetter)**: [Active Directory Firewall - Domain Controller Firewall](https://firewall.dsinternals.com/ADDS/)
* **Microsoft Open Specifications**:
  * [MS-RPCE]: [Remote Procedure Call Protocol Extensions](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/290c38b1-1c03-4677-96a3-27ea0249d40f)
  * [MS-SCMR]: [Service Control Manager Remote Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/705b624a-13de-43cc-b8a2-99573da3635f)
  * [MS-TSCH]: [Task Scheduler Service Remoting Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsch/d1058a28-7e02-4948-8b8d-4a347fa64931)
  * [MS-EVEN6]: [EventLog Remoting Protocol Version 6.0](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even6/18000371-ae6d-45f7-95f3-249cbe2be39b)
  * [MS-EVEN]: [EventLog Remoting Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f)
  * [MS-DFSNM]: [Distributed File System (DFS): Namespace Management Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsnm/95a506a8-cae6-4c42-b19d-9c1ed1223979)
  * [MS-RPRN]: [Print System Remote Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/d42db7d5-f141-4466-8f47-0a4be14e2fc1)
  * [MS-EFSR]: [Encrypting File System Remote (EFSRPC) Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31)
  * [MS-DNSP]: [Domain Name Service (DNS) Server Management Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/f97756c9-3783-428b-9451-b376f877319a)
  * [MS-FSRVP]: [File Server Remote VSS Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsrvp/dae107ec-8198-4778-a950-faa7edad125b)
* **Security Advisories & Vulnerability References**:
  * [CVE-2025-29969]: [MS-EVEN RPC Remote Code Execution Vulnerability](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-29969)
  * [CVE-2021-36942]: [Windows LSA Spoofing Vulnerability (PetitPotam)](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36942)
