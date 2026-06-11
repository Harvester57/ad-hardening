# Hardening Requirement: Enforce RDP Restricted Admin Mode

## Target Scope
* **Applicable Systems**: Domain Controllers, Member Servers, Tier 2 Clients, PAWs
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022, Windows 10/11 Enterprise

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**: 
  * **Client Configuration (GPO)**: `Computer Configuration\Policies\Administrative Templates\System\Credentials Delegation\Restrict delegation of credentials to remote servers` -> Enabled (Require Restricted Admin)
  * **Server Configuration (Registry)**: `HKLM:\System\CurrentControlSet\Control\Lsa\DisableRestrictedAdmin` -> `0` (DWORD)

---

## Rationale
Remote Desktop Protocol (RDP) is a standard tool for administrative sessions. However, by default, RDP authenticates users by placing their credentials (NTLM hashes or Kerberos tickets) directly in the Local Security Authority Subsystem Service (LSASS) memory of the destination host. 

If an administrator connects to a compromised host (such as a Tier 1 server or Tier 2 workstation) from their workstation using standard RDP, an attacker with local administrator privileges on that target system can dump LSASS and harvest the administrator's credentials. This allows the attacker to compromise the administrator's account and move laterally or escalate privileges.

Enforcing RDP Restricted Admin Mode (RDP RA) prevents credential harvesting:
1. **Blocks Credential Transmission**: Under Restricted Admin mode, the client does not send the user's plaintext password, NTLM hash, or Kerberos TGT to the remote host. The host validates the connection without caching reusable credentials in its LSASS database.
2. **Limits Remote Session Privilege**: In network access attempts initiated from within the RDP session, the remote session runs in the security context of the destination machine's computer account (`$MachineName$`) rather than the administrator's user account.

---

## Legacy Impact & Compatibility
* **No Network SSO**: Because the remote session lacks the user's credentials, the administrator cannot access other network shares or Active Directory resources (such as mapped drives or remote management tools) from *within* the RDP session. Any cross-machine administrative tasks must be executed from the administrator's local management host using tools like RSAT or PowerShell Remoting rather than nested RDP.
* **Server Compatibility**: Target servers must support Restricted Admin Mode (supported natively on Windows Server 2012 R2 and later).

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration

#### 1. Enforce Client-Side Connection Restriction (PAWs & Workstations)
To force administrative workstations to use Restricted Admin mode for all remote RDP sessions:

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Create or edit a GPO targeting administrative hosts (e.g., `GPO_Workstation_Hardening`).
3. Navigate to:
   `Computer Configuration\Policies\Administrative Templates\System\Credentials Delegation`
4. Double-click the **Restrict delegation of credentials to remote servers** policy.
5. Set it to **Enabled**.
6. In the options dropdown, select **Require Restricted Admin**.
7. Click **OK** and link the GPO to your PAW / Workstation OUs.

#### 2. Configure Server-Side Support (Domain Controllers & Member Servers)
Ensure that all target hosts are configured to permit Restricted Admin connections:

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Create or edit a GPO targeting servers (e.g., `GPO_Server_Hardening`).
3. Navigate to:
   `Computer Configuration\Policies\Administrative Templates\System\Credentials Delegation`
4. Double-click **Restrict delegation of credentials to remote servers**.
5. Set it to **Enabled**.
6. Select **Require Remote Credential Guard or Restricted Admin** (or **Require Restricted Admin**).
7. Click **OK** and link the GPO to your Domain Controllers and Member Servers OUs.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script to configure the local host registry to allow and enforce Restricted Admin mode.

```powershell
# Set-RdpRestrictedAdmin.ps1
# Description: Enables RDP Restricted Admin mode support on the local system.

Write-Host "Applying hardening requirement: Enforce RDP Restricted Admin Mode..." -ForegroundColor Cyan

$LsaPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
$ValueName = "DisableRestrictedAdmin"
$ValueData = 0 # 0 enables Restricted Admin support

if (Test-Path $LsaPath) {
    Set-ItemProperty -Path $LsaPath -Name $ValueName -Value $ValueData -Type DWord -ErrorAction Stop
    Write-Host "[+] Local system configured to accept RDP Restricted Admin connections." -ForegroundColor Green
} else {
    Write-Host "[-] Error: LSA Registry path not found." -ForegroundColor Red
}
```

*To verify the local RDP configuration status:*
```powershell
# Get-RdpRestrictedAdminStatus.ps1
# Description: Checks the configuration state of RDP Restricted Admin.

$LsaPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
$ValueName = "DisableRestrictedAdmin"

Write-Host "Checking local LSA registry settings..." -ForegroundColor Cyan

if (Test-Path $LsaPath) {
    $Value = Get-ItemProperty -Path $LsaPath -Name $ValueName -ErrorAction SilentlyContinue
    if ($null -ne $Value) {
        if ($Value.DisableRestrictedAdmin -eq 0) {
            Write-Host "[+] RDP Restricted Admin Mode: Enabled (Value = 0)." -ForegroundColor Green
        } else {
            Write-Host "[-] RDP Restricted Admin Mode: Disabled (Value = $($Value.DisableRestrictedAdmin))." -ForegroundColor Red
        }
    } else {
        Write-Host "[+] RDP Restricted Admin Mode: Enabled (Default state: No registry restriction)." -ForegroundColor Green
    }
}
```

*To establish a remote connection with Restricted Admin manually from the command line:*
```cmd
mstsc.exe /RestrictedAdmin
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Section 4.7, Section 4.9 (Connexions distantes), Annexe E
* **ANSSI Remediation of Active Directory Tier 0 Guide**: Section 10.g (Page 40), Section 5.1 (Page 104)
* **Microsoft Security Guidance**: Mitigating Pass-the-Hash Attacks - Section 4.3 (Restricted Admin RDP)
* **CIS Benchmark**: Section 18.4 (Credentials Delegation Configuration)
