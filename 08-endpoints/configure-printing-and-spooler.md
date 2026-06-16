# [REQ-END-025] Configure Secure Printing and Print Spooler Policies

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers.
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional, Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **System Service GPO**: `Computer Configuration\Policies\Windows Settings\Security Settings\System Services\Print Spooler` -> Service Startup Mode: **Disabled**
  * **Limits print driver installation to Administrators GPO**: `Computer Configuration\Policies\Administrative Templates\Printers\Limits print driver installation to Administrators` -> Enabled
  * **Registry Location (Service)**: `HKLM\SYSTEM\CurrentControlSet\Services\Spooler` -> `Start` = `4` (REG_DWORD)
  * **Registry Location (Printers)**: `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers`
  * **Registry Location (Point and Print)**: `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint` -> `RestrictDriverInstallationToAdministrators` = `1` (REG_DWORD)
  * **Registry Location (Print Control)**: `HKLM\SYSTEM\CurrentControlSet\Control\Print`

---

## Rationale
The Windows Print Spooler service (`Spooler`) has been the source of numerous high-severity vulnerabilities (such as the PrintNightmare family - CVE-2021-1675 and CVE-2021-34527). Attackers exploit the Print Spooler to coerce authentication or execute arbitrary code with SYSTEM privileges.

To secure standard client endpoints and member servers, the primary defense is to **completely disable the Print Spooler service**. This eliminates the service's attack surface. As a secondary defense-in-depth, additional printer registry configurations (such as restricting driver installation to administrators, Redirection Guard, and RPC connection configurations) are enforced to ensure that even if the spooler service is temporarily running, the subsystem remains hardened.

1. **Remote Connections Block**: By disabling remote client connections to the print spooler, standard client endpoints are prevented from acting as print servers. Outbound printing remains unaffected, but external hosts can no longer target the workstation's print spooler over the network.
2. **Redirection Guard**: Enabling Redirection Guard prevents print spooler processing from being redirected via symbolic links or junction points, mitigating local privilege escalation vectors that abuse file system paths during printer driver mapping.
3. **RPC over TCP**: Forcing both incoming and outgoing RPC connections to use TCP instead of legacy Named Pipes (which can be easily hijacked or relayed) reduces the attack surface. Forcing packet-level privacy and authentication protocols ensures printing traffic is encrypted and authenticated.
4. **Point and Print Restrictions**: Restricting driver installation and update prompts to administrators prevents non-privileged users from installing malicious or unverified printer drivers.

---

## Legacy Impact & Compatibility
* **No Printing Support**: Printing from client workstations is completely disabled. Standard users will be unable to print documents to network or local printers. This matches the security requirements of high-security air-gapped environments where physical document flows must be restricted.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

#### 1. Disable the Print Spooler Service
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the GPO applied to client endpoints (e.g., `GPO_Hardening_Endpoints`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\System Services`
4. Double-click **Print Spooler**.
5. Check **Define this policy setting** and select **Disabled**. Click **OK**.

#### 2. Configure Printers GPO Hardening (Secondary Defense)
1. Navigate to: `Computer Configuration\Policies\Administrative Templates\Printers`
2. Configure the following policies:
   * **Allow Print Spooler to accept client connections**: Set to `Disabled`
   * **Configure Redirection Guard**: Set to `Enabled`, select `Redirection Guard Enabled`
   * **Configure RPC connection settings**: Set to `Enabled`
     * Protocol to use for outgoing RPC connections: `RPC over TCP`
     * Use authentication for outgoing RPC connections: `Default`
   * **Configure RPC listener settings**: Set to `Enabled`
     * Protocols to allow for incoming RPC connections: `RPC over TCP`
     * Authentication protocol to use for incoming RPC connections: `Negotiate` (or higher)
   * **Configure RPC over TCP port**: Set to `Enabled`, set Port to `0` (dynamic port allocation)
   * **Configure RPC packet level privacy setting for incoming connections**: Set to `Enabled` *(Note: Requires `SecGuide.admx` template)*
   * **Manage processing of Queue-specific files**: Set to `Enabled`, select `Limit Queue-specific files to Color profiles`
   * **Point and Print Restrictions**: Set to `Enabled`
     * When installing drivers for a new connection: `Show warning and elevation prompt`
     * When updating drivers for an existing connection: `Show warning and elevation prompt`
   * **Limits print driver installation to Administrators**: Set to `Enabled`

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure registry keys for print spooler hardening.

[Download Script: Configure-PrintingAndSpooler.ps1](implementation_scripts/Configure-PrintingAndSpooler.ps1)

```powershell
# Configure-PrintingAndSpooler.ps1
# Description: Disables the Print Spooler service and configures secondary print registry hardening parameters on standard endpoints.

Write-Host "Applying Print Spooler security hardening..." -ForegroundColor Cyan

# 1. Disable the Print Spooler Service
if (Get-Service -Name "Spooler" -ErrorAction SilentlyContinue) {
    Set-Service -Name "Spooler" -StartupType Disabled -Confirm:$false
    Stop-Service -Name "Spooler" -Force -Confirm:$false
    Write-Host "[+] Print Spooler service has been stopped and disabled." -ForegroundColor Green
}

# 1. Base Printers Path Policies
$PrintersPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"
if (-not (Test-Path $PrintersPath)) {
    New-Item -Path $PrintersPath -Force | Out-Null
}

# Allow Print Spooler to accept client connections -> Disabled
Set-ItemProperty -Path $PrintersPath -Name "RegisterSpoolerRemoteRpcEndPoint" -Value 2 -Type Dword
Set-ItemProperty -Path $PrintersPath -Name "RegisterSpoolerRemoteSubsystem" -Value 0 -Type Dword

# Configure Redirection Guard -> Enabled: Redirection Guard Enabled
Set-ItemProperty -Path $PrintersPath -Name "RedirectionguardPolicy" -Value 1 -Type Dword

# Manage processing of Queue-specific files -> Enabled: Limit Queue-specific files to Color profiles
Set-ItemProperty -Path $PrintersPath -Name "CopyFilesPolicy" -Value 1 -Type Dword

# 2. Printers RPC Connection and Listener Policies
$PrintersRpcPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC"
if (-not (Test-Path $PrintersRpcPath)) {
    New-Item -Path $PrintersRpcPath -Force | Out-Null
}

# Protocol to use for outgoing RPC connections -> RPC over TCP (0)
Set-ItemProperty -Path $PrintersRpcPath -Name "RpcUseNamedPipeProtocol" -Value 0 -Type Dword

# Use authentication for outgoing RPC connections -> Default (0)
Set-ItemProperty -Path $PrintersRpcPath -Name "RpcAuthentication" -Value 0 -Type Dword

# Protocols to allow for incoming RPC connections -> RPC over TCP (5)
Set-ItemProperty -Path $PrintersRpcPath -Name "RpcProtocols" -Value 5 -Type Dword

# Authentication protocol to use for incoming RPC connections -> Negotiate (0)
Set-ItemProperty -Path $PrintersRpcPath -Name "ForceKerberosForRpc" -Value 0 -Type Dword

# Configure RPC over TCP port -> 0
Set-ItemProperty -Path $PrintersRpcPath -Name "RpcTcpPort" -Value 0 -Type Dword

# 3. System Print Control Privacy Setting
$PrintControlPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Print"
if (-not (Test-Path $PrintControlPath)) {
    New-Item -Path $PrintControlPath -Force | Out-Null
}

# Configure RPC packet level privacy setting for incoming connections -> Enabled
Set-ItemProperty -Path $PrintControlPath -Name "RpcAuthnLevelPrivacyEnabled" -Value 1 -Type Dword

# 4. Point and Print Restrictions
$PointPrintPath = "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
if (-not (Test-Path $PointPrintPath)) {
    New-Item -Path $PointPrintPath -Force | Out-Null
}

Set-ItemProperty -Path $PointPrintPath -Name "RestrictPointAndPrint" -Value 1 -Type Dword
Set-ItemProperty -Path $PointPrintPath -Name "NoWarningNoElevationOnInstall" -Value 0 -Type Dword
Set-ItemProperty -Path $PointPrintPath -Name "UpdatePromptSettings" -Value 0 -Type Dword
Set-ItemProperty -Path $PointPrintPath -Name "RestrictDriverInstallationToAdministrators" -Value 1 -Type Dword

Write-Host "[+] Print Spooler and Printer configurations hardened successfully." -ForegroundColor Green
```

*To verify the print spooler policy settings:*

[Download Script: Get-PrintingAndSpoolerStatus.ps1](audit_scripts/Get-PrintingAndSpoolerStatus.ps1)

```powershell
# Get-PrintingAndSpoolerStatus.ps1
# Description: Audits print spooler and printer security configurations on the local system.

Write-Host "--- Auditing Printing and Spooler Hardening ---" -ForegroundColor Cyan

$script:Vulnerable = $false

# 1. Audit Spooler Service Startup Type
$Service = Get-Service -Name "Spooler" -ErrorAction SilentlyContinue
if ($null -ne $Service) {
    $StartupType = (Get-CimInstance -ClassName Win32_Service -Filter "Name='Spooler'").StartMode
    $Color = if ($StartupType -eq "Disabled") { "Green" } else { "Red" }
    Write-Host "  [-] Print Spooler Service Startup: $StartupType (Expected: Disabled)" -ForegroundColor $Color
    if ($StartupType -ne "Disabled") {
        $script:Vulnerable = $true
    }
} else {
    Write-Host "  [+] Print Spooler Service is not present on this machine." -ForegroundColor Green
}

# Helper function to audit registry properties
function Test-RegistryValue {
    param(
        [string]$Path,
        [string]$Name,
        [object]$ExpectedValue
    )
    if (Test-Path $Path) {
        $Val = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        if ($null -ne $Val) {
            $Actual = $Val.$Name
            if ($Actual -eq $ExpectedValue) {
                Write-Host "  - Path: $Path | Value: $Name | Current: $Actual (Expected: $ExpectedValue)" -ForegroundColor Green
            } else {
                Write-Host "  [!] MISMATCH: Path: $Path | Value: $Name | Current: $Actual (Expected: $ExpectedValue)" -ForegroundColor Red
                $script:Vulnerable = $true
            }
        } else {
            Write-Host "  [!] MISSING VALUE: Path: $Path | Value: $Name (Expected: $ExpectedValue)" -ForegroundColor Red
            $script:Vulnerable = $true
        }
    } else {
        Write-Host "  [!] MISSING KEY: Path: $Path (Expected: $Name = $ExpectedValue)" -ForegroundColor Red
        $script:Vulnerable = $true
    }
}

# Audit base printer settings
$PrintersPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"
Test-RegistryValue -Path $PrintersPath -Name "RegisterSpoolerRemoteRpcEndPoint" -ExpectedValue 2
Test-RegistryValue -Path $PrintersPath -Name "RegisterSpoolerRemoteSubsystem" -ExpectedValue 0
Test-RegistryValue -Path $PrintersPath -Name "RedirectionguardPolicy" -ExpectedValue 1
Test-RegistryValue -Path $PrintersPath -Name "CopyFilesPolicy" -ExpectedValue 1

# Audit RPC settings
$PrintersRpcPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC"
Test-RegistryValue -Path $PrintersRpcPath -Name "RpcUseNamedPipeProtocol" -ExpectedValue 0
Test-RegistryValue -Path $PrintersRpcPath -Name "RpcAuthentication" -ExpectedValue 0
Test-RegistryValue -Path $PrintersRpcPath -Name "RpcProtocols" -ExpectedValue 5
Test-RegistryValue -Path $PrintersRpcPath -Name "ForceKerberosForRpc" -ExpectedValue 0
Test-RegistryValue -Path $PrintersRpcPath -Name "RpcTcpPort" -ExpectedValue 0

# Audit Print Control
$PrintControlPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Print"
Test-RegistryValue -Path $PrintControlPath -Name "RpcAuthnLevelPrivacyEnabled" -ExpectedValue 1

# Audit Point and Print
$PointPrintPath = "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
Test-RegistryValue -Path $PointPrintPath -Name "RestrictPointAndPrint" -ExpectedValue 1
Test-RegistryValue -Path $PointPrintPath -Name "NoWarningNoElevationOnInstall" -ExpectedValue 0
Test-RegistryValue -Path $PointPrintPath -Name "UpdatePromptSettings" -ExpectedValue 0
Test-RegistryValue -Path $PointPrintPath -Name "RestrictDriverInstallationToAdministrators" -ExpectedValue 1

if ($script:Vulnerable) {
    Write-Host "Audit Result: VULNERABLE" -ForegroundColor Red
    exit 1
} else {
    Write-Host "Audit Result: SECURE" -ForegroundColor Green
    exit 0
}
```

---

## Sources & Compliance References
* **CIS Microsoft Windows Client Benchmark**: Section 18.7.1 to 18.7.8, Section 18.7.10 to 18.7.12 (Printing security settings)
* **ANSSI Active Directory Hardening Guide**: Recommendations on disabling spooler remote calls to prevent coercive authentication
* **Microsoft Security Guidance**: Point and Print Restrictions (CVE-2021-34527 mitigation details)
