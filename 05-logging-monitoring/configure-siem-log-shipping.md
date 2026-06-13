# [REQ-LOG-004] Configure Secure SIEM Log Shipping

## Target Scope
* **Applicable Systems**: Domain Controllers, Member Servers, Tier 2 Client Workstations.
* **Operating Systems**: Windows Server 2016 (and above), Windows 10/11 Enterprise.

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **Configuration Files**: 
    - Winlogbeat: `%ProgramFiles%\Winlogbeat\winlogbeat.yml`
    - Wazuh Agent: `%ProgramFiles(x86)%\ossec-agent\ossec.conf`
  * **System Services**: Winlogbeat, WazuhSvc

---

## Rationale
In high-security, isolated environments, local log storage is vulnerable to tampering. Attackers who obtain elevated privileges will attempt to clear or modify the Security Event Logs (e.g., via `wevtutil cl Security`) to destroy evidence of their activities. Shipping event logs in real-time to a dedicated offline SIEM (such as an ELK Stack or Wazuh Manager) ensures that forensic logs are preserved.

To prevent adversaries from intercepting, redirecting, or tampering with log telemetry, log shippers must be hardened:
1. **Secure Transportation (TLS)**: Enforce TLS 1.2 or TLS 1.3 encryption with strict verification of the server certificate authority. This prevents man-in-the-middle attacks where an adversary redirects logs to a rogue listener.
2. **Buffer and Queue Management**: Limit memory and disk spool queues for the shipping agents. If the SIEM receiver goes offline during maintenance or network failure, the agents must cache logs safely without causing memory leaks, high CPU overhead, or local disk exhaustion.
3. **Hardened Configuration Files**: Agent configurations contain hostnames, ports, and potentially credentials or internal CA paths. Restricting access to these configuration files prevents standard users from discovering SIEM endpoints or tampering with configuration parameters.

---

## Legacy Impact & Compatibility
* **PKI Dependencies**: Configuring full verification of the SSL/TLS certificate chain requires that the internal Active Directory Certificate Services (AD CS) CA certificate is distributed to all shipping agents and that the SIEM receiver possesses a certificate signed by this CA.
* **Network Overhead**: Encrypting and transmitting large volumes of security event logs introduces minor CPU and network utilization. Network links, especially in isolated subnets, must be monitored.

---

## Implementation Steps

### Option A: Agent Configuration

#### 1. Secure Winlogbeat Configuration
Edit `winlogbeat.yml` (located by default under `%ProgramFiles%\Winlogbeat\winlogbeat.yml`) to enforce TLS 1.2/1.3, configure local queue limits, and forward the key log channels:

```yaml
winlogbeat.event_logs:
  - name: Security
  - name: System
  - name: Microsoft-Windows-Sysmon/Operational
  - name: Microsoft-Windows-PowerShell/Operational

# Enforce disk-assisted memory queue limits to prevent memory exhaustion
queue.mem:
  events: 4096
  flush.min_events: 2048
  flush.timeout: 1s

# Output to Logstash/SIEM with TLS settings
output.logstash:
  hosts: ["local-logstash.internal.local:5044"]
  ssl.supported_protocols: [TLSv1.2, TLSv1.3]
  ssl.verification_mode: full
  ssl.certificate_authorities: ["C:\\ProgramData\\Winlogbeat\\certs\\ca.crt"]
  ssl.certificate: "C:\\ProgramData\\Winlogbeat\\certs\\client.crt"
  ssl.key: "C:\\ProgramData\\Winlogbeat\\certs\\client.key"
```

#### 2. Secure Wazuh Agent Configuration
Edit `ossec.conf` (located by default under `%ProgramFiles(x86)%\ossec-agent\ossec.conf`) to secure log verification and specify localized channels:

```xml
<ossec_config>
  <client>
    <server>
      <address>local-wazuh.internal.local</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
    <crypto_method>aes</crypto_method>
    <!-- Configure enrollment with validation -->
    <enrollment>
      <enabled>yes</enabled>
      <server_address>local-wazuh.internal.local</server_address>
      <port>1515</port>
      <ssl_cipher>HIGH</ssl_cipher>
      <ssl_verify_host>yes</ssl_verify_host>
      <ssl_cacert>C:\Program Files (x86)\ossec-agent\certs\wpk_root.pem</ssl_cacert>
    </enrollment>
  </client>

  <!-- Channels to Monitor -->
  <localfile>
    <location>Security</location>
    <log_format>eventlog</log_format>
  </localfile>
  <localfile>
    <location>System</location>
    <log_format>eventlog</log_format>
  </localfile>
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventlog</log_format>
  </localfile>
  <localfile>
    <location>Microsoft-Windows-PowerShell/Operational</location>
    <log_format>eventlog</log_format>
  </localfile>
</ossec_config>
```

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following scripts locally to secure agent configuration files and verify SIEM shipping services status.

[Download Script: Set-SiemLogShipping.ps1](implementation_scripts/Set-SiemLogShipping.ps1)

```powershell
# Set-SiemLogShipping.ps1
# Secures Winlogbeat and Wazuh log shipping configuration file ACLs.

Write-Host "--- Hardening SIEM Shipping Agent Configurations ---" -ForegroundColor Cyan

$ConfigFiles = @(
    "C:\Program Files\Winlogbeat\winlogbeat.yml",
    "C:\Program Files (x86)\ossec-agent\ossec.conf"
)

foreach ($File in $ConfigFiles) {
    if (Test-Path $File) {
        Write-Host "[+] Applying hardened NTFS permissions to $($File)..." -ForegroundColor Gray
        
        # Get ACL
        $Acl = Get-Acl -Path $File
        # Disable inheritance and copy existing rules
        $Acl.SetAccessRuleProtection($true, $true)
        Set-Acl -Path $File -AclObject $Acl
        
        # Refresh ACL
        $Acl = Get-Acl -Path $File
        $Rules = $Acl.Access
        
        # Remove any access rules for Users, Authenticated Users, Everyone
        foreach ($Rule in $Rules) {
            $Identity = $Rule.IdentityReference.Value
            if ($Identity -like "*Users" -or $Identity -like "*Authenticated Users" -or $Identity -like "*Everyone") {
                $Acl.RemoveAccessRule($Rule) | Out-Null
            }
        }
        
        # Explicitly ensure Administrators and SYSTEM have Full Control
        $FullRights = [System.Security.AccessControl.FileSystemRights]::FullControl
        $InheritanceFlags = [System.Security.AccessControl.InheritanceFlags]::None
        $PropagationFlags = [System.Security.AccessControl.PropagationFlags]::None
        $AccessType = [System.Security.AccessControl.AccessControlType]::Allow
        
        $AdminRule = New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators", $FullRights, $InheritanceFlags, $PropagationFlags, $AccessType)
        $SystemRule = New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM", $FullRights, $InheritanceFlags, $PropagationFlags, $AccessType)
        
        $Acl.AddAccessRule($AdminRule)
        $Acl.AddAccessRule($SystemRule)
        
        Set-Acl -Path $File -AclObject $Acl
        Write-Host "    Permissions successfully secured for $($File)." -ForegroundColor Green
    } else {
        Write-Verbose "    File $($File) not found, skipping."
    }
}
```

*To verify the settings have been applied:*

[Download Script: Test-SiemLogShipping.ps1](audit_scripts/Test-SiemLogShipping.ps1)

```powershell
# Test-SiemLogShipping.ps1
# Audits SIEM shipping agents, configuration permissions, and security.

Write-Host "--- Auditing SIEM Log Shipping Agents ---" -ForegroundColor Cyan

# 1. Audit Agent Services
$Services = @("winlogbeat", "WazuhSvc")
foreach ($SvcName in $Services) {
    $Svc = Get-Service -Name $SvcName -ErrorAction SilentlyContinue
    $Status = "Not Installed"
    if ($Svc) {
        $Status = $Svc.Status
    }
    $Color = if ($Status -eq "Running") { "Green" } else { "Yellow" }
    Write-Host "    - Agent Service '$($SvcName)': $($Status)" -ForegroundColor $Color
}

# 2. Audit Config File Access Permissions
$ConfigFiles = @(
    "C:\Program Files\Winlogbeat\winlogbeat.yml",
    "C:\Program Files (x86)\ossec-agent\ossec.conf"
)

foreach ($File in $ConfigFiles) {
    if (Test-Path $File) {
        $Acl = Get-Acl -Path $File
        $Rules = $Acl.Access
        $HasUnsafeAccess = $false
        
        foreach ($Rule in $Rules) {
            $Identity = $Rule.IdentityReference.Value
            $Type = $Rule.AccessControlType
            
            # Verify if users, authenticated users, or everyone has read/write
            if ($Type -eq "Allow" -and ($Identity -like "*Users" -or $Identity -like "*Authenticated Users" -or $Identity -like "*Everyone")) {
                $HasUnsafeAccess = $true
            }
        }
        
        $FileColor = if (-not $HasUnsafeAccess) { "Green" } else { "Red" }
        Write-Host "    - Configuration File: $($File) | UnsafeAccessAllowed=$($HasUnsafeAccess)" -ForegroundColor $FileColor
    } else {
        Write-Host "    - Configuration File: $($File) | Status: NOT FOUND" -ForegroundColor Yellow
    }
}
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Recommendation R52 (Sysmon and log shipping recommendations)
* **CIS Benchmark**: Recommended settings for centralized log shipping configurations
* **Wazuh Security Hardening Guidelines**: Transport encryption and configuration protection
