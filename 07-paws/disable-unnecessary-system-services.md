# Disable Unnecessary System Services for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration.
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\System Services`
  * **Registry Location**: `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\Start`

---

## Rationale
To minimize the attack surface of standard client endpoints and member servers, all unnecessary system services must be disabled. Operating system services that are not required for core administrative tasks or business functionality introduce unnecessary entry points for network exposure, resource utilization, and privilege escalation vulnerabilities.

On Tier 0 administrative workstations (PAWs), enforcing the principle of least functionality is even more critical.

---

## Legacy Impact & Compatibility
* **Infra Compatibility**: Administrative functions relying on legacy RPC Locator or SSDP-based discovery of network printers/devices may be affected.
* **WSL Functionality**: Disabling `LxssManager` prevents running Windows Subsystem for Linux (WSL) containers on PAWs. This is the desired security behavior, as PAWs should not host developer Linux kernels or unvetted container instances.
* **Mobile Hotspotting**: Disabling `icssvc` and `SharedAccess` prevents users from creating cellular hot-spotting configurations or sharing their network cards. This is a desired security behavior.

---

## Service Hardening Requirements

The following services must be stopped and disabled:

1. **[REQ-PAW-037 - Disable Computer Browser Service for PAWs (Browser)](services/disable-browser.md)**
2. **[REQ-PAW-038 - Disable Infrared Monitor Service for PAWs (irmon)](services/disable-irmon.md)**
3. **[REQ-PAW-039 - Disable Internet Connection Sharing (ICS) Service for PAWs (SharedAccess)](services/disable-sharedaccess.md)**
4. **[REQ-PAW-040 - Disable LxssManager Service for PAWs (LxssManager)](services/disable-lxssmanager.md)**
5. **[REQ-PAW-041 - Disable Microsoft FTP Service for PAWs (FTPSVC)](services/disable-ftpsvc.md)**
6. **[REQ-PAW-042 - Disable OpenSSH SSH Server Service for PAWs (sshd)](services/disable-sshd.md)**
7. **[REQ-PAW-043 - Disable Remote Procedure Call (RPC) Locator Service for PAWs (RpcLocator)](services/disable-rpclocator.md)**
8. **[REQ-PAW-044 - Disable Routing and Remote Access Service for PAWs (RemoteAccess)](services/disable-remoteaccess.md)**
9. **[REQ-PAW-045 - Disable Simple TCP/IP Services for PAWs (simptcp)](services/disable-simptcp.md)**
10. **[REQ-PAW-046 - Disable Special Administration Console Helper Service for PAWs (sacsvr)](services/disable-sacsvr.md)**
11. **[REQ-PAW-047 - Disable SSDP Discovery Service for PAWs (SSDPSRV)](services/disable-ssdpsrv.md)**
12. **[REQ-PAW-048 - Disable UPnP Device Host Service for PAWs (upnphost)](services/disable-upnphost.md)**
13. **[REQ-PAW-049 - Disable Web Management Service for PAWs (WMSvc)](services/disable-wmsvc.md)**
14. **[REQ-PAW-050 - Disable Windows Media Player Network Sharing Service for PAWs (WMPNetworkSvc)](services/disable-wmpnetworksvc.md)**
15. **[REQ-PAW-051 - Disable Windows Mobile Hotspot Service for PAWs (icssvc)](services/disable-icssvc.md)**
16. **[REQ-PAW-052 - Disable World Wide Web Publishing Service for PAWs (W3SVC)](services/disable-w3svc.md)**
17. **[REQ-PAW-053 - Disable Xbox Accessory Management Service for PAWs (XboxGipSvc)](services/disable-xboxgipsvc.md)**
18. **[REQ-PAW-054 - Disable Xbox Live Auth Manager Service for PAWs (XblAuthManager)](services/disable-xblauthmanager.md)**
19. **[REQ-PAW-055 - Disable Xbox Live Game Save Service for PAWs (XblGameSave)](services/disable-xblgamesave.md)**
20. **[REQ-PAW-056 - Disable Xbox Live Networking Service for PAWs (XboxNetApiSvc)](services/disable-xboxnetapisvc.md)**

---

## Sources & Compliance References
* **CIS Microsoft Windows Client Benchmark**: Section 5.3, 5.8, 5.9, 5.11, 5.12, 5.14, 5.25, 5.27, 5.29, 5.31, 5.32, 5.33, 5.34, 5.37, 5.38, 5.43, 5.44 to 5.47
* **ANSSI Active Directory Hardening Guide**: Recommendations on limiting active background services on sensitive systems.
* **DoD Windows 11 Computer STIG v2r6**: Services disable requirements
