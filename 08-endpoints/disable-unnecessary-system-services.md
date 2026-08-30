# Disable Unnecessary System Services

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers.
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional, Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\System Services`
  * **Registry Location**: `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\Start`

---

## Rationale
To minimize the attack surface of standard client endpoints and member servers, all unnecessary system services must be disabled. Operating system services that are not required for core administrative tasks or business functionality introduce unnecessary entry points for network exposure, resource utilization, and privilege escalation vulnerabilities.

This submodule contains the individual hardening controls for each unnecessary system service.

---

## Legacy Impact & Compatibility
* **Infra Compatibility**: Administrative functions relying on legacy RPC Locator or SSDP-based discovery of network printers/devices may be affected.
* **WSL Functionality**: Disabling `LxssManager` prevents users from running Windows Subsystem for Linux (WSL) containers on their endpoints. If WSL is strictly required for engineering roles, this service should be excluded from the policy.
* **Mobile Hotspotting**: Disabling mobile hotspotting services prevents users from creating cellular hot-spotting configurations. This is a desired security behavior but can generate support tickets for mobile employees.

---

## Service Hardening Requirements

The following services must be stopped and disabled:

1. **[REQ-END-037 - Disable Computer Browser Service (Browser)](services/disable-browser.md)**
2. **[REQ-END-038 - Disable Infrared Monitor Service (irmon)](services/disable-irmon.md)**
3. **[REQ-END-039 - Disable Internet Connection Sharing (ICS) Service (SharedAccess)](services/disable-sharedaccess.md)**
4. **[REQ-END-040 - Disable LxssManager Service (LxssManager)](services/disable-lxssmanager.md)**
5. **[REQ-END-041 - Disable Microsoft FTP Service (FTPSVC)](services/disable-ftpsvc.md)**
6. **[REQ-END-042 - Disable OpenSSH SSH Server Service (sshd)](services/disable-sshd.md)**
7. **[REQ-END-043 - Disable Remote Procedure Call (RPC) Locator Service (RpcLocator)](services/disable-rpclocator.md)**
8. **[REQ-END-044 - Disable Routing and Remote Access Service (RemoteAccess)](services/disable-remoteaccess.md)**
9. **[REQ-END-045 - Disable Simple TCP/IP Services (simptcp)](services/disable-simptcp.md)**
10. **[REQ-END-046 - Disable Special Administration Console Helper Service (sacsvr)](services/disable-sacsvr.md)**
11. **[REQ-END-047 - Disable SSDP Discovery Service (SSDPSRV)](services/disable-ssdpsrv.md)**
12. **[REQ-END-048 - Disable UPnP Device Host Service (upnphost)](services/disable-upnphost.md)**
13. **[REQ-END-049 - Disable Web Management Service (WMSvc)](services/disable-wmsvc.md)**
14. **[REQ-END-050 - Disable Windows Media Player Network Sharing Service (WMPNetworkSvc)](services/disable-wmpnetworksvc.md)**
15. **[REQ-END-051 - Disable Windows Mobile Hotspot Service (icssvc)](services/disable-icssvc.md)**
16. **[REQ-END-052 - Disable World Wide Web Publishing Service (W3SVC)](services/disable-w3svc.md)**
17. **[REQ-END-053 - Disable Xbox Accessory Management Service (XboxGipSvc)](services/disable-xboxgipsvc.md)**
18. **[REQ-END-054 - Disable Xbox Live Auth Manager Service (XblAuthManager)](services/disable-xblauthmanager.md)**
19. **[REQ-END-055 - Disable Xbox Live Game Save Service (XblGameSave)](services/disable-xblgamesave.md)**
20. **[REQ-END-056 - Disable Xbox Live Networking Service (XboxNetApiSvc)](services/disable-xboxnetapisvc.md)**
21. **[REQ-END-177 - Disable WebClient Service (WebClient)](services/disable-webclient.md)**

---

## Sources & Compliance References
* **CIS Microsoft Windows Client Benchmark**: Section 5.3, 5.8, 5.9, 5.11, 5.12, 5.14, 5.25, 5.27, 5.29, 5.31, 5.32, 5.33, 5.34, 5.37, 5.38, 5.43, 5.44 to 5.47
* **ANSSI Active Directory Hardening Guide**: Recommendations on host service minimization
* **DoD Windows 11 Computer STIG v2r6**: Services disable requirements
