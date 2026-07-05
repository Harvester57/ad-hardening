# Disable Unnecessary Services on Domain Controllers

## Target Scope
* **Applicable Systems**: Domain Controllers (DCs) running Windows Server.
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022.

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * Computer Configuration\Preferences\Windows Settings\Registry
  * HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\Start

---

## Rationale
Domain Controllers are the core authority within an Active Directory forest (Tier 0). Minimizing the running services on these critical systems reduces the overall attack surface and limits potential targets for local privilege escalation, remote exploit execution, or credential extraction.

Disabling non-essential services aligns with the principle of least functionality. This submodule contains individual requirement controls for each non-essential server service.

---

## Legacy Impact & Compatibility
* **No Functional Impact**: Disabling the specified services has no operational impact on Active Directory Domain Services, replication, group policy processing, client authentication, or administrative management tools.
* **Smart Cards**: If your domain relies on Smart Card authentication, the Smart Card Device Enumeration Service (`ScDeviceEnum`) and Smart Card (`SCardSvr`) services must remain enabled.
* **Desktop Experience Feature Scope**: The specified services are primarily present on Windows Server installations with Desktop Experience. On Windows Server Core installations, most of these services are not installed by default, and attempts to stop or disable them will simply be skipped.

---

## Service Hardening Requirements

The following services must be stopped and disabled:

1. **[REQ-DC-035 - Disable Xbox Live Auth Manager (XblAuthManager)](services/disable-xblauthmanager.md)**
2. **[REQ-DC-036 - Disable Xbox Live Game Save (XblGameSave)](services/disable-xblgamesave.md)**
3. **[REQ-DC-037 - Disable ActiveX Installer (AxInstSV)](services/disable-axinstsv.md)**
4. **[REQ-DC-038 - Disable Bluetooth Support Service (bthserv)](services/disable-bthserv.md)**
5. **[REQ-DC-039 - Disable Connected Devices Platform User Service (CDPUserSvc)](services/disable-cdpusersvc.md)**
6. **[REQ-DC-040 - Disable Contact Data (PimIndexMaintenanceSvc)](services/disable-pimindexmaintenancesvc.md)**
7. **[REQ-DC-041 - Disable WAP Push Message Routing Service (dmwappushservice)](services/disable-dmwappushservice.md)**
8. **[REQ-DC-042 - Disable Downloaded Maps Manager (MapsBroker)](services/disable-mapsbroker.md)**
9. **[REQ-DC-043 - Disable Geolocation Service (lfsvc)](services/disable-lfsvc.md)**
10. **[REQ-DC-044 - Disable Internet Connection Sharing (ICS) (SharedAccess)](services/disable-sharedaccess.md)**
11. **[REQ-DC-045 - Disable Link-Layer Topology Discovery Mapper (lltdsvc)](services/disable-lltdsvc.md)**
12. **[REQ-DC-046 - Disable Microsoft Account Sign-in Assistant (wlidsvc)](services/disable-wlidsvc.md)**
13. **[REQ-DC-047 - Disable Microsoft Passport (NgcSvc)](services/disable-ngcsvc.md)**
14. **[REQ-DC-048 - Disable Microsoft Passport Container (NgcCtnrSvc)](services/disable-ngcctnrsvc.md)**
15. **[REQ-DC-049 - Disable Network Connection Broker (NcbService)](services/disable-ncbservice.md)**
16. **[REQ-DC-050 - Disable Phone Service (PhoneSvc)](services/disable-phonesvc.md)**
17. **[REQ-DC-051 - Disable Printer Extensions and Notifications (PrintNotify)](services/disable-printnotify.md)**
18. **[REQ-DC-052 - Disable Program Compatibility Assistant Service (PcaSvc)](services/disable-pcasvc.md)**
19. **[REQ-DC-053 - Disable Quality Windows Audio Video Experience (QWAVE)](services/disable-qwave.md)**
20. **[REQ-DC-054 - Disable Radio Management Service (RmSvc)](services/disable-rmsvc.md)**
21. **[REQ-DC-055 - Disable Sensor Data Service (SensorDataService)](services/disable-sensordataservice.md)**
22. **[REQ-DC-056 - Disable Sensor Monitoring Service (SensrSvc)](services/disable-sensrsvc.md)**
23. **[REQ-DC-057 - Disable Sensor Service (SensorService)](services/disable-sensorservice.md)**
24. **[REQ-DC-058 - Disable Shell Hardware Detection (ShellHWDetection)](services/disable-shellhwdetection.md)**
25. **[REQ-DC-059 - Disable Smart Card Device Enumeration Service (ScDeviceEnum)](services/disable-scdeviceenum.md)**
26. **[REQ-DC-060 - Disable SSDP Discovery (SSDPSRV)](services/disable-ssdpsrv.md)**
27. **[REQ-DC-061 - Disable Still Image Acquisition Events (WiaRpc)](services/disable-wiarpc.md)**
28. **[REQ-DC-062 - Disable Sync Host (OneSyncSvc)](services/disable-onesyncsvc.md)**
29. **[REQ-DC-063 - Disable UPnP Device Host (upnphost)](services/disable-upnphost.md)**
30. **[REQ-DC-064 - Disable User Data Access (UserDataSvc)](services/disable-userdatasvc.md)**
31. **[REQ-DC-065 - Disable User Data Storage (UnistoreSvc)](services/disable-unistoresvc.md)**
32. **[REQ-DC-066 - Disable WalletService (WalletService)](services/disable-walletservice.md)**
33. **[REQ-DC-067 - Disable Windows Audio (Audiosrv)](services/disable-audiosrv.md)**
34. **[REQ-DC-068 - Disable Windows Audio Endpoint Builder (AudioEndpointBuilder)](services/disable-audioendpointbuilder.md)**
35. **[REQ-DC-069 - Disable Windows Camera Frame Server (FrameServer)](services/disable-frameserver.md)**
36. **[REQ-DC-070 - Disable Windows Image Acquisition (WIA) (stisvc)](services/disable-stisvc.md)**
37. **[REQ-DC-071 - Disable Windows Insider Service (wisvc)](services/disable-wisvc.md)**
38. **[REQ-DC-072 - Disable Windows Mobile Hotspot Service (icssvc)](services/disable-icssvc.md)**
39. **[REQ-DC-073 - Disable Windows Push Notifications System Service (WpnService)](services/disable-wpnservice.md)**
40. **[REQ-DC-074 - Disable Windows Push Notifications User Service (WpnUserService)](services/disable-wpnuserservice.md)**

---

## Sources & Compliance References
* **Microsoft Windows Server Security Guidance**: [Security guidelines for disabling system services in Windows Server](https://learn.microsoft.com/en-us/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server)
* **ANSSI AD Hardening Guide**: Recommendation R4 (Minimization of service execution and software installation)
* **CIS Microsoft Windows Server Benchmark**: Section 2.2 and general service minimization baselines
