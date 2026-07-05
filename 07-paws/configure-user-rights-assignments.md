# Configure User Rights Assignments for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration.
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment`
  * **Registry Location**: Stored inside local security database under privilege definitions.

---

## Rationale
Enforcing strict User Rights Assignments (URAs) on PAWs limits the execution footprint of administrative helper binaries, service accounts, and logon permissions to minimize the privilege footprint and prevent administrative impersonation.

This submodule contains individual requirement rules for each User Rights Assignment control enforced on PAWs.

---

## Legacy Impact & Compatibility
* **Maximum Console Isolation**: Standard domain users and non-administrative services have no permission assignments on PAW consoles. Operational impact should be non-existent because PAWs are restricted to pure administrative functions.

---

## Enforced User Rights Assignments on PAWs

The following individual URA rules must be configured:

1. **[REQ-PAW-092 - Configure User Rights: Access Credential Manager as a trusted caller for PAWs](user-rights/configure-ura-setrustedcredmanaccessprivilege.md)**
2. **[REQ-PAW-093 - Configure User Rights: Access this computer from the network for PAWs](user-rights/configure-ura-senetworklogonright.md)**
3. **[REQ-PAW-094 - Configure User Rights: Act as part of the operating system for PAWs](user-rights/configure-ura-setcbprivilege.md)**
4. **[REQ-PAW-095 - Configure User Rights: Allow log on locally for PAWs](user-rights/configure-ura-seinteractivelogonright.md)**
5. **[REQ-PAW-096 - Configure User Rights: Back up files and directories for PAWs](user-rights/configure-ura-sebackupprivilege.md)**
6. **[REQ-PAW-097 - Configure User Rights: Create a pagefile for PAWs](user-rights/configure-ura-secreatepagefileprivilege.md)**
7. **[REQ-PAW-098 - Configure User Rights: Create a token object for PAWs](user-rights/configure-ura-secreatetokenprivilege.md)**
8. **[REQ-PAW-099 - Configure User Rights: Create global objects for PAWs](user-rights/configure-ura-secreateglobalprivilege.md)**
9. **[REQ-PAW-100 - Configure User Rights: Create permanent shared objects for PAWs](user-rights/configure-ura-secreatepermanentprivilege.md)**
10. **[REQ-PAW-101 - Configure User Rights: Debug programs for PAWs](user-rights/configure-ura-sedebugprivilege.md)**
11. **[REQ-PAW-102 - Configure User Rights: Enable computer and user accounts to be trusted for delegation for PAWs](user-rights/configure-ura-seenabledelegationprivilege.md)**
12. **[REQ-PAW-103 - Configure User Rights: Force shutdown from a remote system for PAWs](user-rights/configure-ura-seremoteshutdownprivilege.md)**
13. **[REQ-PAW-104 - Configure User Rights: Impersonate a client after authentication for PAWs](user-rights/configure-ura-seimpersonateprivilege.md)**
14. **[REQ-PAW-105 - Configure User Rights: Load and unload device drivers for PAWs](user-rights/configure-ura-seloaddriverprivilege.md)**
15. **[REQ-PAW-106 - Configure User Rights: Lock pages in memory for PAWs](user-rights/configure-ura-selockmemoryprivilege.md)**
16. **[REQ-PAW-107 - Configure User Rights: Manage auditing and security log for PAWs](user-rights/configure-ura-sesecurityprivilege.md)**
17. **[REQ-PAW-108 - Configure User Rights: Modify firmware environment values for PAWs](user-rights/configure-ura-sesystemenvironmentprivilege.md)**
18. **[REQ-PAW-109 - Configure User Rights: Perform volume maintenance tasks for PAWs](user-rights/configure-ura-semanagevolumeprivilege.md)**
19. **[REQ-PAW-110 - Configure User Rights: Profile single process for PAWs](user-rights/configure-ura-seprofilesingleprocessprivilege.md)**
20. **[REQ-PAW-111 - Configure User Rights: Restore files and directories for PAWs](user-rights/configure-ura-serestoreprivilege.md)**
21. **[REQ-PAW-112 - Configure User Rights: Take ownership of files or other objects for PAWs](user-rights/configure-ura-setakeownershipprivilege.md)**
22. **[REQ-PAW-113 - Configure User Rights: Deny access to this computer from the network for PAWs](user-rights/configure-ura-sedenynetworklogonright.md)**
23. **[REQ-PAW-114 - Configure User Rights: Deny log on through Remote Desktop Services for PAWs](user-rights/configure-ura-sedenyremoteinteractivelogonright.md)**

---

## Sources & Compliance References
* **ANSSI Active Directory Hardening Guide**: Protective controls baselines on Privileged Access Workstations
* **Microsoft Security Baseline**: User Rights Configuration specifications
