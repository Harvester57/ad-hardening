# Configure User Rights Assignments

## Target Scope
* **Applicable Systems**: Member Servers, Tier 2 Clients (Windows 10/11)
* **Operating Systems**: Windows Server 2016 (and above), Windows 10/11 Enterprise/Professional

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment`
  * **Registry Location**: Stored inside local security database under privilege definitions.

---

## Rationale
User Rights Assignments (URAs) govern the specific actions that security principals (users, groups, and service accounts) can perform on a system. Insecure default URA mappings can be abused by attackers to elevate privileges, compromise credentials, or establish persistence.

This submodule contains individual requirement rules for each User Rights Assignment control enforced on standard workstations.

---

## Legacy Impact & Compatibility
* **Operational Impact**: Restricting privileges restricts custom services or applications that depend on local execution rights. Validate all applications in audit staging environments before implementing block rules.

---

## Enforced User Rights Assignments

The following individual URA rules must be configured:

1. **[REQ-END-096 - Configure User Rights: Access Credential Manager as a trusted caller](user-rights/configure-ura-setrustedcredmanaccessprivilege.md)**
2. **[REQ-END-097 - Configure User Rights: Access this computer from the network](user-rights/configure-ura-senetworklogonright.md)**
3. **[REQ-END-098 - Configure User Rights: Act as part of the operating system](user-rights/configure-ura-setcbprivilege.md)**
4. **[REQ-END-099 - Configure User Rights: Allow log on locally](user-rights/configure-ura-seinteractivelogonright.md)**
5. **[REQ-END-100 - Configure User Rights: Back up files and directories](user-rights/configure-ura-sebackupprivilege.md)**
6. **[REQ-END-101 - Configure User Rights: Change the system time](user-rights/configure-ura-sesystemtimeprivilege.md)**
7. **[REQ-END-102 - Configure User Rights: Change the time zone](user-rights/configure-ura-setimezoneprivilege.md)**
8. **[REQ-END-103 - Configure User Rights: Create a pagefile](user-rights/configure-ura-secreatepagefileprivilege.md)**
9. **[REQ-END-104 - Configure User Rights: Create a token object](user-rights/configure-ura-secreatetokenprivilege.md)**
10. **[REQ-END-105 - Configure User Rights: Create global objects](user-rights/configure-ura-secreateglobalprivilege.md)**
11. **[REQ-END-106 - Configure User Rights: Create permanent shared objects](user-rights/configure-ura-secreatepermanentprivilege.md)**
12. **[REQ-END-107 - Configure User Rights: Create symbolic links](user-rights/configure-ura-secreatesymboliclinkprivilege.md)**
13. **[REQ-END-108 - Configure User Rights: Debug programs](user-rights/configure-ura-sedebugprivilege.md)**
14. **[REQ-END-109 - Configure User Rights: Enable computer and user accounts to be trusted for delegation](user-rights/configure-ura-seenabledelegationprivilege.md)**
15. **[REQ-END-110 - Configure User Rights: Force shutdown from a remote system](user-rights/configure-ura-seremoteshutdownprivilege.md)**
16. **[REQ-END-111 - Configure User Rights: Impersonate a client after authentication](user-rights/configure-ura-seimpersonateprivilege.md)**
17. **[REQ-END-112 - Configure User Rights: Increase scheduling priority](user-rights/configure-ura-seincreasebasepriorityprivilege.md)**
18. **[REQ-END-113 - Configure User Rights: Load and unload device drivers](user-rights/configure-ura-seloaddriverprivilege.md)**
19. **[REQ-END-114 - Configure User Rights: Lock pages in memory](user-rights/configure-ura-selockmemoryprivilege.md)**
20. **[REQ-END-115 - Configure User Rights: Manage auditing and security log](user-rights/configure-ura-sesecurityprivilege.md)**
21. **[REQ-END-116 - Configure User Rights: Modify firmware environment values](user-rights/configure-ura-sesystemenvironmentprivilege.md)**
22. **[REQ-END-117 - Configure User Rights: Perform volume maintenance tasks](user-rights/configure-ura-semanagevolumeprivilege.md)**
23. **[REQ-END-118 - Configure User Rights: Profile single process](user-rights/configure-ura-seprofilesingleprocessprivilege.md)**
24. **[REQ-END-119 - Configure User Rights: Profile system performance](user-rights/configure-ura-sesystemprofileprivilege.md)**
25. **[REQ-END-120 - Configure User Rights: Replace a process level token](user-rights/configure-ura-seassignprimarytokenprivilege.md)**
26. **[REQ-END-121 - Configure User Rights: Restore files and directories](user-rights/configure-ura-serestoreprivilege.md)**
27. **[REQ-END-122 - Configure User Rights: Take ownership of files or other objects](user-rights/configure-ura-setakeownershipprivilege.md)**
28. **[REQ-END-123 - Configure User Rights: Modify an object label](user-rights/configure-ura-serelabelprivilege.md)**
29. **[REQ-END-124 - Configure User Rights: Deny access to this computer from the network](user-rights/configure-ura-sedenynetworklogonright.md)**
30. **[REQ-END-125 - Configure User Rights: Deny log on through Remote Desktop Services](user-rights/configure-ura-sedenyremoteinteractivelogonright.md)**

---

## Sources & Compliance References
* **ANSSI Active Directory Hardening Guide**: User Rights Assignment protective controls
* **Microsoft Security Baseline**: User Rights Configuration specifications
