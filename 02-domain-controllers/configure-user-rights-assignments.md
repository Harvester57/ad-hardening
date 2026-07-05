# Configure User Rights Assignments for Domain Controllers

## Target Scope
* **Applicable Systems**: Domain Controllers (DCs)
* **Operating Systems**: Windows Server 2016 and above

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment`
  * **Registry Location**: Stored inside local security database under privilege definitions.

---

## Rationale
User Rights Assignments on Domain Controllers represent a primary defense boundary to secure Active Directory directory services (Tier 0). Restricting who can perform raw volume access, time adjustments, or credential delegations prevents local privilege hijacking.

This submodule contains individual requirement rules for each User Rights Assignment control enforced on Domain Controllers.

---

## Legacy Impact & Compatibility
* **Operational Impact**: Restricting privileges on Domain Controllers impacts replication, system tasks, or third-party AD monitoring agents. Thoroughly validate service accounts before deploying constraints.

---

## Enforced User Rights Assignments on Domain Controllers

The following individual URA rules must be configured:

1. **[REQ-DC-104 - Configure User Rights: Access this computer from the network on Domain Controllers](user-rights/configure-ura-senetworklogonright.md)**
2. **[REQ-DC-105 - Configure User Rights: Act as part of the operating system on Domain Controllers](user-rights/configure-ura-setcbprivilege.md)**
3. **[REQ-DC-106 - Configure User Rights: Add workstations to domain on Domain Controllers](user-rights/configure-ura-semachineaccountprivilege.md)**
4. **[REQ-DC-107 - Configure User Rights: Adjust memory quotas for a process on Domain Controllers](user-rights/configure-ura-seincreasequotaprivilege.md)**
5. **[REQ-DC-108 - Configure User Rights: Allow log on locally on Domain Controllers](user-rights/configure-ura-seinteractivelogonright.md)**
6. **[REQ-DC-109 - Configure User Rights: Allow log on through Remote Desktop Services on Domain Controllers](user-rights/configure-ura-seremoteinteractivelogonright.md)**
7. **[REQ-DC-110 - Configure User Rights: Back up files and directories on Domain Controllers](user-rights/configure-ura-sebackupprivilege.md)**
8. **[REQ-DC-111 - Configure User Rights: Bypass traverse checking on Domain Controllers](user-rights/configure-ura-sechangenotifyprivilege.md)**
9. **[REQ-DC-112 - Configure User Rights: Change the system time on Domain Controllers](user-rights/configure-ura-sesystemtimeprivilege.md)**
10. **[REQ-DC-113 - Configure User Rights: Create a pagefile on Domain Controllers](user-rights/configure-ura-secreatepagefileprivilege.md)**
11. **[REQ-DC-114 - Configure User Rights: Create a token object on Domain Controllers](user-rights/configure-ura-secreatetokenprivilege.md)**
12. **[REQ-DC-115 - Configure User Rights: Create permanent shared objects on Domain Controllers](user-rights/configure-ura-secreatepermanentprivilege.md)**
13. **[REQ-DC-116 - Configure User Rights: Debug programs on Domain Controllers](user-rights/configure-ura-sedebugprivilege.md)**
14. **[REQ-DC-117 - Configure User Rights: Deny access to this computer from the network on Domain Controllers](user-rights/configure-ura-sedenynetworklogonright.md)**
15. **[REQ-DC-118 - Configure User Rights: Deny log on as a batch job on Domain Controllers](user-rights/configure-ura-sedenybatchlogonright.md)**
16. **[REQ-DC-119 - Configure User Rights: Deny log on as a service on Domain Controllers](user-rights/configure-ura-sedenyservicelogonright.md)**
17. **[REQ-DC-120 - Configure User Rights: Deny log on locally on Domain Controllers](user-rights/configure-ura-sedenyinteractivelogonright.md)**
18. **[REQ-DC-121 - Configure User Rights: Deny log on through Remote Desktop Services on Domain Controllers](user-rights/configure-ura-sedenyremoteinteractivelogonright.md)**
19. **[REQ-DC-122 - Configure User Rights: Enable computer and user accounts to be trusted for delegation on Domain Controllers](user-rights/configure-ura-seenabledelegationprivilege.md)**
20. **[REQ-DC-123 - Configure User Rights: Force shutdown from a remote system on Domain Controllers](user-rights/configure-ura-seremoteshutdownprivilege.md)**
21. **[REQ-DC-124 - Configure User Rights: Generate security audits on Domain Controllers](user-rights/configure-ura-seauditprivilege.md)**
22. **[REQ-DC-125 - Configure User Rights: Load and unload device drivers on Domain Controllers](user-rights/configure-ura-seloaddriverprivilege.md)**
23. **[REQ-DC-126 - Configure User Rights: Lock pages in memory on Domain Controllers](user-rights/configure-ura-selockmemoryprivilege.md)**
24. **[REQ-DC-127 - Configure User Rights: Log on as a batch job on Domain Controllers](user-rights/configure-ura-sebatchlogonright.md)**
25. **[REQ-DC-128 - Configure User Rights: Log on as a service on Domain Controllers](user-rights/configure-ura-seservicelogonright.md)**
26. **[REQ-DC-129 - Configure User Rights: Manage auditing and security log on Domain Controllers](user-rights/configure-ura-sesecurityprivilege.md)**
27. **[REQ-DC-130 - Configure User Rights: Modify firmware environment values on Domain Controllers](user-rights/configure-ura-sesystemenvironmentprivilege.md)**
28. **[REQ-DC-131 - Configure User Rights: Profile single process on Domain Controllers](user-rights/configure-ura-seprofilesingleprocessprivilege.md)**
29. **[REQ-DC-132 - Configure User Rights: Restore files and directories on Domain Controllers](user-rights/configure-ura-serestoreprivilege.md)**
30. **[REQ-DC-133 - Configure User Rights: Shut down the system on Domain Controllers](user-rights/configure-ura-seshutdownprivilege.md)**
31. **[REQ-DC-134 - Configure User Rights: Synchronize directory service data on Domain Controllers](user-rights/configure-ura-sesyncagentprivilege.md)**
32. **[REQ-DC-135 - Configure User Rights: Take ownership of files or other objects on Domain Controllers](user-rights/configure-ura-setakeownershipprivilege.md)**

---

## Sources & Compliance References
* **ANSSI Active Directory Hardening Guide**: Protective controls baselines on Domain Controllers
* **Microsoft Security Baseline**: User Rights Configuration specifications
