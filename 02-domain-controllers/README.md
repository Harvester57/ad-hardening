# Module 2: Domain Controller Hardening

This directory contains security baselines for Domain Controllers running Windows Server 2016 and above in high-security, air-gapped Active Directory environments.

## Technical Hardening Controls

* **[Domain Controller Hardening Baseline](dc-hardening.md)**
  Detailed requirement to secure the DC operating system, including disabling legacy protocols (SMBv1, LLMNR, NBT-NS, NTLMv1), enforcing LDAP signing and channel binding (ANSSI R19/R20), configuring LSA Protection, enabling Credential Guard, and disabling the Print Spooler service.
