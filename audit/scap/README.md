# Active Directory Hardening Compliance Checking (XCCDF & OVAL)

This directory contains the compliance checking manifests for the Active Directory Hardening Guidebook. These files allow security auditors, administrators, and automated tools to verify compliance against the hardening guidelines defined in this repository.

---

## The Compliance Audit Framework

To achieve high-fidelity auditing with minimal overhead and no arbitrary script execution, the framework utilizes two standardized security industry formats:

1. **[ad-hardening-xccdf.xml](ad-hardening-xccdf.xml)**: The Extensible Configuration Checklist Description Format (XCCDF 1.2) benchmark. It organizes hardening controls into three target profiles:
   * **Domain Controller Hardening Profile**: Security settings for Domain Controllers and Tier 0 Active Directory infrastructure.
   * **Privileged Access Workstations (PAW) Hardening Profile**: Hardening controls specifically designed for PAWs.
   * **Endpoint Hardening Profile**: Security controls for general member client workstations.
2. **[ad-hardening-oval.xml](ad-hardening-oval.xml)**: The Open Vulnerability and Assessment Language (OVAL 5.11) definitions file. It maps each XCCDF rule to automated native checks that directly query system properties:
   * **Registry Values**: Direct `registry_test` checks of key paths, names, types, and expected values.
   * **System Services**: Native `service_test` checks validating startup configurations (e.g., Disabled, Automatic).
   * **User Rights Assignments**: Native `userright_test` checks mapping security permissions to trustee SIDs.
   * **Local Account Policies**: Native `passwordpolicy_test` and `lockoutpolicy_test` checks validating SAM limits.
   * **Audit Policies**: Native `auditeventpolicysubcategories_test` checks validating audit subcategory settings.
    * **External Scripts (Fallback)**: Native placeholder checks for rules requiring complex custom scripts (actual checks are performed by the PowerShell DSC audit framework).

---

## Performing an Audit on a Windows System

Automated audits using these compliance manifests can be performed using standard SCAP-compliant scanners.

### Option A: Using OpenSCAP (oscap)

OpenSCAP is an open-source security compliance tool. It can evaluate XCCDF benchmarks and OVAL definitions on Windows systems:

1. **Install OpenSCAP**: Download and install the OpenSCAP command-line utility for Windows (available in packages or compiled from source).
2. **Run the Audit**: Open an elevated command prompt or PowerShell console (run as Administrator) and execute `oscap` specifying the benchmark profile. Include the `--oval-results` flag to ensure that the system characteristics (expected vs actual value) are included in the results for detailed reporting:

```text
# Evaluate Domain Controller baseline
oscap xccdf eval --oval-results --profile xccdf_org.adhardening.benchmarks_profile_DomainController --results dc-results.xml --report dc-report.html ad-hardening-xccdf.xml

# Evaluate Privileged Access Workstation baseline
oscap xccdf eval --oval-results --profile xccdf_org.adhardening.benchmarks_profile_PAW --results paw-results.xml --report paw-report.html ad-hardening-xccdf.xml

# Evaluate Endpoint baseline
oscap xccdf eval --oval-results --profile xccdf_org.adhardening.benchmarks_profile_Endpoint --results endpoint-results.xml --report endpoint-report.html ad-hardening-xccdf.xml
```

3. **View the Detailed Report**:
Open the generated HTML report (e.g., `dc-report.html`) in a browser. Under each evaluated rule, you can expand the rule details to see the OVAL system characteristics, including the expected value versus the actual value found on the machine.
```

### Option B: Using jOVAL or Enterprise Vulnerability Scanners

For enterprise environments, scanners like **jOVAL** (a Java-based OVAL interpreter designed for Windows) or scanning agents (such as **Nessus**, **Qualys**, or **Rapid7 Nexpose**) can ingest the OVAL definitions file directly to run authenticated compliance scans:

1. Import `ad-hardening-oval.xml` as a custom audit file in your vulnerability management console.
2. Provide local administrative credentials for the target Windows systems.
3. Schedule the scan. The scanning engine will automatically query the registry, user privileges, and services defined in the XML.

---

## Prerequisites for Fallback Script Tests

While the vast majority of checks are evaluated natively, certain advanced Active Directory checks (e.g. Forest Functional Level, replication status, AdminSDHolder permissions) require executing PowerShell audit scripts on the target machine.

To enable these fallback tests:
1. Ensure the repository's audit scripts are synchronized to `C:\ProgramData\ADHardening\audit_scripts`. This directory structure is deployed automatically by the PowerShell DSC audit framework:
```powershell
cd ../dsc
.\Deploy-ADHardeningAudit.ps1 -Profile DomainController
```
2. The scanner running the audit must have administrative privileges to execute the scripts locally.

---

## Manifest Integrity & Schema Validation

To prevent validation issues, formatting errors, or broken references, this repository includes an offline compliance linter and schema validator.

### How to Run the Validator

Run the main repository validator from the root directory:
```powershell
..\..\Verify-ADHardeningDocs.ps1
```

Or execute the Python compliance validation script directly:
```powershell
python ..\..\scripts\validate_compliance.py
```

### Verification Checks

The linter validates:
1. **XML Schema Compliance**: Cross-references native elements (`registry_test`, `service_test`, `userright_test`, etc.) against the local XML schemas (`windows-definitions-schema.xsd` and `windows-system-characteristics-schema.xsd`) to ensure they conform to structure definitions.
2. **XCCDF Reference Integrity**: Checks that every XCCDF `<Rule>` has a corresponding `<check>` referencing a valid OVAL Definition ID.
3. **OVAL Internal Integrity**: Ensures that every OVAL `definition` criterion references a valid `test_ref`, and every `test` resolves to correct `object` and `state` elements.
4. **Well-formedness**: Checks that all tags and namespaces are correct.
