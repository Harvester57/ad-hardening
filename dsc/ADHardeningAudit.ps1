# ADHardeningAudit.ps1
# Description: Defines the PowerShell DSC configuration for auditing Active Directory and system hardening controls.
# Target Engine: Windows PowerShell 5.1

Configuration ADHardeningAudit {
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("DomainController", "PAW", "Endpoint")]
        [string]$Profile,

        [Parameter(Mandatory = $false)]
        [string]$AuditScriptsSourcePath = "C:\ProgramData\ADHardening"
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration

    # Common scripts apply to all systems
    $commonScripts = @(
        "03-identities-services\audit_scripts\Get-DefaultAccountsStatus.ps1",
        "03-identities-services\audit_scripts\Get-DenyServiceLogonsStatus.ps1",
        "03-identities-services\audit_scripts\Get-EndpointDelegationAndBootStatus.ps1",
        "03-identities-services\audit_scripts\Get-LAPSStatus.ps1",
        "04-network-firewall\audit_scripts\Get-FirewallLoggingAndSettingsStatus.ps1",
        "04-network-firewall\audit_scripts\Get-HardenedUNCAndClientSigningStatus.ps1",
        "04-network-firewall\audit_scripts\Get-WinRMAndRpcHardeningStatus.ps1",
        "04-network-firewall\audit_scripts\Test-ADPortMatrixRules.ps1",
        "04-network-firewall\audit_scripts\Test-IPsecCryptography.ps1",
        "04-network-firewall\audit_scripts\Test-IPsecDomainIsolation.ps1",
        "04-network-firewall\audit_scripts\Test-RPCDynamicPorts.ps1",
        "04-network-firewall\audit_scripts\Test-SMBSecurity.ps1",
        "04-network-firewall\audit_scripts\Test-TLSConfiguration.ps1",
        "04-network-firewall\audit_scripts\Test-WorkstationIsolation.ps1",
        "05-logging-monitoring\audit_scripts\Test-AdvancedAuditPolicies.ps1",
        "05-logging-monitoring\audit_scripts\Test-PowerShellAuditing.ps1",
        "05-logging-monitoring\audit_scripts\Test-SiemLogShipping.ps1",
        "05-logging-monitoring\audit_scripts\Test-SysmonHardening.ps1",
        "06-operations-maintenance\audit_scripts\Audit-GPOCentralStore.ps1",
        "06-operations-maintenance\audit_scripts\Audit-ThirdPartyTemplates.ps1",
        "06-operations-maintenance\audit_scripts\Get-WsusConfigStatus.ps1"
    )

    # Profile-specific scripts
    if ($Profile -eq "DomainController") {
        $profileScripts = @(
            "01-architecture\audit_scripts\Audit-ADAdminGroups.ps1",
            "01-architecture\audit_scripts\Audit-ADFunctionalLevels.ps1",
            "01-architecture\audit_scripts\Audit-GPOPrecedence.ps1",
            "01-architecture\audit_scripts\Get-ADTrustStatus.ps1",
            "01-architecture\audit_scripts\Test-ADChangesAuditing.ps1",
            "01-architecture\audit_scripts\Test-AdminProtocolRestrictions.ps1",
            "01-architecture\audit_scripts\Test-LocalLogonRestrictions.ps1",
            "02-domain-controllers\audit_scripts\Get-AdminSDHolderAudit.ps1",
            "02-domain-controllers\audit_scripts\Get-AppLockerDCStatus.ps1",
            "02-domain-controllers\audit_scripts\Get-CredentialGuardStatus.ps1",
            "02-domain-controllers\audit_scripts\Get-DcVirtualizationStatus.ps1",
            "02-domain-controllers\audit_scripts\Get-DefenderDCStatus.ps1",
            "02-domain-controllers\audit_scripts\Get-DfsrHealthStatus.ps1",
            "02-domain-controllers\audit_scripts\Get-DnsAuditStatus.ps1",
            "02-domain-controllers\audit_scripts\Get-DriverBlocklistStatus.ps1",
            "02-domain-controllers\audit_scripts\Get-KerberosArmoringStatus.ps1",
            "02-domain-controllers\audit_scripts\Get-KerberosEncryptionStatus.ps1",
            "02-domain-controllers\audit_scripts\Get-LDAPChannelBindingStatus.ps1",
            "02-domain-controllers\audit_scripts\Get-LDAPSigningStatus.ps1",
            "02-domain-controllers\audit_scripts\Get-LSAProtectionStatus.ps1",
            "02-domain-controllers\audit_scripts\Get-MulticastNameResolutionStatus.ps1",
            "02-domain-controllers\audit_scripts\Get-NTLMv1Status.ps1",
            "02-domain-controllers\audit_scripts\Get-PrintSpoolerStatus.ps1",
            "02-domain-controllers\audit_scripts\Get-RdpRestrictedAdminStatus.ps1",
            "02-domain-controllers\audit_scripts\Get-RestrictNTLMStatus.ps1",
            "02-domain-controllers\audit_scripts\Get-RestrictRemoteSAMStatus.ps1",
            "02-domain-controllers\audit_scripts\Get-SMBSigningStatus.ps1",
            "02-domain-controllers\audit_scripts\Get-SMBv1Status.ps1",
            "02-domain-controllers\audit_scripts\Get-SYSVOLDfsrMigrationStatus.ps1",
            "02-domain-controllers\audit_scripts\Get-UnnecessaryServicesStatus.ps1",
            "03-identities-services\audit_scripts\Get-AdminCountOrphansAudit.ps1",
            "03-identities-services\audit_scripts\Get-AdminPasswordPolicyStatus.ps1",
            "03-identities-services\audit_scripts\Get-AuthSiloAuditStatus.ps1",
            "03-identities-services\audit_scripts\Get-gMSAStatus.ps1",
            "03-identities-services\audit_scripts\Get-KdsAndGmsaAudit.ps1",
            "03-identities-services\audit_scripts\Get-KerberosDelegationStatus.ps1",
            "03-identities-services\audit_scripts\Get-ProtectedUsersStatus.ps1",
            "03-identities-services\audit_scripts\Get-ADCSTemplateAudit.ps1",
            "06-operations-maintenance\audit_scripts\Audit-ADBackupStatus.ps1",
            "06-operations-maintenance\audit_scripts\Audit-ADRecycleBin.ps1",
            "06-operations-maintenance\audit_scripts\Audit-CrashControl.ps1",
            "06-operations-maintenance\audit_scripts\Get-KrbtgtRotationStatus.ps1"
        )
    } elseif ($Profile -eq "PAW") {
        $profileScripts = @(
            "07-paws\audit_scripts\Audit-HardwareSecurityFeatures.ps1",
            "07-paws\audit_scripts\Audit-UEFISecurity.ps1",
            "07-paws\audit_scripts\Get-DefenderPawStatus.ps1",
            "07-paws\audit_scripts\Get-DriverBlocklistStatus.ps1",
            "07-paws\audit_scripts\Get-WpbtStatus.ps1",
            "07-paws\audit_scripts\Test-PAWAccountPolicies.ps1",
            "07-paws\audit_scripts\Test-PawAppLockerStatus.ps1",
            "07-paws\audit_scripts\Test-PAWBitLockerStatus.ps1",
            "07-paws\audit_scripts\Test-PawDMAPhysicalSecurity.ps1",
            "07-paws\audit_scripts\Test-PawLocalAdministrators.ps1",
            "07-paws\audit_scripts\Test-PawLsaProtection.ps1",
            "07-paws\audit_scripts\Test-PawUserRightsAssignments.ps1",
            "07-paws\audit_scripts\Test-PawVBSCredentialGuard.ps1"
        )
    } else {
        # Endpoint profile
        $profileScripts = @(
            "08-endpoints\audit_scripts\Audit-HardwareSecurityFeatures.ps1",
            "08-endpoints\audit_scripts\Audit-SecureBoot.ps1",
            "08-endpoints\audit_scripts\Audit-UEFISecurity.ps1",
            "08-endpoints\audit_scripts\Get-BlockedLOLBinsOutboundStatus.ps1",
            "08-endpoints\audit_scripts\Get-DefenderAdvancedStatus.ps1",
            "08-endpoints\audit_scripts\Get-ExploitProtectionStatus.ps1",
            "08-endpoints\audit_scripts\Get-SafeModeNonAdminsStatus.ps1",
            "08-endpoints\audit_scripts\Get-WpbtStatus.ps1",
            "08-endpoints\audit_scripts\Test-AccountPolicies.ps1",
            "08-endpoints\audit_scripts\Test-AutoPlay.ps1",
            "08-endpoints\audit_scripts\Test-BitLockerStatus.ps1",
            "08-endpoints\audit_scripts\Test-DMAPhysicalSecurity.ps1",
            "08-endpoints\audit_scripts\Test-EndpointAppLockerStatus.ps1",
            "08-endpoints\audit_scripts\Test-LocalAdministrators.ps1",
            "08-endpoints\audit_scripts\Test-NetworkHardeningStatus.ps1",
            "08-endpoints\audit_scripts\Test-RemoteDesktopStatus.ps1",
            "08-endpoints\audit_scripts\Test-RemovableStorage.ps1",
            "08-endpoints\audit_scripts\Test-UACPolicies.ps1",
            "08-endpoints\audit_scripts\Test-UserProfileRestrictions.ps1",
            "08-endpoints\audit_scripts\Test-UserRightsAssignments.ps1",
            "08-endpoints\audit_scripts\Test-VBSCredentialGuard.ps1",
            "08-endpoints\audit_scripts\Test-WDACStatus.ps1",
            "08-endpoints\audit_scripts\Test-WSUSClientStatus.ps1"
        )
    }

    $allScripts = $commonScripts + $profileScripts

    Node "localhost" {
        foreach ($relativeScriptPath in $allScripts) {
            # Extract script base name
            $scriptFileName = [System.IO.Path]::GetFileNameWithoutExtension($relativeScriptPath)
            
            # Sanitize script name for DSC resource instance key (alphanumeric and underscores only)
            $sanitizedResourceName = $scriptFileName -replace '[^a-zA-Z0-9_]', '_'
            
            # Build target path
            $targetLocalPath = Join-Path $AuditScriptsSourcePath $relativeScriptPath

            Script "Audit_$sanitizedResourceName" {
                GetScript = {
                    return @{
                        "Result" = $using:scriptFileName
                    }
                }
                TestScript = {
                    $path = $using:targetLocalPath
                    if (-not (Test-Path -Path $path)) {
                        Write-Error "Audit script not found at target path: $path"
                        return $false
                    }

                    # Define compliance status flags
                    $script:hasVulnerability = $false
                    $script:hasSecureVerdict = $false
                    $script:hasVulnerableVerdict = $false

                    # Define custom Write-Host to intercept output details
                    function Write-Host {
                        param(
                            [Parameter(ValueFromPipeline = $true, Position = 0)]
                            $Object,
                            $ForegroundColor,
                            $BackgroundColor,
                            [switch]$NoNewline
                        )
                        $text = $Object | Out-String
                        if ($ForegroundColor -eq "Red") {
                            $script:hasVulnerability = $true
                        }
                        if ($text -match "Audit [Rr]esult:\s*SECURE" -or $text -match "Verification PASSED" -or $text -match "compliant" -or $text -match "PASSED") {
                            $script:hasSecureVerdict = $true
                        }
                        if ($text -match "Audit [Rr]esult:\s*VULNERABLE" -or $text -match "Verification FAILED" -or $text -match "vulnerable" -or $text -match "FAILED") {
                            $script:hasVulnerableVerdict = $true
                        }
                        Microsoft.PowerShell.Utility\Write-Host @PSBoundParameters
                    }

                    # Define custom Write-Warning to intercept warnings
                    function Write-Warning {
                        param(
                            [Parameter(ValueFromPipeline = $true, Position = 0)]
                            $Message
                        )
                        $script:hasVulnerability = $true
                        Microsoft.PowerShell.Utility\Write-Warning @PSBoundParameters
                    }

                    # Define custom Write-Error to intercept errors
                    function Write-Error {
                        param(
                            [Parameter(ValueFromPipeline = $true, Position = 0)]
                            $Message
                        )
                        $script:hasVulnerability = $true
                        Microsoft.PowerShell.Utility\Write-Error @PSBoundParameters
                    }

                    # Execute the script, capturing stdout, stderr, warning, error, and information streams
                    $output = & $path 6>&1 *>&1 | Out-String

                    # Cleanup functions to prevent scope leakage
                    Remove-Item Function:\Write-Host -ErrorAction SilentlyContinue
                    Remove-Item Function:\Write-Warning -ErrorAction SilentlyContinue
                    Remove-Item Function:\Write-Error -ErrorAction SilentlyContinue

                    # Compliance Decision Logic:
                    # 1. If red text, warnings, or errors were generated, it is vulnerable.
                    if ($script:hasVulnerability) {
                        return $false
                    }
                    # 2. If an explicit VULNERABLE verdict was printed, it is vulnerable.
                    if ($script:hasVulnerableVerdict) {
                        return $false
                    }
                    # 3. If an explicit SECURE verdict was printed, it is secure.
                    if ($script:hasSecureVerdict) {
                        return $true
                    }
                    # 4. If none of the above are matched (i.e. no vulnerabilities or explicit verdicts were printed),
                    # we default to compliant ($true) since no failures were logged.
                    return $true
                }
                SetScript = {
                    $name = $using:scriptFileName
                    $path = $using:targetLocalPath
                    Write-Warning "Audit result failed: Control '$name' is not secure. Script path: $path"
                }
            }
        }
    }
}
