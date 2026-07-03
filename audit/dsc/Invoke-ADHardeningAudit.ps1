# Invoke-ADHardeningAudit.ps1
# Description: Helper script to run an audit script and determine compliance by intercepting output streams.
# Target Engine: Windows PowerShell 5.1

param (
    [Parameter(Mandatory = $true)]
    [string]$Path
)

if (-not (Test-Path -Path $Path)) {
    Write-Error "Target audit script not found: $Path"
    return $false
}

# Define compliance status flags
$script:hasVulnerability = $false
$script:hasSecureVerdict = $false
$script:hasVulnerableVerdict = $false

# Define custom Write-Host to intercept output details
function Write-Host {
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '')]
    param(
        [Parameter(ValueFromPipeline = $true, Position = 0)]
        $Object,
        $ForegroundColor,
        $BackgroundColor,
        [switch]$NoNewline
    )
    process {
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
}

# Define custom Write-Warning to intercept warnings
function Write-Warning {
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '')]
    param(
        [Parameter(ValueFromPipeline = $true, Position = 0)]
        $Message
    )
    process {
        $script:hasVulnerability = $true
        Microsoft.PowerShell.Utility\Write-Warning @PSBoundParameters
    }
}

# Define custom Write-Error to intercept errors
function Write-Error {
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '')]
    param(
        [Parameter(ValueFromPipeline = $true, Position = 0)]
        $Message
    )
    process {
        $script:hasVulnerability = $true
        Microsoft.PowerShell.Utility\Write-Error @PSBoundParameters
    }
}

# Execute the script, capturing stdout, stderr, warning, error, and information streams
$null = & $Path 6>&1 *>&1 | Out-String

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
# 4. If none of the above are matched, we default to compliant ($true).
return $true
