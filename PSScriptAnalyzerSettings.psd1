# PSScriptAnalyzer settings configuration file.
# This configuration file instructs PSScriptAnalyzer to run all default rules
# except for the PSAvoidUsingWriteHost rule.

@{
    IncludeDefaultRules = $true
    ExcludeRules = @(
        'PSAvoidUsingWriteHost'
    )
}
