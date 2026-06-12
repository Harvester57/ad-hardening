# Get-FirewallLoggingAndSettingsStatus.ps1
Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, NotifyOnListen, LogBlocked, LogAllowed, LogMaxSizeKilobytes, LogFileName, AllowLocalFirewallRules, AllowLocalIPsecRules
