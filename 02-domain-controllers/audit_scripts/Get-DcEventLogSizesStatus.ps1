#Get-DcEventLogSizesStatus.ps1
# Description: Audits Event Log Maximum File Sizes and Retention Policies on Domain Controllers.

Write-Host "--- Auditing Domain Controller Event Log Maximum File Sizes and Retention Policies ---" -ForegroundColor Cyan
$script:Vulnerable = $false

# 1. Audit Application Log
$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application"
$ValueName = "Retention"
$ExpectedValue = "0"
if (Test-Path -Path $TargetKey) {
    $Prop = Get-ItemProperty -Path $TargetKey -Name $ValueName -ErrorAction SilentlyContinue
    if ($null -ne $Prop) {
        $Actual = $Prop.$ValueName
        if ($Actual -eq $ExpectedValue) {
            Write-Host "  [+] Application $ValueName = $($Actual) (Secure)" -ForegroundColor Green
        } else {
            Write-Host "  [!] MISMATCH: Application $ValueName = $($Actual) (Expected: $($ExpectedValue))" -ForegroundColor Red
            $script:Vulnerable = $true
        }
    } else {
        Write-Host "  [!] MISSING VALUE: Application $ValueName (Expected: $($ExpectedValue))" -ForegroundColor Red
        $script:Vulnerable = $true
    }
} else {
    Write-Host "  [!] MISSING KEY: $TargetKey" -ForegroundColor Red
    $script:Vulnerable = $true
}

$ValueName = "MaxSize"
$ExpectedValue = 131072
if (Test-Path -Path $TargetKey) {
    $Prop = Get-ItemProperty -Path $TargetKey -Name $ValueName -ErrorAction SilentlyContinue
    if ($null -ne $Prop) {
        $Actual = $Prop.$ValueName
        if ([int64]$Actual -ge [int64]$ExpectedValue) {
            Write-Host "  [+] Application $ValueName = $($Actual) KB (Secure - Meets or exceeds threshold $($ExpectedValue) KB)" -ForegroundColor Green
        } else {
            Write-Host "  [!] MISMATCH: Application $ValueName = $($Actual) KB (Expected: >= $($ExpectedValue) KB)" -ForegroundColor Red
            $script:Vulnerable = $true
        }
    } else {
        Write-Host "  [!] MISSING VALUE: Application $ValueName (Expected: >= $($ExpectedValue) KB)" -ForegroundColor Red
        $script:Vulnerable = $true
    }
} else {
    Write-Host "  [!] MISSING KEY: $TargetKey" -ForegroundColor Red
    $script:Vulnerable = $true
}

# 2. Audit Security Log
$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security"
$ValueName = "Retention"
$ExpectedValue = "0"
if (Test-Path -Path $TargetKey) {
    $Prop = Get-ItemProperty -Path $TargetKey -Name $ValueName -ErrorAction SilentlyContinue
    if ($null -ne $Prop) {
        $Actual = $Prop.$ValueName
        if ($Actual -eq $ExpectedValue) {
            Write-Host "  [+] Security $ValueName = $($Actual) (Secure)" -ForegroundColor Green
        } else {
            Write-Host "  [!] MISMATCH: Security $ValueName = $($Actual) (Expected: $($ExpectedValue))" -ForegroundColor Red
            $script:Vulnerable = $true
        }
    } else {
        Write-Host "  [!] MISSING VALUE: Security $ValueName (Expected: $($ExpectedValue))" -ForegroundColor Red
        $script:Vulnerable = $true
    }
} else {
    Write-Host "  [!] MISSING KEY: $TargetKey" -ForegroundColor Red
    $script:Vulnerable = $true
}

$ValueName = "MaxSize"
$ExpectedValue = 4194304
if (Test-Path -Path $TargetKey) {
    $Prop = Get-ItemProperty -Path $TargetKey -Name $ValueName -ErrorAction SilentlyContinue
    if ($null -ne $Prop) {
        $Actual = $Prop.$ValueName
        if ([int64]$Actual -ge [int64]$ExpectedValue) {
            Write-Host "  [+] Security $ValueName = $($Actual) KB (Secure - Meets or exceeds threshold $($ExpectedValue) KB)" -ForegroundColor Green
        } else {
            Write-Host "  [!] MISMATCH: Security $ValueName = $($Actual) KB (Expected: >= $($ExpectedValue) KB)" -ForegroundColor Red
            $script:Vulnerable = $true
        }
    } else {
        Write-Host "  [!] MISSING VALUE: Security $ValueName (Expected: >= $($ExpectedValue) KB)" -ForegroundColor Red
        $script:Vulnerable = $true
    }
} else {
    Write-Host "  [!] MISSING KEY: $TargetKey" -ForegroundColor Red
    $script:Vulnerable = $true
}

# 3. Audit Setup Log
$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup"
$ValueName = "Retention"
$ExpectedValue = "0"
if (Test-Path -Path $TargetKey) {
    $Prop = Get-ItemProperty -Path $TargetKey -Name $ValueName -ErrorAction SilentlyContinue
    if ($null -ne $Prop) {
        $Actual = $Prop.$ValueName
        if ($Actual -eq $ExpectedValue) {
            Write-Host "  [+] Setup $ValueName = $($Actual) (Secure)" -ForegroundColor Green
        } else {
            Write-Host "  [!] MISMATCH: Setup $ValueName = $($Actual) (Expected: $($ExpectedValue))" -ForegroundColor Red
            $script:Vulnerable = $true
        }
    } else {
        Write-Host "  [!] MISSING VALUE: Setup $ValueName (Expected: $($ExpectedValue))" -ForegroundColor Red
        $script:Vulnerable = $true
    }
} else {
    Write-Host "  [!] MISSING KEY: $TargetKey" -ForegroundColor Red
    $script:Vulnerable = $true
}

$ValueName = "MaxSize"
$ExpectedValue = 32768
if (Test-Path -Path $TargetKey) {
    $Prop = Get-ItemProperty -Path $TargetKey -Name $ValueName -ErrorAction SilentlyContinue
    if ($null -ne $Prop) {
        $Actual = $Prop.$ValueName
        if ([int64]$Actual -ge [int64]$ExpectedValue) {
            Write-Host "  [+] Setup $ValueName = $($Actual) KB (Secure - Meets or exceeds threshold $($ExpectedValue) KB)" -ForegroundColor Green
        } else {
            Write-Host "  [!] MISMATCH: Setup $ValueName = $($Actual) KB (Expected: >= $($ExpectedValue) KB)" -ForegroundColor Red
            $script:Vulnerable = $true
        }
    } else {
        Write-Host "  [!] MISSING VALUE: Setup $ValueName (Expected: >= $($ExpectedValue) KB)" -ForegroundColor Red
        $script:Vulnerable = $true
    }
} else {
    Write-Host "  [!] MISSING KEY: $TargetKey" -ForegroundColor Red
    $script:Vulnerable = $true
}

# 4. Audit System Log
$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System"
$ValueName = "Retention"
$ExpectedValue = "0"
if (Test-Path -Path $TargetKey) {
    $Prop = Get-ItemProperty -Path $TargetKey -Name $ValueName -ErrorAction SilentlyContinue
    if ($null -ne $Prop) {
        $Actual = $Prop.$ValueName
        if ($Actual -eq $ExpectedValue) {
            Write-Host "  [+] System $ValueName = $($Actual) (Secure)" -ForegroundColor Green
        } else {
            Write-Host "  [!] MISMATCH: System $ValueName = $($Actual) (Expected: $($ExpectedValue))" -ForegroundColor Red
            $script:Vulnerable = $true
        }
    } else {
        Write-Host "  [!] MISSING VALUE: System $ValueName (Expected: $($ExpectedValue))" -ForegroundColor Red
        $script:Vulnerable = $true
    }
} else {
    Write-Host "  [!] MISSING KEY: $TargetKey" -ForegroundColor Red
    $script:Vulnerable = $true
}

$ValueName = "MaxSize"
$ExpectedValue = 262144
if (Test-Path -Path $TargetKey) {
    $Prop = Get-ItemProperty -Path $TargetKey -Name $ValueName -ErrorAction SilentlyContinue
    if ($null -ne $Prop) {
        $Actual = $Prop.$ValueName
        if ([int64]$Actual -ge [int64]$ExpectedValue) {
            Write-Host "  [+] System $ValueName = $($Actual) KB (Secure - Meets or exceeds threshold $($ExpectedValue) KB)" -ForegroundColor Green
        } else {
            Write-Host "  [!] MISMATCH: System $ValueName = $($Actual) KB (Expected: >= $($ExpectedValue) KB)" -ForegroundColor Red
            $script:Vulnerable = $true
        }
    } else {
        Write-Host "  [!] MISSING VALUE: System $ValueName (Expected: >= $($ExpectedValue) KB)" -ForegroundColor Red
        $script:Vulnerable = $true
    }
} else {
    Write-Host "  [!] MISSING KEY: $TargetKey" -ForegroundColor Red
    $script:Vulnerable = $true
}

# 5. Audit Role-Specific Channels (Directory Service, DNS Server, DFS Replication)
$RoleAudit = @(
    @{ Name = "Directory Service"; Path = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Directory Service"; MinBytes = 268435456 },
    @{ Name = "DNS Server"; Path = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\DNS Server"; MinBytes = 268435456 },
    @{ Name = "DFS Replication"; Path = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\DFS Replication"; MinBytes = 134217728 }
)

foreach ($Item in $RoleAudit) {
    if (Test-Path -Path $Item.Path) {
        $Prop = Get-ItemProperty -Path $Item.Path -ErrorAction SilentlyContinue
        if ($null -ne $Prop) {
            $ActualSize = $Prop.MaxSize
            $ActualRetention = $Prop.Retention
            
            if ($null -ne $ActualRetention -and $ActualRetention -eq 0) {
                Write-Host "  [+] $($Item.Name) Retention = $($ActualRetention) (Secure)" -ForegroundColor Green
            } else {
                Write-Host "  [!] MISMATCH: $($Item.Name) Retention = $($ActualRetention) (Expected: 0)" -ForegroundColor Red
                $script:Vulnerable = $true
            }
            
            if ($null -ne $ActualSize -and [int64]$ActualSize -ge [int64]$Item.MinBytes) {
                Write-Host "  [+] $($Item.Name) MaxSize = $($ActualSize) bytes (Secure - Meets or exceeds threshold $($Item.MinBytes) bytes)" -ForegroundColor Green
            } else {
                Write-Host "  [!] MISMATCH: $($Item.Name) MaxSize = $($ActualSize) bytes (Expected: >= $($Item.MinBytes) bytes)" -ForegroundColor Red
                $script:Vulnerable = $true
            }
        }
    }
}

if ($script:Vulnerable) {
    Write-Host "Audit Result: VULNERABLE" -ForegroundColor Red
    exit 1
} else {
    Write-Host "Audit Result: SECURE" -ForegroundColor Green
    exit 0
}
