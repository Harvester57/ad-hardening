# Verify-ADHardeningDocs.ps1
# Script to validate links and verify PowerShell syntax in markdown files within the repository.

[CmdletBinding()]
param(
    [switch]$ChangedOnly,
    [switch]$Force
)

$scriptPath = $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptPath
$cacheDir = Join-Path -Path $repoRoot -ChildPath ".cache"
$cacheFile = Join-Path -Path $cacheDir -ChildPath "syntax_cache.json"

Write-Host "Starting documentation validation in: $repoRoot" -ForegroundColor Cyan

# Load syntax verification cache
$syntaxCache = @{}
if (-not $Force -and (Test-Path -Path $cacheFile)) {
    try {
        $rawJson = Get-Content -Path $cacheFile -Raw -Encoding UTF8
        if ($rawJson) {
            $parsed = $rawJson | ConvertFrom-Json
            if ($parsed.files) {
                foreach ($prop in $parsed.files.PSObject.Properties) {
                    $syntaxCache[$prop.Name] = $prop.Value
                }
            }
        }
    }
    catch {
        $syntaxCache = @{}
    }
}

$mdFiles = @()

if ($ChangedOnly) {
    Write-Host "Checking git status for modified markdown files..." -ForegroundColor Yellow
    try {
        $gitStatus = git status --porcelain
        $changedPaths = @()
        foreach ($line in $gitStatus) {
            if ($line.Length -gt 3) {
                $statusFilePath = $line.Substring(3).Trim().Trim('"')
                if ($statusFilePath -like "*.md" -and $statusFilePath -notlike "*\.git*" -and $statusFilePath -notlike "*\_book*" -and $statusFilePath -ne "AD-Hardening-Guidebook.md") {
                    $fullPath = Join-Path -Path $repoRoot -ChildPath $statusFilePath
                    if (Test-Path -Path $fullPath) {
                        $changedPaths += (Get-Item -Path $fullPath)
                    }
                }
            }
        }
        $mdFiles = $changedPaths
        Write-Host "Found $($mdFiles.Count) changed markdown file(s) to validate." -ForegroundColor Cyan
    }
    catch {
        Write-Warning "Failed to query git status. Falling back to full scan."
        $ChangedOnly = $false
    }
}

if (-not $ChangedOnly) {
    $mdFiles = Get-ChildItem -Path $repoRoot -Filter *.md -Recurse | Where-Object {
        $_.FullName -notlike "*\.git*" -and
        $_.FullName -notlike "*\.gemini*" -and
        $_.FullName -notlike "*\node_modules*" -and
        $_.FullName -notlike "*\_book*" -and
        $_.FullName -notlike "*\.cache*" -and
        $_.Name -ne "AD-Hardening-Guidebook.md"
    }
}

$errorsCount = 0
$verifiedCount = 0
$cachedCount = 0
$sha256 = [System.Security.Cryptography.SHA256]::Create()

function Get-StringHash([string]$inputString) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($inputString)
    $hashBytes = $sha256.ComputeHash($bytes)
    return -join ($hashBytes | ForEach-Object { $_.ToString("x2") })
}

foreach ($file in $mdFiles) {
    $relPath = $file.FullName.Substring($repoRoot.Length).TrimStart('\', '/')
    $content = Get-Content -Path $file.FullName -Raw -Encoding UTF8
    $fileHash = Get-StringHash -inputString $content
    $fileDir = Split-Path -Parent $file.FullName

    # Check cache
    if (-not $Force -and $syntaxCache.ContainsKey($relPath) -and $syntaxCache[$relPath] -eq $fileHash) {
        $cachedCount++
        continue
    }

    $verifiedCount++
    Write-Host "`nChecking: $($relPath)" -ForegroundColor Yellow

    # 1. Verify markdown relative links
    $linkRegex = '\[([^\]]+)\]\(([^)#:\s]+)(#[^)]*)?\)'
    $linkMatches = [regex]::Matches($content, $linkRegex)

    foreach ($match in $linkMatches) {
        $linkPath = $match.Groups[2].Value
        $decodedLinkPath = [System.Uri]::UnescapeDataString($linkPath)

        if ($decodedLinkPath -notmatch '^https?://' -and $decodedLinkPath -notmatch '^mailto:' -and $decodedLinkPath -ne '') {
            $targetFullPath = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($fileDir, $decodedLinkPath))
            if (-not (Test-Path -Path $targetFullPath)) {
                Write-Error "Broken link in $($file.Name): '$decodedLinkPath' -> Resolved path '$targetFullPath' not found."
                $errorsCount++
            }
        }
    }

    # 2. Extract and syntax check PowerShell code blocks
    $codeBlockRegex = '(?s)```(?:powershell|ps1)\r?\n(.*?)\r?\n```'
    $codeBlocks = [regex]::Matches($content, $codeBlockRegex)

    $blockIndex = 1
    $fileHasSyntaxError = $false
    foreach ($block in $codeBlocks) {
        $code = $block.Groups[1].Value
        $tokens = $null
        $parseErrors = $null
        $null = [System.Management.Automation.Language.Parser]::ParseInput($code, [ref]$tokens, [ref]$parseErrors)

        if ($parseErrors) {
            $fileHasSyntaxError = $true
            Write-Host "  PowerShell Code Block #$blockIndex syntax errors:" -ForegroundColor Red
            foreach ($err in $parseErrors) {
                Write-Host "    Line $($err.Extent.StartLineNumber): $($err.Message)" -ForegroundColor Red
                Write-Host "    Code snippet: $($err.Extent.Text)" -ForegroundColor DarkGray
                $errorsCount++
            }
        }
        else {
            Write-Host "  PowerShell Code Block #$blockIndex syntax: OK" -ForegroundColor Green
        }
        $blockIndex++
    }

    # If no syntax errors, update cache
    if (-not $fileHasSyntaxError) {
        $syntaxCache[$relPath] = $fileHash
    }
}

# Save syntax cache
if (-not (Test-Path -Path $cacheDir)) {
    New-Item -ItemType Directory -Path $cacheDir -Force | Out-Null
}
$cacheObj = [PSCustomObject]@{
    version = 1
    files = $syntaxCache
}
$cacheObj | ConvertTo-Json -Depth 5 | Set-Content -Path $cacheFile -Encoding UTF8

Write-Host "`nSyntax check summary: $verifiedCount verified, $cachedCount skipped (cached)." -ForegroundColor Cyan

# 3. Verify Table of Contents (SUMMARY.md) Coverage
Write-Host "`nVerifying SUMMARY.md completeness..." -ForegroundColor Yellow
$summaryFile = Join-Path -Path $repoRoot -ChildPath "SUMMARY.md"
if (Test-Path -Path $summaryFile) {
    $summaryContent = Get-Content -Path $summaryFile -Raw -Encoding UTF8
    $summaryMatches = [regex]::Matches($summaryContent, '\]\(([^)#:\s]+\.md)\)')
    $summarySet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($m in $summaryMatches) {
        [void]$summarySet.Add($m.Groups[1].Value.Replace('\', '/'))
    }

    $allRepoMd = Get-ChildItem -Path $repoRoot -Filter *.md -Recurse | Where-Object {
        $_.FullName -notlike "*\_book*" -and
        $_.FullName -notlike "*\node_modules*" -and
        $_.FullName -notlike "*\.git*" -and
        $_.FullName -notlike "*\.gemini*" -and
        $_.FullName -notlike "*\scratch*"
    }

    $ignoredMd = @("README.md", "SUMMARY.md", "TEMPLATE.md", "AGENTS.md", "AD-Hardening-Guidebook.md", "task.md")
    $missingFromSummary = @()

    foreach ($md in $allRepoMd) {
        $rel = $md.FullName.Substring($repoRoot.Length).TrimStart('\', '/').Replace('\', '/')
        $base = $md.Name
        if ($ignoredMd -contains $base -or $rel -like "*/AGENTS.md") {
            continue
        }
        if (-not $summarySet.Contains($rel)) {
            $missingFromSummary += $rel
        }
    }

    if ($missingFromSummary.Count -gt 0) {
        foreach ($unindexed in $missingFromSummary) {
            Write-Error "Unindexed file: '$unindexed' is missing from SUMMARY.md. Ensure it is linked in the corresponding module README.md and run 'py scripts/generate_summary.py'."
            $errorsCount++
        }
    }
    else {
        Write-Host "SUMMARY.md coverage check: PASSED (all requirements are indexed)" -ForegroundColor Green
    }
}
else {
    Write-Error "SUMMARY.md not found in repository root!"
    $errorsCount++
}

# 4. Verify XML Compliance Manifests
Write-Host "`nRunning compliance manifests validation..." -ForegroundColor Yellow
$pythonCandidates = @("py", "python3", "python")
$pythonExe = $null
foreach ($cand in $pythonCandidates) {
    if (Get-Command $cand -ErrorAction SilentlyContinue) {
        $testProcess = Start-Process $cand -ArgumentList "--version" -Wait -NoNewWindow -PassThru -ErrorAction SilentlyContinue
        if ($testProcess -and $testProcess.ExitCode -eq 0) {
            $pythonExe = $cand
            break
        }
    }
}
if ($null -eq $pythonExe) {
    $pythonExe = "py"
}

$validateScript = Join-Path -Path $repoRoot -ChildPath "scripts/validate_compliance.py"
$valProcess = Start-Process $pythonExe -ArgumentList "`"$validateScript`"" -Wait -NoNewWindow -PassThru
if ($valProcess.ExitCode -ne 0) {
    Write-Error "Compliance XML files validation failed!"
    $errorsCount++
}
else {
    Write-Host "Compliance XML files validation: PASSED" -ForegroundColor Green
}

Write-Host "`n-------------------------------------------" -ForegroundColor Cyan
if ($errorsCount -eq 0) {
    Write-Host "Verification PASSED. No broken links, syntax errors, or schema validation errors found!" -ForegroundColor Green
    exit 0
}
else {
    Write-Host "Verification FAILED with $errorsCount error(s)." -ForegroundColor Red
    exit 1
}
