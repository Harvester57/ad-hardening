# Verify-ADHardeningDocs.ps1
# Script to validate links and verify PowerShell syntax in all markdown files within the repository.

$scriptPath = $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptPath

Write-Host "Starting documentation validation in: $repoRoot" -ForegroundColor Cyan

$mdFiles = Get-ChildItem -Path $repoRoot -Filter *.md -Recurse | Where-Object {
    $_.FullName -notlike "*\.git*" -and
    $_.FullName -notlike "*\.gemini*" -and
    $_.FullName -notlike "*\node_modules*" -and
    $_.FullName -notlike "*\_book*" -and
    $_.Name -ne "AD-Hardening-Guidebook.md"
}
$errorsCount = 0

foreach ($file in $mdFiles) {
    Write-Host "`nChecking: $($file.FullName.Replace($repoRoot, ''))" -ForegroundColor Yellow
    $content = Get-Content -Path $file.FullName -Raw
    $fileDir = Split-Path -Parent $file.FullName

    # 1. Verify markdown relative links
    # Matches [text](link) where link doesn't start with http, file, or mailto
    # Group 1: text, Group 2: link, Group 3: anchor (if any)
    $linkRegex = '\[([^\]]+)\]\(([^)#:\s]+)(#[^)]*)?\)'
    $linkMatches = [regex]::Matches($content, $linkRegex)

    foreach ($match in $linkMatches) {
        $linkPath = $match.Groups[2].Value
        # Decode URL-encoded characters (like %20)
        $decodedLinkPath = [System.Uri]::UnescapeDataString($linkPath)

        # If it's a relative local file link
        if ($decodedLinkPath -notmatch '^https?://' -and $decodedLinkPath -notmatch '^mailto:' -and $decodedLinkPath -ne '') {
            $targetFullPath = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($fileDir, $decodedLinkPath))
            if (-not (Test-Path -Path $targetFullPath)) {
                Write-Error "Broken link in $($file.Name): '$decodedLinkPath' -> Resolved path '$targetFullPath' not found."
                $errorsCount++
            }
            else {
                Write-Verbose "Valid link: $decodedLinkPath"
            }
        }
    }

    # 2. Extract and syntax check PowerShell code blocks
    # Matches ```powershell ... ``` or ```ps1 ... ```
    $codeBlockRegex = '(?s)```(?:powershell|ps1)\r?\n(.*?)\r?\n```'
    $codeBlocks = [regex]::Matches($content, $codeBlockRegex)

    $blockIndex = 1
    foreach ($block in $codeBlocks) {
        $code = $block.Groups[1].Value

        # Parse PowerShell code syntax
        $tokens = $null
        $parseErrors = $null
        $null = [System.Management.Automation.Language.Parser]::ParseInput($code, [ref]$tokens, [ref]$parseErrors)

        if ($parseErrors) {
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
}

Write-Host "`n-------------------------------------------" -ForegroundColor Cyan
if ($errorsCount -eq 0) {
    Write-Host "Verification PASSED. No broken links or syntax errors found!" -ForegroundColor Green
    exit 0
}
else {
    Write-Host "Verification FAILED with $errorsCount error(s)." -ForegroundColor Red
    exit 1
}
