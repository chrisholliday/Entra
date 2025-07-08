<#
.SYNOPSIS
    Scans files in a directory for suspected secrets using regex patterns.

.DESCRIPTION
    This script recursively scans all files in the specified directory for lines that may contain secrets such as passwords, API keys, tokens, and connection strings. It uses regular expressions to match common secret variable names and assignment styles, including JWT tokens. Any file containing a suspected secret is logged to an output file for review.

.PARAMETER ScanPath
    The root directory to scan for suspected secrets.

.PARAMETER LogFile
    The path to the log file where results will be written. Defaults to $env:TEMP\suspected_secrets_log.txt.

.EXAMPLE
    .\Find-SuspectedSecrets.ps1 -ScanPath C:\Projects\MyApp

.NOTES
    - Only file paths containing suspected secrets are logged (not the actual secret values).
    - Update the regex patterns as needed to improve detection for your environment.
    - Author: Chris Holliday
    - Date: 2024-07-04
#>

param (
    [Parameter(Mandatory)]
    [string]$ScanPath,

    [string]$LogFile = "$env:TEMP\suspected_secrets_log.txt"
)

# Improved regex pattern for secrets (case-insensitive, supports = or :, optional quotes, more variable names)
$patterns = @(
    # Common secret variable names and assignment styles
    '(?i)(password|pass|pwd|secret|client[_-]?secret|apikey|api[_-]?key|token|connectionstring|access[_-]?key|auth|auth[_-]?token|key)\s*[:=]\s*["\'`]?(?!\s)([^"\'`\s]{4,}|[\w\-]{16,}\.[\w\-]{16,}\.[\w\-]{16,})["\'`]?'  # General secrets and JWTs
)

Write-Host "`n🔍 Scanning directory:` $ScanPath" -ForegroundColor Cyan
Write-Host "🧵 Patterns loaded: $($patterns.Count)" -ForegroundColor Cyan
Write-Host "📝 Logging output to:` $LogFile`n" -ForegroundColor Yellow

Remove-Item -Path $LogFile -ErrorAction SilentlyContinue

# Scan files recursively
Get-ChildItem -Path $ScanPath -Recurse -File | ForEach-Object {
    $filePath = $_.FullName
    foreach ($pattern in $patterns) {
        $matches = Select-String -Path $filePath -Pattern $pattern -AllMatches
        if ($matches) {
            $logEntry = "$filePath"
            Add-Content -Path $LogFile -Value $logEntry
            break
        }
    }
}

Write-Host "✅ Scan complete. Review results in:` $LogFile`n" -ForegroundColor Green