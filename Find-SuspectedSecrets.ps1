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
[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [ValidateScript({Test-Path $_ -PathType Container})]
    [string]$ScanPath,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$LogFile = "$env:TEMP\suspected_secrets_log.txt"
)

# Initialize error handling
$ErrorActionPreference = 'Stop'

# Improved regex pattern for secrets (case-insensitive, supports = or :, optional quotes, more variable names)
$patterns = @(
    # Common secret variable names and assignment styles
    '(?i)(password|pass|pwd|secret|client[_-]?secret|apikey|api[_-]?key|token|connectionstring|access[_-]?key|auth|auth[_-]?token|key)\s*[:=]\s*[\x22\x27\x60]?(?!\s)([^\x22\x27\x60\s]{4,}|[\w\-]{16,}\.[\w\-]{16,}\.[\w\-]{16,})[\x22\x27\x60]?'  # General secrets and JWTs
)

Write-Verbose "Starting secret scan in directory: $ScanPath"
Write-Host "`n🔍 Scanning directory: $ScanPath" -ForegroundColor Cyan
Write-Host "🧵 Patterns loaded: $($patterns.Count)" -ForegroundColor Cyan
Write-Host "📝 Logging output to: $LogFile`n" -ForegroundColor Yellow

# Ensure log file directory exists
$logDir = Split-Path -Parent $LogFile
if (-not (Test-Path -Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
}
Remove-Item -Path $LogFile -ErrorAction SilentlyContinue

# Scan files recursively
try {
    $files = Get-ChildItem -Path $ScanPath -Recurse -File -ErrorAction Stop
    $fileCount = $files.Count
    $processedFiles = 0

    foreach ($file in $files) {
        $processedFiles++
        Write-Progress -Activity "Scanning for secrets" -Status "Processing file $processedFiles of $fileCount" `
            -PercentComplete (($processedFiles / $fileCount) * 100)

        $filePath = $file.FullName
        try {
            foreach ($pattern in $patterns) {
                $matches = Select-String -Path $filePath -Pattern $pattern -ErrorAction Stop
                if ($matches) {
                    foreach ($match in $matches) {
                        $logEntry = "$filePath`tLine $($match.LineNumber)"
                        Add-Content -Path $LogFile -Value $logEntry
                    }
                    break # Move to next file once a match is found and logged
                }
            }
        }
        catch {
            Write-Warning "Could not scan file '$filePath'. Error: $_"
        }
    }
}
catch {
    Write-Error "Failed to scan directory: $_"
    return
}
finally {
    Write-Progress -Activity "Scanning for secrets" -Completed
}

if (Test-Path -Path $LogFile) {
    Write-Host "✅ Scan complete. Results saved to: $LogFile`n" -ForegroundColor Green
}
else {
    Write-Host "✅ Scan complete. No suspected secrets found.`n" -ForegroundColor Green
}