param (
    [Parameter(Mandatory)]
    [string]$ScanPath,

    [string]$LogFile = "$env:TEMP\suspected_secrets_log.txt"
)

# Define regex patterns for secrets
$patterns = @(
    'password\s*=\s*["''][^"'']{4,}["'']',
    'client[_-]?secret\s*=\s*["''][^"'']{4,}["'']',
    'secret\s*=\s*["''][^"'']{4,}["'']',
    'apikey\s*=\s*["''][^"'']{4,}["'']',
    'token\s*=\s*["''][^"'']{4,}["'']',
    'connectionstring\s*=\s*["''][^"'']{10,}["'']',
    'access[_-]?key\s*=\s*["''][^"'']{4,}["'']',
    '[\w\-]{16,}\.[\w\-]{16,}\.[\w\-]{16,}'  # JWT-like
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