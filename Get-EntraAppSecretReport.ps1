<#
.SYNOPSIS
    Retrieves and lists details for all client secrets and certificates for all App Registrations in Entra ID.

.DESCRIPTION
    This script connects to Microsoft Graph to fetch all application registrations in the tenant.
    It then iterates through each application to find associated credentials (both client secrets and certificates).
    The details of each credential, including its name, type, expiry date, and a status are collected into a report.
    The status highlights if a credential is expired, expiring within 30 days, or has a long validity (> 6 months).
    The script can display the report in the console or export it to a CSV file.

.NOTES
    Author: Gemini Code Assist

    Prerequisites:
    - PowerShell 7+ is recommended.
    - The Microsoft.Graph.Applications module is required. Install it via:
      Install-Module Microsoft.Graph.Applications -Scope CurrentUser
    - You must be connected to Microsoft Graph with 'Application.Read.All' permissions.
      Connect using: Connect-MgGraph -Scopes "Application.Read.All"

.EXAMPLE
    .\Get-EntraAppSecretReport.ps1 -OutFile "C:\temp\AppSecretReport.csv"

    This command runs the script and exports the report of all app secrets and certificates
    to the specified CSV file. The output will be sorted by the credential end date.

.EXAMPLE
    .\Get-EntraAppSecretReport.ps1

    This command runs the script and displays the report as a table in the PowerShell console.
#>
[CmdletBinding()]
param (
    # The full path to the output CSV file. If not provided, output will be written to the host console.
    [Parameter(Mandatory = $false)]
    [string]
    $OutFile
)

#region Prerequisites Check
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Applications)) {
    Write-Error "The 'Microsoft.Graph.Applications' module is not installed. Please run 'Install-Module Microsoft.Graph.Applications -Scope CurrentUser' and try again."
    return
}

try {
    $context = Get-MgContext -ErrorAction Stop
    $requiredScope = 'Application.Read.All'
    if (-not ($context.Scopes -contains $requiredScope)) {
        Write-Warning "You might be missing required permissions. Please ensure you are connected with 'Connect-MgGraph -Scopes ""$requiredScope""'."
    }
}
catch {
    Write-Error "Connection to Microsoft Graph not found. Please run 'Connect-MgGraph -Scopes ""Application.Read.All""' before executing this script."
    return
}
#endregion

Write-Host 'Fetching all application registrations. This may take a while for large tenants...' -ForegroundColor Yellow

try {
    # Get all applications. The -All parameter handles pagination automatically.
    $applications = Get-MgApplication -All -ErrorAction Stop
}
catch {
    Write-Error "Failed to retrieve applications. Error: $($_.Exception.Message)"
    return
}

if (-not $applications) {
    Write-Warning 'No application registrations were found in the tenant.'
    return
}

#region Helper Function
function Get-CredentialStatus {
    param(
        [datetime]$EndDate
    )
    # These date variables are defined in the parent script scope
    if ($EndDate -lt $today) {
        return 'Expired'
    }
    elseif ($EndDate -lt $thirtyDaysFromNow) {
        return 'Expires within 30 days'
    }
    elseif ($EndDate -gt $sixMonthsFromNow) {
        return 'Valid > 6 months'
    }
    else {
        return 'OK (Expires in 1-6 months)'
    }
}
#endregion

Write-Host "Found $($applications.Count) applications. Reviewing all credentials..." -ForegroundColor Green

$report = [System.Collections.Generic.List[object]]::new()

$today = (Get-Date).Date
$thirtyDaysFromNow = $today.AddDays(30)
$sixMonthsFromNow = $today.AddMonths(6)

foreach ($app in $applications) {
    # Get owners for the application
    try {
        $owners = Get-MgApplicationOwner -ApplicationId $app.Id -ErrorAction Stop
        $ownerNames = if ($owners) {
            $owners | ForEach-Object {
                if ($_.AdditionalProperties.ContainsKey('userPrincipalName')) { $_.AdditionalProperties.userPrincipalName } elseif ($_.DisplayName) { $_.DisplayName } else { $_.Id }
            } | Sort-Object | Select-Object -Unique # | -join ', '
        }
        else {
            'None'
        }
    }
    catch {
        $ownerNames = 'Error retrieving owners'
    }

    # Process Password Credentials (Client Secrets)
    foreach ($secret in $app.PasswordCredentials) {
        $endDate = $secret.EndDateTime
        $report.Add([PSCustomObject]@{
                ApplicationName = $app.DisplayName
                ApplicationId   = $app.AppId
                Owners          = $ownerNames
                CredentialType  = 'Client Secret'
                CredentialName  = $secret.DisplayName
                KeyId           = $secret.KeyId
                StartDate       = $secret.StartDateTime
                EndDate         = $endDate
                DaysRemaining   = [math]::Floor(($endDate - $today).TotalDays)
                Status          = Get-CredentialStatus -EndDate $endDate
            })
    }

    # Process Key Credentials (Certificates)
    foreach ($cert in $app.KeyCredentials) {
        $endDate = $cert.EndDateTime
        $report.Add([PSCustomObject]@{
                ApplicationName = $app.DisplayName
                ApplicationId   = $app.AppId
                Owners          = $ownerNames
                CredentialType  = 'Certificate'
                CredentialName  = $cert.DisplayName
                KeyId           = $cert.KeyId
                StartDate       = $cert.StartDateTime
                EndDate         = $endDate
                DaysRemaining   = [math]::Floor(($endDate - $today).TotalDays)
                Status          = Get-CredentialStatus -EndDate $endDate
            })
    }
}

Write-Host "Credential review complete. Found $($report.Count) total credentials." -ForegroundColor Green

if ($report.Count -gt 0) {
    $sortedReport = $report | Sort-Object -Property DaysRemaining
    if ($PSBoundParameters.ContainsKey('OutFile')) {
        $sortedReport | Export-Csv -Path $OutFile -NoTypeInformation -Encoding UTF8BOM
        Write-Host "Report successfully exported to $OutFile" -ForegroundColor Green
    }
    else {
        $sortedReport | Format-Table
    }
}