# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Application.Read.All", "ServicePrincipal.Read.All", "Directory.Read.All", "AppRoleAssignment.Read.All"

# Define an array to store the results
$appReport = @()

# Get all application registrations
$applications = Get-MgApplication -All

foreach ($app in $applications) {
    $appName = $app.DisplayName
    $appId = $app.AppId
    $objectId = $app.Id

    # Get owners
    $owners = @()
    try {
        $appOwners = Get-MgApplicationOwner -ApplicationId $objectId -All
        foreach ($owner in $appOwners) {
            # ...owner resolution logic...
        }
    } catch {
        # ...error handling...
    }
    $ownersString = ($owners | Select-Object -Unique) -join "; "

    # Get API Permissions
    $delegatedPermissions = @()
    $applicationPermissions = @()

    # Permissions are typically granted to the Service Principal associated with the application
    $servicePrincipal = Get-MgServicePrincipal -Filter "appId eq '$appId'" -ErrorAction SilentlyContinue

    if ($servicePrincipal) {
        # ...delegated and application permissions logic...
    }

    # Add to the report
    $appReport += [PSCustomObject]@{
        AppName                = $appName
        AppId                  = $appId
        ObjectId               = $objectId
        Owners                 = $ownersString
        DelegatedPermissions   = ($delegatedPermissions | Select-Object -Unique) -join "; "
        ApplicationPermissions = ($applicationPermissions | Select-Object -Unique) -join "; "
    }
}

# Output the report to a grid view
$appReport | Out-GridView -Title "Entra ID Application Registrations Security Audit"

# Optionally, export to CSV
$outputPath = "C:\Temp\Entra_AppRegistrations_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
$appReport | Export-Csv -Path $outputPath -NoTypeInformation -Encoding UTF8

Write-Host "Report saved to: $outputPath"