# Prerequisites:
# Install the Graph module if needed: Install-Module Microsoft.Graph -Scope CurrentUser
# Connect to Graph with appropriate permissions: Connect-MgGraph -Scopes "Application.Read.All","AppRoleAssignment.ReadWrite.All","Directory.Read.All"

Import-Module Microsoft.Graph

$apps = Get-MgApplication -All
$results = @()

foreach ($app in $apps) {
    # Get owners
    $owners = Get-MgApplicationOwner -ApplicationId $app.Id | Select-Object -ExpandProperty UserPrincipalName -ErrorAction SilentlyContinue
    if (-not $owners) { $owners = "None" }

    # Get permissions (AppRoles and RequiredResourceAccess)
    $permissions = @()

    # Application permissions (AppRoles)
    foreach ($role in $app.AppRoles) {
        if ($role.Value -match "write") {
            $permissions += [PSCustomObject]@{
                AppName         = $app.DisplayName
                AppId           = $app.AppId
                Owner           = $owners -join "; "
                PermissionName  = $role.Value
                PermissionType  = "Application"
                AdminConsent    = if ($role.AllowedMemberTypes -contains "Application") { "Yes" } else { "No" }
            }
        }
    }

    # Delegated permissions (OAuth2PermissionScopes)
    foreach ($scope in $app.Api.Oauth2PermissionScopes) {
        if ($scope.Value -match "write") {
            $permissions += [PSCustomObject]@{
                AppName         = $app.DisplayName
                AppId           = $app.AppId
                Owner           = $owners -join "; "
                PermissionName  = $scope.Value
                PermissionType  = "Delegated"
                AdminConsent    = if ($scope.AdminConsentDescription) { "Yes" } else { "No" }
            }
        }
    }

    $results += $permissions
}

# Export the results
$results  | Sort-Object AppName | Export-Csv -Path ".\cpEntra-App-Permissions-Report.csv" -NoTypeInformation
Write-Host "✅ App registration audit complete. Output saved to cpEntra-App-Permissions-Report.csv"