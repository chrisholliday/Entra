# filepath: c:\Users\chris\OneDrive\scripts\Entra GUID\entra-app-permission-lookup\src\Get-AppPermissionDescriptions.ps1

<#
.SYNOPSIS
    Retrieves all existing application and delegated permission GUIDs from key Microsoft services and translates them into their corresponding text descriptions.

.DESCRIPTION
    This script connects to Microsoft Graph, fetches all application and delegated permissions for key Microsoft services
    (like Microsoft Graph, SharePoint, Exchange, Purview, etc.), and outputs their GUIDs along with their text descriptions and type.
    It requires the Microsoft Graph PowerShell SDK to be installed and appropriate permissions to access the service principal data.

.NOTES
    Author: Chris Holliday
    Date: July 2024
    Version: 2.0

.PREREQUISITES
    - PowerShell 5.1 or later (Windows) / PowerShell 7+ (cross-platform)
    - Microsoft Graph PowerShell SDK module installed.
      If not installed, run: Install-Module Microsoft.Graph -Scope CurrentUser

.USAGE
    1. Open PowerShell.
    2. Run the script.
    3. You will be prompted to authenticate to Microsoft Graph. Ensure you have sufficient permissions (e.g., Application.Read.All, and potentially Exchange Administrator for the RBAC audit).
    4. The output will be saved to CSV files in the current directory.

.EXAMPLE
    .\Get-AppPermissionDescriptions.ps1

.EXAMPLE
    .\Get-AppPermissionDescriptions.ps1 -IncludeExchangeRbacAudit
    This command generates the API permission lookup file and also performs an audit of Exchange Online RBAC roles assigned to applications, creating a second CSV file.

.INPUTS
    None.

.OUTPUTS
    A CSV file named 'EntraApiPermissions.csv' containing the permission details for the specified APIs.
    If -IncludeExchangeRbacAudit is used, a second CSV file named 'ExchangeRbacAssignments.csv' is also created.
#>

[CmdletBinding()]
param (
    # Switch to also perform an audit of administrative roles assigned directly to applications within Exchange Online.
    [switch]$IncludeExchangeRbacAudit
)

#region Install and Connect to Microsoft Graph
Write-Host 'Checking for Microsoft Graph PowerShell SDK module...'
try {
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
        Write-Host 'Microsoft.Graph module not found. Attempting to install...'
        Install-Module Microsoft.Graph -Scope CurrentUser -Force -Confirm:$false -ErrorAction Stop
        Write-Host 'Microsoft.Graph module installed successfully.'
    }
    else {
        Write-Host 'Microsoft.Graph module found.'
    }

    Write-Host 'Connecting to Microsoft Graph. You will be prompted to authenticate...'
    Connect-MgGraph -Scopes 'Application.Read.All' -ErrorAction Stop
    Write-Host 'Successfully connected to Microsoft Graph.'

}
catch {
    Write-Error "Failed to connect to Microsoft Graph or install module: $($_.Exception.Message)"
    Write-Host 'Please ensure you have the necessary permissions and try again.'
    exit 1
}
#endregion

#region Main Script Logic

Write-Host 'Retrieving API permissions...'
$allPermissions = @()

$targetApis = @(
    @{ AppId = '00000003-0000-0000-c000-000000000000'; Name = 'Microsoft Graph' };
    @{ AppId = '00000002-0000-0000-c000-000000000000'; Name = 'Office 365 Exchange Online' };
    @{ AppId = '00000003-0000-0ff1-ce00-000000000000'; Name = 'Office 365 SharePoint Online' };
    @{ AppId = 'c5393580-f805-4401-95e8-94b7a6ef2fc2'; Name = 'Office 365 Management APIs' };
    @{ AppId = 'd3c6a767-6503-4075-b2a0-5c5519f1d93e'; Name = 'Microsoft Purview' }; # Formerly Azure Purview
    @{ AppId = 'cc15fd57-2c6c-4117-a88c-83b1d56b4bbe'; Name = 'Configuration Manager Microservice' };
    @{ AppId = '0000000a-0000-0000-c000-000000000000'; Name = 'Microsoft Intune API' };
    @{ AppId = '00000013-0000-0000-c000-000000000000'; Name = 'Microsoft Information Protection Sync Service' };
    @{ AppId = '00000012-0000-0000-c000-000000000000'; Name = 'Microsoft Rights Management Services' };
    @{ AppId = '00000009-0000-0000-c000-000000000000'; Name = 'Power BI Service' }
)

try {
    foreach ($api in $targetApis) {
        Write-Host "Fetching permissions for $($api.Name)..."
        $sp = Get-MgServicePrincipal -Filter "appId eq '$($api.AppId)'" -Property 'AppRoles,Oauth2PermissionScopes' -ErrorAction Stop
        
        if ($sp) {
            # Process Application permissions (AppRoles)
            if ($sp.AppRoles) {
                $appRoles = $sp.AppRoles | Select-Object @{Name = 'Resource'; Expression = { $api.Name } }, Id, Value, DisplayName, @{Name = 'PermissionType'; Expression = { 'Application' } }
                $allPermissions += $appRoles
            }

            # Process Delegated permissions (Oauth2PermissionScopes)
            if ($sp.Oauth2PermissionScopes) {
                $delegatedScopes = $sp.Oauth2PermissionScopes | Select-Object @{Name = 'Resource'; Expression = { $api.Name } }, Id, Value, DisplayName, @{Name = 'PermissionType'; Expression = { 'Delegated' } }
                $allPermissions += $delegatedScopes
            }

            # For Exchange Online, manually add the well-known 'full_access_as_app' permission if it wasn't found dynamically.
            # This permission is sometimes not exposed via the service principal's AppRoles property by default.
            if ($api.Name -eq 'Office 365 Exchange Online') {
                $fullAccessPermissionId = 'dc890d15-9560-4a4c-9b7f-a736ec7435a4'
                if (-not ($allPermissions.Id -contains $fullAccessPermissionId)) {
                    Write-Host "Manually adding well-known 'full_access_as_app' permission for Exchange Online."
                    $allPermissions += [PSCustomObject]@{
                        Resource       = 'Office 365 Exchange Online'
                        Id             = $fullAccessPermissionId
                        Value          = 'full_access_as_app'
                        DisplayName    = 'Access to all mailboxes as an app'
                        PermissionType = 'Application'
                    }
                }
            }
        }
        else {
            Write-Warning "Could not find Service Principal for $($api.Name) (AppId: $($api.AppId))"
        }
    }

    if ($allPermissions.Count -gt 0) {
        Write-Host "Found $($allPermissions.Count) total permissions."
        $csvPath = 'EntraApiPermissions.csv'
        $allPermissions | Sort-Object Resource, PermissionType, DisplayName | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        Write-Host "Exported permission list to '$csvPath' in the current directory."
    }
    else {
        Write-Host 'No permissions found for the specified APIs.'
    }
}
catch {
    Write-Error "Failed to retrieve API permissions: $($_.Exception.Message)"
}
finally {
    Write-Host 'Disconnecting from Microsoft Graph.'
    Disconnect-MgGraph
}

#endregion

#region Optional: Audit Exchange Online RBAC Roles
if ($IncludeExchangeRbacAudit) {
    Write-Host "`n--- Exchange Online RBAC Audit ---"
    try {
        # Check for ExchangeOnlineManagement module
        if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
            Write-Host 'ExchangeOnlineManagement module not found. Attempting to install...'
            Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force -Confirm:$false -ErrorAction Stop
            Write-Host 'ExchangeOnlineManagement module installed successfully.'
        }

        # Connect to Exchange Online
        Write-Host 'Connecting to Exchange Online. You may be prompted to authenticate again...'
        # Suppress the banner on subsequent connections
        $null = Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
        Write-Host 'Successfully connected to Exchange Online.'

        Write-Host 'Auditing Exchange Online RBAC role assignments for applications...'
        $rbacAssignments = @()
        
        # Get all service principals that have role assignments in Exchange Online
        $roleAssignments = Get-ManagementRoleAssignment -App -ResultSize Unlimited -ErrorAction Stop

        if ($roleAssignments) {
            Write-Host "Found $($roleAssignments.Count) RBAC role assignments to applications."
            foreach ($assignment in $roleAssignments) {
                $rbacAssignments += [PSCustomObject]@{
                    AppName          = $assignment.App.DisplayName
                    AppId            = $assignment.App.AppId
                    Role             = $assignment.Role
                    RoleAssigneeName = $assignment.RoleAssigneeName
                }
            }
        }

        if ($rbacAssignments.Count -gt 0) {
            $rbacCsvPath = 'ExchangeRbacAssignments.csv'
            $rbacAssignments | Sort-Object AppName, Role | Export-Csv -Path $rbacCsvPath -NoTypeInformation -Encoding UTF8
            Write-Host "Exported Exchange RBAC audit to '$rbacCsvPath' in the current directory."
        }
        else {
            Write-Host 'No direct Exchange Online RBAC role assignments found for applications.'
        }

    }
    catch {
        Write-Error "An error occurred during the Exchange Online RBAC audit: $($_.Exception.Message)"
    }
    finally {
        # Disconnect from Exchange Online if a session is active
        if (Get-PSSession -InstanceId (Get-ConnectionInformation).InstanceId -ErrorAction SilentlyContinue) {
            Write-Host 'Disconnecting from Exchange Online.'
            Disconnect-ExchangeOnline -Confirm:$false
        }
    }
}
#endregion