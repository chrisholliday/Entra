<#
.SYNOPSIS
    Generates a report of Entra ID App Registrations with Application (App-only) API permissions.

.DESCRIPTION
    This script searches all Entra ID App Registrations and identifies those with Application API permissions.
    It resolves permission names, identifies owners, determines if the permission is Read or Write,
    and checks if Admin Consent has been granted.
    The output is exported to a CSV file.

.NOTES
    File Name: Get-EntraAppRoleAssignmentsReport.ps1
    Author: GitHub Copilot
    Date: November 19, 2025
#>

# Check for Microsoft.Graph module
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
    Write-Warning "Microsoft.Graph module not found. Please install it using 'Install-Module Microsoft.Graph -Scope CurrentUser'."
    return
}

# Connect to Microsoft Graph
try {
    Write-Host "Connecting to Microsoft Graph..."
    Connect-MgGraph -Scopes "Application.Read.All", "Directory.Read.All", "User.Read.All" -ErrorAction Stop
    Write-Host "Connected successfully."
} catch {
    Write-Error "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
    return
}

# Helper function to resolve Service Principal Name
$servicePrincipalCache = @{}
function Get-ServicePrincipalName {
    param ([string]$AppId)
    if ($servicePrincipalCache.ContainsKey($AppId)) { return $servicePrincipalCache[$AppId] }
    
    try {
        $sp = Get-MgServicePrincipal -Filter "appId eq '$AppId'" -ErrorAction SilentlyContinue | Select-Object -First 1
        $name = if ($sp) { $sp.DisplayName } else { "Unknown ($AppId)" }
        $servicePrincipalCache[$AppId] = $name
        return $name
    } catch {
        return "Error Resolving ($AppId)"
    }
}

# Helper function to resolve Permission Name
$permissionCache = @{}
function Get-PermissionName {
    param (
        [string]$ResourceAppId,
        [string]$PermissionId
    )
    $cacheKey = "$ResourceAppId-$PermissionId"
    if ($permissionCache.ContainsKey($cacheKey)) { return $permissionCache[$cacheKey] }

    try {
        $sp = Get-MgServicePrincipal -Filter "appId eq '$ResourceAppId'" -Property "AppRoles" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($sp -and $sp.AppRoles) {
            $role = $sp.AppRoles | Where-Object { $_.Id -eq $PermissionId }
            if ($role) {
                $name = "$($role.Value)"
                # Append DisplayName if different and available
                if ($role.DisplayName -and $role.DisplayName -ne $role.Value) {
                    $name += " ($($role.DisplayName))"
                }
                $permissionCache[$cacheKey] = $name
                return $name
            }
        }
    } catch {
        Write-Warning "Error resolving permission $PermissionId for resource $ResourceAppId"
    }
    
    $name = "Unknown Permission ($PermissionId)"
    $permissionCache[$cacheKey] = $name
    return $name
}

# Helper function to get Owners
function Get-AppOwners {
    param ([string]$AppId)
    $ownersList = @()
    try {
        $owners = Get-MgApplicationOwner -ApplicationId $AppId -ErrorAction SilentlyContinue
        foreach ($owner in $owners) {
            if ($owner.AdditionalProperties.ContainsKey('userPrincipalName')) {
                $ownersList += $owner.AdditionalProperties['userPrincipalName']
            } elseif ($owner.AdditionalProperties.ContainsKey('displayName')) {
                $ownersList += $owner.AdditionalProperties['displayName']
            } else {
                $ownersList += $owner.Id
            }
        }
    } catch {
        $ownersList += "Error retrieving owners"
    }
    return ($ownersList -join "; ")
}

# Main Logic
$report = @()

Write-Host "Retrieving all App Registrations..."
$apps = Get-MgApplication -All -Property Id, AppId, DisplayName, RequiredResourceAccess -ErrorAction Stop
Write-Host "Found $($apps.Count) applications."

foreach ($app in $apps) {
    # Skip apps with no required resources
    if (-not $app.RequiredResourceAccess) { continue }

    # Check if app has ANY Application permissions requested
    $hasAppPermissions = $false
    foreach ($r in $app.RequiredResourceAccess) {
        if ($r.ResourceAccess | Where-Object { $_.Type -eq "Role" }) {
            $hasAppPermissions = $true
            break
        }
    }
    if (-not $hasAppPermissions) { continue }

    Write-Host "Processing App: $($app.DisplayName)"
    
    # Get Owners
    $owners = Get-AppOwners -AppId $app.Id

    # Get Service Principal for the App (to check consent)
    $appSp = Get-MgServicePrincipal -Filter "appId eq '$($app.AppId)'" -ErrorAction SilentlyContinue | Select-Object -First 1
    $grantedRoles = @()
    if ($appSp) {
        # Get all app role assignments for this service principal
        $assignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $appSp.Id -ErrorAction SilentlyContinue
        if ($assignments) {
            $grantedRoles = $assignments.AppRoleId
        }
    }

    foreach ($req in $app.RequiredResourceAccess) {
        $resourceName = Get-ServicePrincipalName -AppId $req.ResourceAppId
        
        foreach ($access in $req.ResourceAccess) {
            # Filter for Application Permissions (Type == "Role")
            if ($access.Type -ne "Role") { continue }

            $permName = Get-PermissionName -ResourceAppId $req.ResourceAppId -PermissionId $access.Id
            
            # Determine Access Type (Read vs Write)
            $accessType = "Read"
            if ($permName -match "Write|Manage|Full|Delete|Create|Update|Modify") {
                $accessType = "Write"
            }

            # Check Admin Consent
            # If the permission ID is in the list of granted roles for the service principal, it is consented.
            $consentStatus = "Not Granted"
            if ($grantedRoles -contains $access.Id) {
                $consentStatus = "Granted"
            }

            $report += [PSCustomObject]@{
                ApplicationDisplayName = $app.DisplayName
                ApplicationId          = $app.AppId
                Owners                 = $owners
                ResourceName           = $resourceName
                PermissionName         = $permName
                PermissionType         = "Application"
                AccessType             = $accessType
                AdminConsent           = $consentStatus
            }
        }
    }
}

# Export to CSV
$csvPath = ".\EntraAppRoleAssignmentsReport.csv"
$report | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
Write-Host "Report exported to $csvPath"
