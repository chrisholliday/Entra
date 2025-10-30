<#
.SYNOPSIS
    Modifies the group membership of an Entra ID user using app registration authentication.

.DESCRIPTION
    This script adds or removes a user from an Entra ID group.
    Requires the Microsoft.Graph.Groups and Microsoft.Graph.Users modules.
    Authenticates using an Entra App registration with either client secret or certificate.

.PARAMETER UserPrincipalName
    The User Principal Name (UPN) or Object ID of the user.

.PARAMETER GroupName
    The display name or Object ID of the group.

.PARAMETER Action
    The action to perform: Add or Remove. Default is Add.

.PARAMETER TenantId
    The Tenant ID for app registration authentication.

.PARAMETER ClientId
    The Application (Client) ID of the Entra App registration.

.PARAMETER ClientSecret
    The client secret for the app registration (as SecureString).

.PARAMETER CertificateThumbprint
    The certificate thumbprint for certificate-based authentication.

.EXAMPLE
    # Using App Registration with Client Secret
    $secret = ConvertTo-SecureString "your-client-secret" -AsPlainText -Force
    .\Set-EntraUserGroupMembership.ps1 -UserPrincipalName "user@domain.com" -GroupName "Sales Team" -TenantId "your-tenant-id" -ClientId "your-client-id" -ClientSecret $secret

.EXAMPLE
    # Using App Registration with Certificate
    .\Set-EntraUserGroupMembership.ps1 -UserPrincipalName "user@domain.com" -GroupName "Sales Team" -TenantId "your-tenant-id" -ClientId "your-client-id" -CertificateThumbprint "your-cert-thumbprint"

.EXAMPLE
    # Remove user from group using Client Secret
    $secret = ConvertTo-SecureString "your-client-secret" -AsPlainText -Force
    .\Set-EntraUserGroupMembership.ps1 -UserPrincipalName "user@domain.com" -GroupName "Sales Team" -Action Remove -TenantId "your-tenant-id" -ClientId "your-client-id" -ClientSecret $secret
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$UserPrincipalName,

    [Parameter(Mandatory = $true)]
    [string]$GroupName,

    [Parameter(Mandatory = $false)]
    [ValidateSet("Add", "Remove")]
    [string]$Action = "Add",

    [Parameter(Mandatory = $true)]
    [string]$TenantId,

    [Parameter(Mandatory = $true)]
    [string]$ClientId,

    [Parameter(Mandatory = $false)]
    [SecureString]$ClientSecret,

    [Parameter(Mandatory = $false)]
    [string]$CertificateThumbprint
)

# Check if Microsoft.Graph modules are installed
$requiredModules = @("Microsoft.Graph.Authentication", "Microsoft.Graph.Groups", "Microsoft.Graph.Users")
foreach ($module in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        Write-Error "Required module '$module' is not installed. Please install it using: Install-Module $module"
        exit 1
    }
}

try {
    # Validate that either ClientSecret or CertificateThumbprint is provided
    if (-not $ClientSecret -and -not $CertificateThumbprint) {
        Write-Error "You must provide either -ClientSecret or -CertificateThumbprint for app registration authentication"
        exit 1
    }

    # Connect to Microsoft Graph using App Registration
    Write-Host "Authenticating with App Registration..."
    
    if ($ClientSecret) {
        # Authenticate with Client Secret
        $clientSecretCredential = New-Object System.Management.Automation.PSCredential($ClientId, $ClientSecret)
        Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $clientSecretCredential -NoWelcome
        Write-Host "Connected using Client Secret" -ForegroundColor Green
    }
    else {
        # Authenticate with Certificate
        Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint -NoWelcome
        Write-Host "Connected using Certificate" -ForegroundColor Green
    }

    # Get the user
    Write-Host "Looking up user: $UserPrincipalName"
    $user = Get-MgUser -Filter "userPrincipalName eq '$UserPrincipalName'" -ErrorAction Stop
    if (-not $user) {
        # Try as Object ID
        $user = Get-MgUser -UserId $UserPrincipalName -ErrorAction Stop
    }
    Write-Host "Found user: $($user.DisplayName) ($($user.UserPrincipalName))"

    # Get the group
    Write-Host "Looking up group: $GroupName"
    $group = Get-MgGroup -Filter "displayName eq '$GroupName'" -ErrorAction Stop
    if (-not $group) {
        # Try as Object ID
        $group = Get-MgGroup -GroupId $GroupName -ErrorAction Stop
    }
    Write-Host "Found group: $($group.DisplayName)"

    # Perform the action
    if ($Action -eq "Add") {
        Write-Host "Adding user to group..."
        New-MgGroupMember -GroupId $group.Id -DirectoryObjectId $user.Id -ErrorAction Stop
        Write-Host "Successfully added $($user.DisplayName) to $($group.DisplayName)" -ForegroundColor Green
    }
    elseif ($Action -eq "Remove") {
        Write-Host "Removing user from group..."
        Remove-MgGroupMemberByRef -GroupId $group.Id -DirectoryObjectId $user.Id -ErrorAction Stop
        Write-Host "Successfully removed $($user.DisplayName) from $($group.DisplayName)" -ForegroundColor Green
    }
}
catch {
    Write-Error "An error occurred: $_"
    exit 1
}
