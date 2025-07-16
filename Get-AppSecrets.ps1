<#
.SYNOPSIS
    Retrieves Entra ID app registration details including secrets information.

.DESCRIPTION
    This script connects to Microsoft Graph and retrieves app registration details including:
    - App ID (Application ID)
    - Display Name
    - Owners
    - Secret ID
    - Secret Hint (description)
    - Secret Expiration Date

.PARAMETER TenantId
    The Entra ID tenant ID. If not provided, will use the default tenant.

.PARAMETER OutputPath
    Optional path to export results to CSV file.

.PARAMETER ApplicationId
    Optional specific Application ID to retrieve. If not provided, retrieves all app registrations.

.PARAMETER Limit
    Optional limit on the number of app registrations to retrieve. Useful for testing with large tenants.

.EXAMPLE
    .\Get-EntraAppRegistrations.ps1
    Retrieves all app registrations from the default tenant.

.EXAMPLE
    .\Get-EntraAppRegistrations.ps1 -TenantId "12345678-1234-1234-1234-123456789012"
    Retrieves app registrations from a specific tenant.

.EXAMPLE
    .\Get-EntraAppRegistrations.ps1 -OutputPath "C:\temp\app-registrations.csv"
    Retrieves app registrations and exports to CSV file.

.EXAMPLE
    .\Get-EntraAppRegistrations.ps1 -ApplicationId "87654321-4321-4321-4321-210987654321"
    Retrieves details for a specific app registration.

.EXAMPLE
    .\Get-EntraAppRegistrations.ps1 -Limit 100
    Retrieves details for the first 100 app registrations (useful for testing).

.NOTES
    Requires Microsoft.Graph PowerShell module and appropriate permissions:
    - Application.Read.All
    - Application.ReadWrite.All (for secrets)
    
    Author: Generated Script
    Version: 1.0
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$TenantId,
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath,
    
    [Parameter(Mandatory = $false)]
    [string]$ApplicationId,
    
    [Parameter(Mandatory = $false)]
    [int]$Limit
)

# Error handling preference
$ErrorActionPreference = 'Stop'

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = 'Info'
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logMessage = "[$timestamp] [$Level] $Message"
    
    switch ($Level) {
        'Error' { Write-Error $logMessage }
        'Warning' { Write-Warning $logMessage }
        'Info' { Write-Host $logMessage -ForegroundColor Green }
        'Debug' { Write-Verbose $logMessage }
    }
}

function Test-ModuleInstalled {
    param([string]$ModuleName)
    
    $module = Get-Module -ListAvailable -Name $ModuleName
    if (-not $module) {
        Write-Log "Module $ModuleName is not installed. Please install it using: Install-Module -Name $ModuleName -Scope CurrentUser" -Level 'Error'
        throw "Required module $ModuleName is not installed"
    }
}

function Connect-ToGraph {
    param([string]$TenantId)
    
    try {
        Write-Log 'Connecting to Microsoft Graph...'
        
        $connectParams = @{
            Scopes = @('Application.Read.All', 'Application.ReadWrite.All')
        }
        
        if ($TenantId) {
            $connectParams.TenantId = $TenantId
        }
        
        Connect-MgGraph @connectParams
        
        $context = Get-MgContext
        Write-Log "Connected to tenant: $($context.TenantId)" -Level 'Info'
        
    }
    catch {
        Write-Log "Failed to connect to Microsoft Graph: $($_.Exception.Message)" -Level 'Error'
        throw
    }
}

function Get-AppRegistrationDetails {
    param(
        [string]$AppId,
        [int]$Limit
    )
    
    try {
        $applications = if ($AppId) {
            Write-Log "Retrieving specific app registration: $AppId"
            @(Get-MgApplication -Filter "appId eq '$AppId'")
        }
        else {
            Write-Log 'Retrieving all app registrations...'
            if ($Limit -gt 0) {
                Write-Log "Limiting results to first $Limit app registrations"
                Get-MgApplication -Top $Limit
            }
            else {
                Get-MgApplication -All
            }
        }
        
        if (-not $applications -or $applications.Count -eq 0) {
            Write-Log 'No app registrations found' -Level 'Warning'
            return @()
        }
        
        Write-Log "Found $($applications.Count) app registration(s)"
        
        $results = @()
        
        foreach ($app in $applications) {
            Write-Log "Processing app: $($app.DisplayName)"
            
            # Get owners
            $owners = @()
            try {
                $appOwners = Get-MgApplicationOwner -ApplicationId $app.Id
                $owners = $appOwners | ForEach-Object {
                    if ($_.AdditionalProperties.userPrincipalName) {
                        $_.AdditionalProperties.userPrincipalName
                    }
                    elseif ($_.AdditionalProperties.displayName) {
                        $_.AdditionalProperties.displayName
                    }
                    else {
                        $_.Id
                    }
                }
            }
            catch {
                Write-Log "Could not retrieve owners for app $($app.DisplayName): $($_.Exception.Message)" -Level 'Warning'
            }
            
            # Get password credentials (secrets)
            $secrets = $app.PasswordCredentials
            
            if ($secrets -and $secrets.Count -gt 0) {
                foreach ($secret in $secrets) {
                    # The API doesn't expose the actual secret value for security reasons
                    # We can only get the DisplayName (custom name) and Hint (if available)
                    $secretHint = if ($secret.Hint) { 
                        $secret.Hint 
                    }
                    elseif ($secret.DisplayName) { 
                        $secret.DisplayName 
                    }
                    else { 
                        'No hint available' 
                    }
                    
                    $results += [PSCustomObject]@{
                        AppId               = $app.AppId
                        DisplayName         = $app.DisplayName
                        Owners              = ($owners -join '; ')
                        SecretId            = $secret.KeyId
                        SecretHint          = $secretHint
                        SecretExpiration    = $secret.EndDateTime
                        SecretStartDate     = $secret.StartDateTime
                        DaysUntilExpiration = if ($secret.EndDateTime) { 
                            [math]::Round(($secret.EndDateTime - (Get-Date)).TotalDays, 0) 
                        }
                        else { 
                            $null 
                        }
                    }
                }
            }
            else {
                # Include apps without secrets
                $results += [PSCustomObject]@{
                    AppId               = $app.AppId
                    DisplayName         = $app.DisplayName
                    Owners              = ($owners -join '; ')
                    SecretId            = 'No secrets'
                    SecretHint          = 'No secrets'
                    SecretExpiration    = $null
                    SecretStartDate     = $null
                    DaysUntilExpiration = $null
                }
            }
        }
        
        return $results
        
    }
    catch {
        Write-Log "Error retrieving app registration details: $($_.Exception.Message)" -Level 'Error'
        throw
    }
}

# Main execution
try {
    Write-Log 'Starting Entra ID App Registration retrieval script'
    
    # Check required module
    Test-ModuleInstalled -ModuleName 'Microsoft.Graph'
    
    # Import the module
    Import-Module Microsoft.Graph -Force
    
    # Connect to Graph
    Connect-ToGraph -TenantId $TenantId
    
    # Get app registration details
    $appDetails = Get-AppRegistrationDetails -AppId $ApplicationId -Limit $Limit
    
    if ($appDetails.Count -gt 0) {
        # Display results
        Write-Log 'App Registration Details:'
        $appDetails | Format-Table -AutoSize
        
        # Export to CSV if path provided
        if ($OutputPath) {
            try {
                $appDetails | Export-Csv -Path $OutputPath -NoTypeInformation
                Write-Log "Results exported to: $OutputPath" -Level 'Info'
            }
            catch {
                Write-Log "Failed to export to CSV: $($_.Exception.Message)" -Level 'Error'
            }
        }
        
    }
    else {
        Write-Log 'No app registrations found matching the criteria' -Level 'Warning'
    }
    
}
catch {
    Write-Log "Script execution failed: $($_.Exception.Message)" -Level 'Error'
    exit 1
}
finally {
    # Disconnect from Graph
    try {
        if (Get-MgContext) {
            Disconnect-MgGraph
            Write-Log 'Disconnected from Microsoft Graph'
        }
    }
    catch {
        Write-Log "Error disconnecting from Graph: $($_.Exception.Message)" -Level 'Warning'
    }
}

Write-Log 'Script completed successfully'