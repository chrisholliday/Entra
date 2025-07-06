<#
.SYNOPSIS
    Bulk creates Microsoft Entra ID security groups from a CSV file.
.DESCRIPTION
    This script reads group information from a specified CSV file and creates non-mail-enabled 
    security groups in Microsoft Entra ID using the Microsoft Graph API.
    It assigns up to two owners for each group as specified in the CSV.

    The script requires the Microsoft.Graph.Identity.DirectoryManagement and Microsoft.Graph.Users modules to be pre-installed.
    If the modules are not present, the script will fail to run.

    The user running the script will be prompted to authenticate interactively and must have 
    sufficient permissions (e.g., Groups Administrator or User Administrator).
.PARAMETER CsvPath
    The full path to the CSV file containing the group definitions.
    The CSV must contain the following headers: DisplayName, Description, MailNickname, Owner1UPN, Owner2UPN.
.EXAMPLE
    .\New-EntraGroupsFromCsv.ps1 -CsvPath "C:\Users\chris\OneDrive\scripts\Azure\NewGroups.csv"

    This command runs the script and creates groups based on the content of NewGroups.csv.
.NOTES
    Author: Gemini Code Assist
    Version: 1.1
    Requires: 
    - PowerShell 5.1 or later
    - Microsoft.Graph.Identity.DirectoryManagement module
    - Microsoft.Graph.Users module
#>

#Requires -Modules Microsoft.Graph.Identity.DirectoryManagement, Microsoft.Graph.Users

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, HelpMessage = "Please provide the full path to the CSV file.")]
    [string]$CsvPath
)

# --- Script Start ---

# 1. Connect to Microsoft Graph with required permissions
try {
    Write-Host "Connecting to Microsoft Graph..."
    # Scopes required: Create groups and read user profiles to assign owners.
    $scopes = @('Group.ReadWrite.All', 'User.Read.All')
    Connect-MgGraph -Scopes $scopes
    Write-Host "Successfully connected to Microsoft Graph." -ForegroundColor Green
}
catch {
    Write-Error "Failed to connect to Microsoft Graph. Please check your permissions and internet connection."
    throw
}

# 2. Import and validate the CSV file
if (-not (Test-Path -Path $CsvPath)) {
    Write-Error "CSV file not found at path: $CsvPath"
    throw
}

try {
    $groupsToCreate = Import-Csv -Path $CsvPath
}
catch {
    Write-Error "Failed to read the CSV file. Please ensure it is a valid CSV."
    throw
}

$requiredHeaders = @('DisplayName', 'Description', 'MailNickname', 'Owner1UPN', 'Owner2UPN')
foreach ($header in $requiredHeaders) {
    if ($header -notin $groupsToCreate[0].PSObject.Properties.Name) {
        Write-Error "CSV file is missing the required header: '$header'. Please correct the file and try again."
        throw
    }
}

Write-Host "CSV file loaded successfully. Starting group creation process..."

# 3. Loop through each row in the CSV and create the group
foreach ($row in $groupsToCreate) {
    $displayName = $row.DisplayName
    $mailNickname = $row.MailNickname

    Write-Host "--------------------------------------------------"
    Write-Host "Processing Group: '$displayName'"

    # Skip if essential fields are empty
    if ([string]::IsNullOrWhiteSpace($displayName) -or [string]::IsNullOrWhiteSpace($mailNickname)) {
        Write-Warning "Skipping row because DisplayName or MailNickname is empty."
        continue
    }

    try {
        # Check if a group with the same mail nickname already exists
        $existingGroup = Get-MgGroup -Filter "mailNickname eq '$mailNickname'"
        if ($existingGroup) {
            Write-Warning "A group with MailNickname '$mailNickname' already exists. Skipping."
            continue
        }

        # Prepare group properties
        $groupParams = @{
            DisplayName     = $displayName
            Description     = $row.Description
            MailNickname    = $mailNickname
            MailEnabled     = $false
            SecurityEnabled = $true
        }

        # Create the new group
        $newGroup = New-MgGroup @groupParams
        Write-Host "Successfully created group '$($newGroup.DisplayName)' with ID: $($newGroup.Id)" -ForegroundColor Green

        # Assign owners
        $ownerUPNs = @($row.Owner1UPN, $row.Owner2UPN) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        foreach ($ownerUPN in $ownerUPNs) {
            try {
                $owner = Get-MgUser -UserId $ownerUPN -ErrorAction Stop
                # The API requires a reference object for the owner
                New-MgGroupOwnerByRef -GroupId $newGroup.Id -OdataId "https://graph.microsoft.com/v1.0/users/$($owner.Id)"
                Write-Host "-> Successfully assigned '$($owner.DisplayName)' as an owner." -ForegroundColor Cyan
            }
            catch {
                Write-Warning "-> Could not find or assign owner with UPN '$ownerUPN'. Please check the UPN and assign manually. Error: $($_.Exception.Message)"
            }
        }
    }
    catch {
        Write-Error "Failed to create group '$displayName'. Error: $($_.Exception.Message)"
    }
}

Write-Host "--------------------------------------------------"
Write-Host "Script finished." -ForegroundColor Green

# 4. Disconnect from Microsoft Graph
Disconnect-MgGraph