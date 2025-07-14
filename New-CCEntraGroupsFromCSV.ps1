<#
.SYNOPSIS
    Bulk creates Microsoft Entra ID security groups from a CSV file.
.DESCRIPTION
    This script reads group information from a specified CSV file and creates non-mail-enabled security groups in Microsoft Entra ID using the Microsoft Graph API.
    It requires a properly formatted CSV file with the following headers: DisplayName, Description, MailNickname, Owners.
    The Owners field must contain one or more Microsoft Entra object IDs (not UPNs or emails), separated by semicolons.
    Optionally, it can assign members to the groups if specified in the CSV; the Members field must also contain semicolon-separated object IDs.

    The script requires the Microsoft.Graph.Identity.DirectoryManagement and Microsoft.Graph.Users modules to be pre-installed.
    If the modules are not present, the script will fail to run.

    The user running the script will be prompted to authenticate interactively and must have 
    sufficient permissions (e.g., Groups Administrator or User Administrator).
    Required Microsoft Graph API permissions: Group.ReadWrite.All, User.Read.All.
.PARAMETER CsvPath
    The full path to the CSV file containing the group definitions.
    The CSV must contain the following headers: DisplayName, Description, MailNickname, Owners. 
    The Owners field must contain one or more Microsoft Entra object IDs (semicolon-separated). 
    It may also include a Members header for group membership, which must also be a semicolon-separated list of object IDs.
.EXAMPLE
    .\New-CCEntraGroupsFromCSV.ps1 -CsvPath "C:\Users\chris\OneDrive\scripts\Azure\NewGroups.csv"

    This command runs the script and creates groups based on the content of NewGroups.csv.
.NOTES
    Author: Chris Holliday
    Version: 1.0
    Update History:
        - 2024-06-10: Initial version.
    Requires: 
    - PowerShell 5.1 or later
    - Microsoft.Graph.Identity.DirectoryManagement module
    - Microsoft.Graph.Users module
    - Microsoft Graph API permissions: Group.ReadWrite.All, User.Read.All
#>
param (
    [Parameter(Mandatory = $true)]
    [string]$CsvPath
)
# Define 
function Write-Log {
    param(
        [string]$Message
    )
    Add-Content -Path $logFile -Value $Message
}

# Set up log file
$scriptName = [System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name)
$csvBaseName = [System.IO.Path]::GetFileNameWithoutExtension($CsvPath)
$logFile = Join-Path -Path (Split-Path -Parent $MyInvocation.MyCommand.Path) -ChildPath ("${scriptName}_${csvBaseName}_GroupCreationLog_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))

# Ensure the required modules are installed
$requiredModules = @('Microsoft.Graph.Identity.DirectoryManagement', 'Microsoft.Graph.Users')
foreach ($module in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        Write-Error "Required module '$module' is not installed. Please install it before running this script."
        exit 1
    }
}
# Import the required modules
Import-Module Microsoft.Graph.Identity.DirectoryManagement
Import-Module Microsoft.Graph.Users

# Define required Microsoft Graph scopes (see .PARAMETER and .NOTES)
$graphScopes = @('Group.ReadWrite.All', 'User.Read.All')

# Authenticate to Microsoft Graph
try {
    Connect-MgGraph -Scopes $graphScopes
}
catch {
    Write-Error 'Failed to connect to Microsoft Graph. Please ensure you have the necessary permissions and try again.'
    throw
}
if (-not (Test-Path $CsvPath)) {
    Write-Error "The specified CSV file '$CsvPath' does not exist."
    throw
}
$groups = Import-Csv -Path $CsvPath
if ($null -eq $groups) {
    Write-Error 'Failed to read the CSV file. Please ensure it is properly formatted.'

    Add-Content -Path $logFile -Value $Message
}

# Create groups from the CSV data
foreach ($group in $groups) {
    # Validate required fields
    if ([string]::IsNullOrWhiteSpace($group.DisplayName) -or 
        [string]::IsNullOrWhiteSpace($group.Description) -or 
        [string]::IsNullOrWhiteSpace($group.MailNickname) -or 
        [string]::IsNullOrWhiteSpace($group.Owners)) {
        $msg = "[ERROR] Group '$($group.DisplayName)' is missing one or more required fields: DisplayName, Description, MailNickname, or Owners. Skipping group: $($group | ConvertTo-Json -Compress)"
        Write-Host $msg -ForegroundColor Red
        Write-Log $msg
        continue
    }
    $escapedDisplayName = $group.DisplayName -replace '"', '\"'
    $escapedMailNickname = $group.MailNickname -replace '"', '\"'
    $filter = "displayName eq `"$escapedDisplayName`" or mailNickname eq `"$escapedMailNickname`""
    $existingGroup = Get-MgGroup -Filter $filter -ErrorAction SilentlyContinue
    $escapedMailNickname = $group.MailNickname -replace "'", "''"
    $filter = "displayName eq '$escapedDisplayName' or mailNickname eq '$escapedMailNickname'"
    $existingGroup = Get-MgGroup -Filter $filter -ErrorAction SilentlyContinue
    if ($existingGroup) {
        $msg = "[SKIP] A group with DisplayName '$($group.DisplayName)' or MailNickname '$($group.MailNickname)' already exists. Skipping group."
        Write-Warning $msg
        Write-Log $msg
        continue
    }
    $groupParams = @{
        DisplayName     = $group.DisplayName
        Description     = $group.Description
        MailNickname    = $group.MailNickname
        MailEnabled     = $false
        SecurityEnabled = $true
    }
    try {
        $newGroup = New-MgGroup @groupParams
        $msg = "[SUCCESS] Created group: $($newGroup.DisplayName) (ID: $($newGroup.Id))"
        Write-Host $msg
        Write-Log $msg
    }
    catch {
        $msg = "[ERROR] Failed to create group: $($group.DisplayName). Error: $_"
        Write-Host $msg -ForegroundColor Red
        Write-Log $msg
        continue
    }

    # Only proceed if the group was created successfully
    if ($null -ne $newGroup) {
        if ($group.Owners) {
            $ownerIds = $group.Owners -split ';' | ForEach-Object { $_.Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
            foreach ($ownerIdentifier in $ownerIds) {
                try {
                    # Check if the identifier is a GUID (object ID) or a UPN
                    $actualOwnerId = $null
                    if ($ownerIdentifier -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
                        # It's already an object ID
                        $actualOwnerId = $ownerIdentifier
                    }
                    else {
                        # Assume it's a UPN and resolve to object ID
                        $user = Get-MgUser -Filter "userPrincipalName eq '$ownerIdentifier'" -ErrorAction Stop
                        if ($user) {
                            $actualOwnerId = $user.Id
                        }
                        else {
                            throw "User not found with UPN: $ownerIdentifier"
                        }
                    }
            
                    $ownerParams = @{
                        '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$actualOwnerId"
                    }
                    New-MgGroupOwnerByRef -GroupId $newGroup.Id -BodyParameter $ownerParams
                    $msg = "[SUCCESS] Added owner: $ownerIdentifier (ID: $actualOwnerId) to group: $($newGroup.DisplayName)"
                    Write-Host $msg
                    Write-Log $msg
                }
                catch {
                    $msg = "[WARNING] Failed to add owner: $ownerIdentifier to group: $($newGroup.DisplayName). Error: $_"
                    Write-Warning $msg
                    Write-Log $msg
                }
            }
        }

        # Assign members if specified
        if ($group.Members) {
            $memberIds = $group.Members -split ';' | ForEach-Object { $_.Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
            foreach ($memberIdentifier in $memberIds) {
                try {
                    # Check if the identifier is a GUID (object ID) or a UPN
                    $actualMemberId = $null
                    if ($memberIdentifier -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
                        # It's already an object ID
                        $actualMemberId = $memberIdentifier
                    }
                    else {
                        # Assume it's a UPN and resolve to object ID
                        $user = Get-MgUser -Filter "userPrincipalName eq '$memberIdentifier'" -ErrorAction Stop
                        if ($user) {
                            $actualMemberId = $user.Id
                        }
                        else {
                            throw "User not found with UPN: $memberIdentifier"
                        }
                    }
                    
                    $memberParams = @{
                        '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$actualMemberId"
                    }
                    New-MgGroupMemberByRef -GroupId $newGroup.Id -BodyParameter $memberParams
                    $msg = "[SUCCESS] Added member: $memberIdentifier (ID: $actualMemberId) to group: $($newGroup.DisplayName)"
                    Write-Host $msg
                    Write-Log $msg
                }
                catch {
                    $msg = "[WARNING] Failed to add member: $memberIdentifier to group: $($newGroup.DisplayName). Error: $_"
                    Write-Warning $msg
                    Write-Log $msg
                }
            }
        }
    }
}
