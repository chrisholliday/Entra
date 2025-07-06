<#
.SYNOPSIS
    Creates new Entra ID (Azure AD) groups from a formatted CSV file.

.DESCRIPTION
    This function reads a CSV file containing group details and creates new Entra ID groups accordingly.
    It checks for existing groups with the same display name and skips creation if a group already exists,
    issuing a warning. The function outputs which groups were created and which were skipped.

.PARAMETER CsvPath
    The path to the CSV file. The CSV must have columns: DisplayName, Description, Owner1, Owner2, MailNickname.

.EXAMPLE
    New-EntraIDGroupsFromCsv -CsvPath "C:\groups.csv"

    This command reads the groups.csv file and creates Entra ID groups as specified.

.EXAMPLE
    $csv = "C:\mygroups.csv"
    New-EntraIDGroupsFromCsv -CsvPath $csv

.NOTES
    Requires the Microsoft Graph PowerShell module and appropriate permissions.
    Owners must be specified as UPNs or object IDs.

#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$CsvPath
)

# Ensure Microsoft Graph module is installed and imported
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Groups)) {
    Write-Host 'Installing Microsoft.Graph.Groups module...'
    Install-Module Microsoft.Graph -Scope CurrentUser -Force
}
Import-Module Microsoft.Graph.Groups

# Connect to Microsoft Graph if not already connected
if (-not (Get-MgContext)) {
    Connect-MgGraph -Scopes 'Group.ReadWrite.All', 'User.Read.All'
}

$groups = Import-Csv -Path $CsvPath

foreach ($group in $groups) {
    $displayName = $group.DisplayName
    $description = $group.Description
    $owner1 = $group.Owner1
    $owner2 = $group.Owner2
    $mailNickname = $group.MailNickname

    # Check if group already exists
    $existing = Get-MgGroup -Filter "displayName eq '$displayName'" -ConsistencyLevel eventual -CountVariable count
    if ($existing) {
        Write-Warning "Group '$displayName' already exists. Skipping creation."
        Write-Output "SKIPPED: $displayName"
        continue
    }

    # Create the group
    $newGroup = New-MgGroup -DisplayName $displayName `
        -Description $description `
        -MailEnabled:$false `
        -MailNickname $mailNickname `
        -SecurityEnabled:$true

    # Add owners
    foreach ($owner in @($owner1, $owner2)) {
        $ownerObj = Get-MgUser -UserId $owner -ErrorAction SilentlyContinue
        if ($ownerObj) {
            Add-MgGroupOwnerByRef -GroupId $newGroup.Id -BodyParameter @{
                '@odata.id' = "https://graph.microsoft.com/v1.0/users/$($ownerObj.Id)"
            }
        }
        else {
            Write-Warning "Owner '$owner' not found. Skipping owner assignment for group '$displayName'."
        }
    }

    Write-Output "CREATED: $displayName"
}