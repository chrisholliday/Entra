#Requires -Modules Microsoft.Graph
<#
.SYNOPSIS
    Creates Entra ID (Azure AD) security groups from a CSV file.

.DESCRIPTION
    This script creates Entra ID security groups based on input from a CSV file.
    It includes error checking, validation, and logging capabilities.

.PARAMETER CsvPath
    The path to the CSV file containing group information.
    CSV must contain columns: DisplayName,Description,MailNickname,Owner1,Owner2,Members

.EXAMPLE
    .\New-EntraIDGroupsFromCSV.ps1 -CsvPath ".\groups.csv"

.NOTES
    Required CSV format:
    DisplayName,Description,MailNickname,Owner1,Owner2,Members
    "Group1","Description1","nick1","owner1@domain.com","owner2@domain.com","user1@domain.com,user2@domain.com"
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path $_ -PathType Leaf })]
    [string]$CsvPath
)

# Initialize logging
$logFile = "EntraID_GroupCreation_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$summaryFile = "EntraID_Summary_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
$ErrorActionPreference = 'Stop'

function Write-Log {
    param($Message)
    $logMessage = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): $Message"
    Add-Content -Path $logFile -Value $logMessage
    Write-Verbose $logMessage
}

function Test-GroupExists {
    param([string]$DisplayName)
    try {
        $group = Get-MgGroup -Filter "displayName eq '$DisplayName'"
        return $null -ne $group
    }
    catch {
        Write-Log "Error checking if group exists: $_"
        return $false
    }
}

# Connect to Microsoft Graph
try {
    Write-Log 'Connecting to Microsoft Graph...'
    Connect-MgGraph -Scopes 'Group.ReadWrite.All', 'User.ReadWrite.All'
}
catch {
    Write-Error "Failed to connect to Microsoft Graph: $_"
    exit 1
}

# Initialize summary
$summary = @{
    GroupsCreated = 0
    GroupsSkipped = 0
    Errors        = @()
    Details       = @()
}

# Import and validate CSV
try {
    $groups = Import-Csv -Path $CsvPath
    Write-Log "Successfully imported CSV with $($groups.Count) groups to process"
}
catch {
    Write-Error "Failed to import CSV file: $_"
    exit 1
}

# Process each group
foreach ($group in $groups) {
    try {
        # Check if group already exists
        if (Test-GroupExists -DisplayName $group.DisplayName) {
            Write-Log "Group '$($group.DisplayName)' already exists - skipping"
            $summary.GroupsSkipped++
            $summary.Details += "SKIPPED: $($group.DisplayName) - Group already exists"
            continue
        }

        # Create new group
        $groupParams = @{
            DisplayName     = $group.DisplayName
            Description     = $group.Description
            MailNickname    = $group.MailNickname
            SecurityEnabled = $true
            MailEnabled     = $false
            GroupTypes      = @()
        }

        $newGroup = New-MgGroup @groupParams
        Write-Log "Created group: $($group.DisplayName)"

        # Add owners
        foreach ($owner in @($group.Owner1, $group.Owner2)) {
            $ownerId = (Get-MgUser -Filter "userPrincipalName eq '$owner'").Id
            if ($ownerId) {
                New-MgGroupOwner -GroupId $newGroup.Id -DirectoryObjectId $ownerId
                Write-Log "Added owner $owner to group $($group.DisplayName)"
            }
        }

        # Add members
        $members = $group.Members -split ','
        foreach ($member in $members) {
            $member = $member.Trim()
            try {
                $memberId = (Get-MgUser -Filter "userPrincipalName eq '$member'").Id
                if (-not $memberId) {
                    $memberId = (Get-MgGroup -Filter "displayName eq '$member'").Id
                }
                if ($memberId) {
                    New-MgGroupMember -GroupId $newGroup.Id -DirectoryObjectId $memberId
                    Write-Log "Added member $member to group $($group.DisplayName)"
                }
            }
            catch {
                Write-Log "Error adding member ${member}: $_"
            }
        }

        $summary.GroupsCreated++
        $summary.Details += "CREATED: $($group.DisplayName) successfully"
    }
    catch {
        Write-Log "Error processing group $($group.DisplayName): $_"
        $summary.Errors += "ERROR: $($group.DisplayName) - $_"
    }
}

# Generate summary file
$summaryContent = @"
Entra ID Group Creation Summary
$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
----------------------------------------
Groups Created: $($summary.GroupsCreated)
Groups Skipped: $($summary.GroupsSkipped)
Total Groups Processed: $($groups.Count)

Detailed Results:
$($($summary.Details | ForEach-Object { "- $_" }) -join "`r`n")

Errors:
$($($summary.Errors | ForEach-Object { "- $_" }) -join "`r`n")
"@

Set-Content -Path $summaryFile -Value $summaryContent
Write-Log "Summary file created: $summaryFile"

Write-Host "`nOperation completed. Check $summaryFile for details."
Disconnect-MgGraph