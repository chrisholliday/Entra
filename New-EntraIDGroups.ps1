#Requires -Modules Microsoft.Graph.Groups
<#
.SYNOPSIS
    Creates new Entra ID (Azure AD) groups from a CSV file.

.DESCRIPTION
    This script reads group information from a CSV file and creates new Entra ID groups.
    It supports specifying group owners and optional members.
    All operations are logged, and a summary report is generated.

.PARAMETER CsvPath
    Path to the CSV file containing group information.
    Required CSV columns: Name, Description, mailnickname, Owner1, Owner2
    Optional CSV column: Members (semicolon-separated list of user principal names)

.EXAMPLE
    .\New-EntraIDGroups.ps1 -CsvPath ".\groups.csv"

.NOTES
    Author: Chris Holliday
    Date: 2025-07-08
    Requires Microsoft Graph PowerShell SDK
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path $_ -PathType Leaf })]
    [string]$CsvPath
)

#Region Functions
function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter()]
        [ValidateSet('Information', 'Warning', 'Error')]
        [string]$Level = 'Information'
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logMessage = "[$timestamp] [$Level] $Message"
    
    # Write to console with appropriate color
    switch ($Level) {
        'Warning' { Write-Host $logMessage -ForegroundColor Yellow }
        'Error' { Write-Host $logMessage -ForegroundColor Red }
        default { Write-Host $logMessage }
    }
    
    # Append to log file
    $logMessage | Out-File -FilePath $script:LogFile -Append
}

function Get-UserIdFromUPN {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserPrincipalName
    )
    
    try {
        $user = Get-MgUser -Filter "userPrincipalName eq '$UserPrincipalName'" -ErrorAction Stop
        return $user.Id
    }
    catch {
        Write-Log -Message "Failed to find user $UserPrincipalName. Error: $_" -Level Warning
        return $null
    }
}
#EndRegion Functions

#Region Script Initialization
# Create timestamp for log files
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$script:LogFile = Join-Path $PSScriptRoot "EntraID_GroupCreation_$timestamp.log"
$summaryFile = Join-Path $PSScriptRoot "EntraID_Summary_$timestamp.txt"

# Initialize counters
$groupsCreated = 0
$groupsFailed = 0
$summaryLines = [System.Collections.ArrayList]::new()

Write-Log "Script started. Reading CSV from: $CsvPath"
#EndRegion Script Initialization

#Region Main Script
try {
    # Check if connected to Microsoft Graph
    try {
        $null = Get-MgContext -ErrorAction Stop
        Write-Log 'Successfully verified Microsoft Graph connection'
    }
    catch {
        Write-Log 'Not connected to Microsoft Graph. Please run Connect-MgGraph with appropriate permissions' -Level Error
        exit 1
    }

    # Import CSV
    try {
        $groups = Import-Csv -Path $CsvPath -ErrorAction Stop
        Write-Log "Successfully imported CSV with $($groups.Count) group(s)"
    }
    catch {
        Write-Log "Failed to import CSV file: $_" -Level Error
        exit 1
    }

    # Process each group
    foreach ($group in $groups) {
        Write-Log "Processing group: $($group.Name)"
        
        # Validate required fields
        if (-not ($group.Name -and $group.Description -and $group.mailnickname -and $group.Owner1 -and $group.Owner2)) {
            Write-Log "Missing required fields for group $($group.Name)" -Level Error
            $groupsFailed++
            $null = $summaryLines.Add("❌ Failed: $($group.Name) - Missing required fields")
            continue
        }

        try {
            # Create group
            $newGroup = New-MgGroup -DisplayName $group.Name `
                -Description $group.Description `
                -MailNickname $group.mailnickname `
                -MailEnabled:$false `
                -SecurityEnabled:$true `
                -GroupTypes @()

            Write-Log "Successfully created group: $($group.Name)"

            # Add owners
            foreach ($ownerUpn in @($group.Owner1, $group.Owner2)) {
                $ownerId = Get-UserIdFromUPN -UserPrincipalName $ownerUpn
                if ($ownerId) {
                    try {
                        New-MgGroupOwnerByRef -GroupId $newGroup.Id -OdataId "https://graph.microsoft.com/v1.0/users/$ownerId"
                        Write-Log "Added owner $ownerUpn to group $($group.Name)"
                    }
                    catch {
                        Write-Log "Failed to add owner $ownerUpn to group $($group.Name): $_" -Level Warning
                    }
                }
            }

            # Add members if specified
            if ($group.Members) {
                $members = $group.Members -split '; ' | Where-Object { $_ -match '\S' }    
                foreach ($memberUpn in $members) {
                    $memberId = Get-UserIdFromUPN -UserPrincipalName $memberUpn.Trim()
                    if ($memberId) {
                        try {
                            New-MgGroupMemberByRef -GroupId $newGroup.Id -OdataId "https://graph.microsoft.com/v1.0/users/$memberId"
                            Write-Log "Added member $memberUpn to group $($group.Name)"
                        }
                        catch {
                            Write-Log "Failed to add member $memberUpn to group $($group.Name): $_" -Level Warning
                        }
                    }
                }
            }

            $groupsCreated++
            $null = $summaryLines.Add("✓ Created: $($group.Name)")
        }
        catch {
            Write-Log "Failed to create group $($group.Name): $_" -Level Error
            $groupsFailed++
            $null = $summaryLines.Add("❌ Failed: $($group.Name) - $($_.Exception.Message)")
        }
    }
}
catch {
    Write-Log "Unexpected error occurred: $_" -Level Error
}
finally {
    # Generate summary
    $scriptStatus = if ($groupsCreated -eq 0 -and $groupsFailed -eq 0) {
        '❌ SCRIPT FAILED: No groups were processed. Check the log file for errors.'
    }
    else {
        'Script completed'
    }

    $summary = @"
=== Entra ID Group Creation Summary ===
Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Status: $scriptStatus
Total Groups Processed: $($groupsCreated + $groupsFailed)
Successfully Created: $groupsCreated
Failed: $groupsFailed

Detailed Results:
$($summaryLines -join "`n")
"@

    # Write summary to file and display
    $summary | Out-File -FilePath $summaryFile
    Write-Log "$scriptStatus. Summary written to: $summaryFile" -Level $(if ($scriptStatus -like '❌*') { 'Error' } else { 'Information' })
    Write-Host "`n$summary" -ForegroundColor $(if ($scriptStatus -like '❌*') { 'Red' } else { 'Cyan' })
}
#EndRegion Main Script
