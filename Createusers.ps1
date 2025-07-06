[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = 'Path to the CSV file with user information')]
    [string] $File
)

<#
.SYNOPSIS
    Bulk creates users in Entra ID (Azure AD) from a CSV file using Microsoft.Graph module.
.DESCRIPTION
    This script creates Azure AD (Entra ID) users in bulk using the Microsoft.Graph PowerShell module. Each user is created with a long, complex, auto-generated password (never output or handled by the admin), and is required to change their password at first sign-in. Users are created as disabled by default unless the CSV column 'Enabled' is set to true/yes/1 (case-insensitive).

.EXAMPLE
    PS C:\> .\Createusers.ps1 -File ./newusers.csv
    # Creates users from the specified CSV file. Each user is disabled by default unless 'Enabled' column is set to true/yes/1.

.EXAMPLE
    CSV file format:
    UserPrincipalName,DisplayName,MailNickName,GivenName,Surname,Department,State,City,CompanyName,JobTitle,Enabled
    alice@contoso.com,Alice Smith,asmith,Alice,Smith,IT,WA,Seattle,Contoso,Engineer,true
    bob@contoso.com,Bob Jones,bjones,Bob,Jones,HR,CA,San Francisco,Contoso,Manager,false
    # 'Enabled' column is optional. If omitted or not set to true/yes/1, the user will be created as disabled.

.INPUTS
    -File: Path to the CSV file with user details. The CSV must include at least UserPrincipalName, DisplayName, and MailNickName columns.
.OUTPUTS
    Logs of user creation results, including success and failure counts.
.NOTES
    - Requires Microsoft.Graph module and admin permissions.
    - Passwords are auto-generated and not output or stored by this script.
    - Users are required to change their password at next sign-in.
#>

# Ensure Microsoft.Graph module is installed
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Users)) {
    try {
        Install-Module Microsoft.Graph -Scope CurrentUser -Force -ErrorAction Stop
    }
    catch {
        Write-Error 'Microsoft.Graph module is required. Install failed. Exiting.'
        exit 1
    }
}

Import-Module Microsoft.Graph.Users

# Connect to Microsoft Graph if not already connected
if (-not (Get-MgContext)) {
    try {
        Connect-MgGraph -Scopes 'User.ReadWrite.All'
    }
    catch {
        Write-Error 'Failed to connect to Microsoft Graph. Exiting.'
        exit 1
    }
}

# Import users from CSV
try {
    $users = Import-Csv -Path $File
}
catch {
    Write-Error "User file not found: $File"
    exit 1
}

# Ensure required columns exist in the CSV
$requiredColumns = @('UserPrincipalName', 'DisplayName', 'MailNickName')
foreach ($col in $requiredColumns) {
    if (-not ($users | Get-Member -Name $col)) {
        Write-Error "CSV is missing required column: $col"
        exit 1
    }
}

function New-ComplexPassword {
    param(
        [int]$Length = 20
    )
    $chars = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*()-_=+[]{};:,.<>?'
    $password = -join ((1..$Length) | ForEach-Object { $chars | Get-Random })
    return $password
}

$successCount = 0
$failCount = 0

foreach ($user in $users) {
    # Validate required fields
    if (-not $user.UserPrincipalName -or -not $user.DisplayName -or -not $user.MailNickName) {
        Write-Warning "Missing required fields for user: $($user | ConvertTo-Json)"
        $failCount++
        continue
    }

    # Determine if the user should be enabled based on CSV column 'Enabled'
    $enabledValue = $user.Enabled
    $isEnabled = $false
    if ($enabledValue) {
        if ($enabledValue -match '^(?i:true|yes|1)$') {
            $isEnabled = $true
        }
    }

    $generatedPassword = New-ComplexPassword

    $params = @{
        AccountEnabled    = $isEnabled
        DisplayName       = $user.DisplayName
        MailNickname      = $user.MailNickName
        UserPrincipalName = $user.UserPrincipalName
        PasswordProfile   = @{ Password = $generatedPassword; ForceChangePasswordNextSignIn = $true }
    }
    if ($user.GivenName) { $params.GivenName = $user.GivenName }
    if ($user.Surname) { $params.Surname = $user.Surname }
    if ($user.Department) { $params.Department = $user.Department }
    if ($user.State) { $params.State = $user.State }
    if ($user.City) { $params.City = $user.City }
    if ($user.CompanyName) { $params.CompanyName = $user.CompanyName }
    if ($user.JobTitle) { $params.JobTitle = $user.JobTitle }

    try {
        $existingUser = Get-MgUser -UserId $user.UserPrincipalName -ErrorAction SilentlyContinue
        if (-not $existingUser) {
            New-MgUser @params
            Write-Output "Created user: $($user.UserPrincipalName)"
            $successCount++
        }
        else {
            Write-Output "User already exists: $($user.UserPrincipalName)"
            $failCount++
        }
    }
    catch {
        Write-Error "Failed to create user: $($user.UserPrincipalName). $_"
        $failCount++
    }
}

Write-Output "User creation complete. Success: $successCount, Failed: $failCount"