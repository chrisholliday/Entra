<#
.SYNOPSIS
Export Azure AD SignInActivity
.DESCRIPTION
Connect to App registrations and Export Azure AD SignInActivity
.NOTES
#>
 
Import-Module Az.storage

# Application (client) ID, Directory (tenant) ID, and secret
$clientID = ''
$tenantName = ''
$ClientSecret = ''
$resource = 'https://graph.microsoft.com/'
 
# Connect to AzureAD
$ReqTokenBody = @{
    Grant_Type    = 'client_credentials'
    Scope         = 'https://graph.microsoft.com/.default'
    client_Id     = $clientID
    Client_Secret = $clientSecret
} 
 
$TokenResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenantName/oauth2/v2.0/token" -Method POST -Body $ReqTokenBody


# Connect to Azure Resource Objects

Connect-AzAccount -Identity

# Get all users in source tenant
$uri = 'https://graph.microsoft.com/beta/users?$select=displayName,userPrincipalName,signInActivity'


# If the result is more than 999, we need to read the @odata.nextLink to show more than one side of users
$Data = while (-not [string]::IsNullOrEmpty($uri)) {
    # API Call
    $apiCall = try {
        Invoke-RestMethod -Headers @{Authorization = "Bearer $($Tokenresponse.access_token)" } -Uri $uri -Method Get
    }
    catch {
        $errorMessage = $_.ErrorDetails.Message | ConvertFrom-Json
    }
    $uri = $null
    if ($apiCall) {
        # Check if any data is left
        $uri = $apiCall.'@odata.nextLink'
        $apiCall
    }
}
 
# Set the result into an variable
$result = ($Data | Select-Object Value).Value
$Export = $result | Select-Object DisplayName, UserPrincipalName, @{n = 'LastLoginDate'; e = { $_.signInActivity.lastSignInDateTime } }
 
#[datetime]::Parse('2020-04-07T16:55:35Z')
 
# Export data and pipe to Out-GridView for copy to Excel
#$Export | Select-Object DisplayName,UserPrincipalName,@{Name='LastLoginDate';Expression={[datetime]::Parse($_.LastLoginDate)}} | Out-GridView
 
# Export and filter result based on domain name (Update the domainname)
$stale = $Export | Where-Object { $_.userPrincipalName -match 'azuresmith' } | Select-Object DisplayName, UserPrincipalName, @{Name = 'LastLoginDate'; Expression = { [datetime]::Parse($_.LastLoginDate) } }

$todaydate = Get-Date -Format MM-dd-yy 
$LogFull = "AzureStaleUsersReport-$todaydate.csv" 
$LogItem = New-Item -ItemType File -Name $LogFull

$stale | Export-Csv -Path $LogFull -NoTypeInformation

#Get key to storage account
#$storageaccountkey = ''

$storageaccountkey = (Get-AzStorageAccountKey -Name azuresmithadminsa1 -ResourceGroupName Administrative-RG).Value[0]


#Map to the reports BLOB context
$storageContext = New-AzStorageContext -StorageAccountName 'azuresmithadminsa1' -StorageAccountKey $storageaccountkey 

#Copy the file to the storage account
Set-AzStorageBlobContent -File $LogFull -Container 'stale-user-report' -BlobType 'Block' -Context $storageContext -Verbose -Force
 