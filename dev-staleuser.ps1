<#
.SYNOPSIS
Export List of Stale Azure AD "Cloud Native Users"
.DESCRIPTION
Connect to App registrations and Export Azure AD SignInActivity
.NOTES
This script assumes it is being run as a runbook under an Azure Automation Account. To run the script standalone, replace the references to the automation account under the variable declariation section with appropriate values.
#>

# Define / Retrive Variables from Automation Account
Try {
    $ClientID = get-automationvariable -name AppRegistrationClientID
    $TenantName = get-automationvariable -name TenantName
    $ClientSecret = get-automationvariable -Name AzureADSecret
    $StorageAccountName = get-automationvariable -name StorageAccountName
    $ResourceGroup = get-automationvariable -name ResourceGroup
    $Container = get-automationvariable -name Container
    $filename = "StaleCloudUsers"
    $ReqTokenBody = @{
        Grant_Type    = "client_credentials"
        Scope         = "https://graph.microsoft.com/.default"
        client_Id     = $clientID
        Client_Secret = $ClientSecret
    } 
    }
    catch {
        $errorMessage = "Unable to define variables correctly. Are you using an automtion account with all the variables defined?"
        throw $errorMessage
        exit
    }
    
    try {
    Import-module Az.storage
    Import-module Az.Accounts
    }
    catch {
        $errorMessage = "Attempt to import Powershell Modules failed. Please confirm that these are avaialable."
        throw $errorMessage
        exit
    }
    
    # Connect to Azure Resource Objects
    try {
        # Connect to Azure using Managed Identity of the Automation Account
    Connect-AzAccount -identity
    }
    catch {
        $errorMessage = "Failed to connect to Azure. Do you have a properly configured Managed Identity on the Automation Account?"
        throw $errorMessage
        exit    
    }
     
    # Connect to AzureAD tenant
    try {
    $TokenResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenantName/oauth2/v2.0/token" -Method POST -Body $ReqTokenBody
    }
    catch{
        $errorMessage = "Failed to connect to AzureAD using App Registration"
        throw $errorMessage
        exit
    }
    
    
    # Get all users in 'All Users' goup'
    $uri = 'https://graph.microsoft.com/v1.0/groups/c2614388-da97-48cb-a5a8-c414b7206245/members'
    
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
    $result = ($Data | select-object Value).Value
    
    $AllCloudUsers = $result | Select-Object ID
    
    $stale = (get-date).adddays(-90)
    
    $userobjects = foreach ($user in $AllCloudUsers) {

        $ID = $user.ID
        $URI2 = "https://graph.microsoft.com/beta/users/{$ID}?`$select=displayName,accountEnabled,createdDateTime,mail,jobTitle,manager,userPrincipalName,userType,signInActivity"
        $UserData = Invoke-RestMethod -Headers @{Authorization = "Bearer $($Tokenresponse.access_token)" } -Uri $URI2 -Method Get
        
        if ($userdata.signInActivity.lastSignInDateTime -ge $stale){
            $Stalestate = "No"
        }
        else{
            $Stalestate = "Yes"
        }
    
    
        $Information = @{
            UserName          = $UserData.DisplayName
            UserPrincipalName = $UserData.UserPrincipalName
            Enabled           = $UserData.accountEnabled
            Created           = $userdata.createdDateTime
            Mail              = $UserData.mail
            jobTitle          = $UserData.jobTitle
            Manager           = $UserData.manager
            UserType          = $UserData.userType
            LastSignIn        = $UserData.signInActivity.lastSignInDateTime
            Stale = $Stalestate
        }
    
        $object = New-Object -TypeName psobject -Property $Information
        $object
    }
    
    $Now = Get-Date -Format filedatetimeuniversal
    $LogName = "$filename-$Now.csv" 
    
    $userobjects | Export-CSV -Path $LogName -NoTypeInformation
    
    # Get key to storage account
    $storageaccountkey = (Get-AzStorageAccountKey -Name $StorageAccountName -ResourceGroupName $ResourceGroup).Value[0]
    
    # Map to the reports BLOB context
    $storageContext = New-AzStorageContext -StorageAccountName $StorageAccountName -StorageAccountKey $storageaccountkey 
    
    # Copy the file to the storage account
    Set-AzStorageBlobContent -File $LogName -Container $Container -BlobType "Block" -Context $storageContext -Verbose -Force