$NorthernUsers = Get-AzureADUser -filter "State eq 'The North'"

$NorthCRMGroup = Get-AzureADGroup -SearchString "North-CRM"
$members = Get-AzureADGroupMember -ObjectId $NorthCRMGroup.ObjectID
foreach ($member in $members){
    Remove-AzureADGroupMember -ObjectId $NorthCRMGroup.ObjectID -MemberId $member.Objectid
}

foreach ($user in $NorthernUsers){
    #$user
    $AppsignedPlans = $user.assignedplans
    $i = 0
    foreach ($plan in $AppsignedPlans){
        $i++
        # Write-Output "Plan $i"
        if ($plan.service -eq 'CRM'){
            if ($plan.capabilitystatus -eq 'Enabled'){
                $Name = $user.displayname
                Write-Output "CRM Service is enabled, adding $Name to North CRM Group"
                Add-AzureADGroupMember -ObjectId $NorthCRMGroup.Objectid -RefObjectId $User.Objectid
            }

        }

    }
}

#>