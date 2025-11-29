<#
.SYNOPSIS
    Export detailed Entra ID App Registration report with owners, API permissions and secret information.

.DESCRIPTION
    Connects to Microsoft Graph (Microsoft.Graph PowerShell SDK required), enumerates application registrations and
    collects:
      - DisplayName
      - AppId (GUID)
      - Owners (userPrincipalName or display name)
      - API Permissions (resource, permission name, delegated/application, admin consent status)
      - Secrets (display name/hint, keyId, start and end/expiration)

    Exports results to CSV (required) and optionally to XLSX if the ImportExcel module is available.
#>
    foreach ($app in $apps) {
        Write-Host "Processing: $($app.DisplayName) ($($app.AppId))"
        try {
            # Owners (single string)
            $ownerNames = @()
            try {
                $owners = Get-MgApplicationOwner -ApplicationId $app.Id -ErrorAction SilentlyContinue
                if ($owners) {
                    foreach ($owner in $owners) {
                        if ($owner.AdditionalProperties.ContainsKey('userPrincipalName')) { $ownerNames += $owner.AdditionalProperties.userPrincipalName }
                        elseif ($owner.DisplayName) { $ownerNames += $owner.DisplayName }
                        elseif ($owner.Id) { $ownerNames += $owner.Id }
                    }
                }
            } catch { $ownerNames += 'Error retrieving owners' }

            $ownersText = if ($ownerNames.Count -gt 0) { ($ownerNames | Sort-Object -Unique) -join '; ' } else { 'None' }

            # Permissions: iterate RequiredResourceAccess, but only emit rows for Application (AppRole) permissions
            if (-not $app.RequiredResourceAccess) { continue }

            foreach ($r in $app.RequiredResourceAccess) {
                $resourceName = Get-ServicePrincipalName -AppId $r.ResourceAppId
                foreach ($access in $r.ResourceAccess) {
                    $permType = if ($access.Type -eq 'Scope') { 'Delegated' } else { 'Application' }
                    if ($permType -ne 'Application') { continue }

                    $permissionId = $access.Id
                    $permissionName = Get-PermissionName -AppId $r.ResourceAppId -PermissionId $permissionId -PermissionType $access.Type

                    # Admin consent (best-effort) for application permission
                    $adminConsent = 'Unknown'
                    try {
                        $currentAppSp = Get-MgServicePrincipal -Filter "appId eq '$($app.AppId)'" -ErrorAction SilentlyContinue | Select-Object -First 1
                        if ($currentAppSp) {
                            $assigns = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $currentAppSp.Id -ErrorAction SilentlyContinue
                            if ($assigns -and ($assigns | Where-Object { $_.AppRoleId -eq $permissionId })) { $adminConsent = 'Granted' } else { $adminConsent = 'Not Granted' }
                        }
                    } catch { $adminConsent = 'Unknown' }

                    # Infer access type (Read/Write/Unknown) using keywords in permission name
                    $accessType = 'Unknown'
                    if ($permissionName -match '(?i)write|update|manage|full|modify|add|create|delete') { $accessType = 'Write' }
                    elseif ($permissionName -match '(?i)read|get|list|view') { $accessType = 'Read' }

                    $permissionRows += [PSCustomObject]@{
                        ApplicationDisplayName = $app.DisplayName
                        ApplicationId = $app.AppId
                        Owners = $ownersText
                        ResourceAppId = $r.ResourceAppId
                        ResourceName = $resourceName
                        PermissionId = $permissionId
                        PermissionName = $permissionName
                        PermissionType = 'Application'
                        AdminConsent = $adminConsent
                        Access = $accessType
                    }
                }
            }
        } catch {
            Write-Warning ("Error processing application {0} ({1}): {2}" -f $($app.DisplayName), $($app.AppId), $_.Exception.Message)
            Write-Host "--- Exception details for app ---" -ForegroundColor Yellow
            try { $_ | Format-List * -Force } catch {}
            try { Write-Host $_.Exception.StackTrace } catch {}
            continue
        }
    }

            # Determine available headers and map to expected fields
            $sample = $rows | Select-Object -First 1
            $cols = if ($sample) { $sample.PSObject.Properties.Name } else { @() }

            # Define possible header names for each expected field
            $idCandidates = @('Id','PermissionId','Id','id')
            $valueCandidates = @('Value','ValueName','Value','PermissionValue')
            $displayCandidates = @('DisplayName','Display','Name','DisplayName')

            $idField = $cols | Where-Object { $idCandidates -contains $_ } | Select-Object -First 1
            $valueField = $cols | Where-Object { $valueCandidates -contains $_ } | Select-Object -First 1
            $displayField = $cols | Where-Object { $displayCandidates -contains $_ } | Select-Object -First 1

            if (-not $idField) {
                Write-Warning "  Imported CSV does not contain an 'Id' column. Headers: $($cols -join ', ')"
                # still try to continue but skip if nothing usable
            }

            $count = 0
            foreach ($r in $rows) {
                $id = if ($idField) { $r.$idField } else { $null }
                $val = if ($valueField) { $r.$valueField } else { $null }
                $disp = if ($displayField) { $r.$displayField } else { $null }

                if ($id) {
                    if (-not $externalPermissionMap.ContainsKey($id)) {
                        $externalPermissionMap[$id] = @{ Value = $val; DisplayName = $disp }
                        $count++
                    }
                }
            }

            Write-Host "  Loaded $count permission mappings from:" $path
            return
        } catch {
            Write-Warning ("  Failed to read external permission file {0}: {1}" -f $path, $_.Exception.Message)
            continue
        }
        
        
    }
}

Load-ExternalPermissionMap

function Get-ServicePrincipalName {
    param([string]$AppId)
    if ($servicePrincipalCache.ContainsKey($AppId)) { 
        $entry = $servicePrincipalCache[$AppId]
        return if ($entry -is [string]) { $entry } else { $entry.DisplayName }
    }
    try {
        $sp = Get-MgServicePrincipal -Filter "appId eq '$AppId'" -Property DisplayName -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($sp) { 
            $servicePrincipalCache[$AppId] = $sp
            return $sp.DisplayName
        }
    } catch {}
    $servicePrincipalCache[$AppId] = "Unknown Service Principal ($AppId)"
    return $servicePrincipalCache[$AppId]
}

function Get-PermissionName {
    param(
        [string]$AppId,
        [string]$PermissionId,
        [string]$PermissionType # 'Scope' or 'AppRole'
    )
    $key = "$AppId-$PermissionId-$PermissionType"
    if ($permissionCache.ContainsKey($key)) { return $permissionCache[$key] }
    # Use prefetched service principal data if available
    if ($servicePrincipalCache.ContainsKey($AppId)) {
        $sp = $servicePrincipalCache[$AppId]
        # sp may be a service principal object
        if ($PermissionType -eq 'Scope' -and $sp.Oauth2PermissionScopes) {
            $p = $sp.Oauth2PermissionScopes | Where-Object { $_.Id -eq $PermissionId }
            if ($p) { $name = if ($p.DisplayName) { "$($p.DisplayName) ($($p.Value))" } else { $p.Value }; $permissionCache[$key] = $name; return $name }
        }
        if ($PermissionType -eq 'AppRole' -and $sp.AppRoles) {
            $p = $sp.AppRoles | Where-Object { $_.Id -eq $PermissionId }
            if ($p) { $name = if ($p.DisplayName) { "$($p.DisplayName) ($($p.Value))" } else { $p.Value }; $permissionCache[$key] = $name; return $name }
        }
    }

    # Check external permission map loaded from EntraApiPermissions.csv
    if ($externalPermissionMap.ContainsKey($PermissionId)) {
        $meta = $externalPermissionMap[$PermissionId]
        $name = if ($meta.DisplayName) { "$($meta.DisplayName) ($($meta.Value))" } else { $meta.Value }
        $permissionCache[$key] = $name
        return $name
    }

    # Fallback map for common Microsoft Graph permissions (partial)
    $graphMap = @{ 
        'e1fe6dd8-ba31-4d61-89e7-88639da4683d' = 'User.Read'
        '62a82d76-70ea-41e2-9197-370581804d09' = 'User.Read.All'
        'df021288-bdef-4463-88db-98f22de89214' = 'Directory.Read.All'
        '19dbc75e-c2e2-444c-a770-ec69d8559fc7' = 'Directory.ReadWrite.All'
    }
    if ($AppId -eq '00000003-0000-0000-c000-000000000000' -and $graphMap.ContainsKey($PermissionId)) {
        $permissionCache[$key] = $graphMap[$PermissionId]
        return $graphMap[$PermissionId]
    }

    $permissionCache[$key] = "Unknown Permission ($PermissionId)"
    return $permissionCache[$key]
}

function Get-UserPrincipalNameCached {
    param([string]$UserId)
    if ($userPrincipalNameCache.ContainsKey($UserId)) { return $userPrincipalNameCache[$UserId] }
    try {
        $u = Get-MgUser -UserId $UserId -Property UserPrincipalName -ErrorAction SilentlyContinue | Select-Object -ExpandProperty UserPrincipalName
        if ($u) { $userPrincipalNameCache[$UserId] = $u; return $u }
    } catch {}
    $userPrincipalNameCache[$UserId] = "UserId:$UserId"
    return $userPrincipalNameCache[$UserId]
}

# Main
try {
    Write-Host "Checking required module Microsoft.Graph..."
    Test-ModuleInstalled -ModuleName 'Microsoft.Graph'
    Import-Module Microsoft.Graph -Force

    Write-Host 'Connecting to Microsoft Graph...'
    Connect-ToGraph -TenantId $TenantId

    Write-Host 'Retrieving applications (this may take time)...'
    if ($Limit -gt 0) { $apps = Get-MgApplication -Top $Limit -ErrorAction Stop } else { $apps = Get-MgApplication -All -ErrorAction Stop }

    # Collect all referenced resourceAppIds so we can prefetch their service principals and permission metadata
    $resourceAppIds = $apps | ForEach-Object { if ($_.RequiredResourceAccess) { $_.RequiredResourceAccess | ForEach-Object { $_.ResourceAppId } } } | Sort-Object -Unique
    foreach ($rid in $resourceAppIds) {
        if (-not $rid) { continue }
        if ($servicePrincipalCache.ContainsKey($rid)) { continue }
        try {
            $sp = Get-MgServicePrincipal -Filter "appId eq '$rid'" -Property AppRoles,Oauth2PermissionScopes,DisplayName -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($sp) { $servicePrincipalCache[$rid] = $sp }
        } catch {
            # ignore
        }
    }


    $permissionRows = @()

    foreach ($app in $apps) {
        Write-Host "Processing: $($app.DisplayName) ($($app.AppId))"
        try {

        # Owners (single string)
        $ownerNames = @()
        try {
            $owners = Get-MgApplicationOwner -ApplicationId $app.Id -ErrorAction SilentlyContinue
            if ($owners) {
                foreach ($owner in $owners) {
                    if ($owner.AdditionalProperties.ContainsKey('userPrincipalName')) { $ownerNames += $owner.AdditionalProperties.userPrincipalName }
                    elseif ($owner.DisplayName) { $ownerNames += $owner.DisplayName }
                    elseif ($owner.Id) { $ownerNames += $owner.Id }
                }
            }
        } catch { $ownerNames += 'Error retrieving owners' }

        $ownersText = if ($ownerNames.Count -gt 0) { ($ownerNames | Sort-Object -Unique) -join '; ' } else { 'None' }

        # Permissions: iterate RequiredResourceAccess, but only emit rows for Application (AppRole) permissions
        if (-not $app.RequiredResourceAccess) { continue }

        foreach ($r in $app.RequiredResourceAccess) {
            $resourceName = Get-ServicePrincipalName -AppId $r.ResourceAppId
            foreach ($access in $r.ResourceAccess) {
                $permType = if ($access.Type -eq 'Scope') { 'Delegated' } else { 'Application' }
                if ($permType -ne 'Application') { continue }

                $permissionId = $access.Id
                $permissionName = Get-PermissionName -AppId $r.ResourceAppId -PermissionId $permissionId -PermissionType $access.Type

                # Admin consent (best-effort) for application permission
                $adminConsent = 'Unknown'
                try {
                    $currentAppSp = Get-MgServicePrincipal -Filter "appId eq '$($app.AppId)'" -ErrorAction SilentlyContinue | Select-Object -First 1
                    if ($currentAppSp) {
                        $assigns = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $currentAppSp.Id -ErrorAction SilentlyContinue
                        if ($assigns -and ($assigns | Where-Object { $_.AppRoleId -eq $permissionId })) { $adminConsent = 'Granted' } else { $adminConsent = 'Not Granted' }
                    }
                } catch { $adminConsent = 'Unknown' }

                # Infer access type (Read/Write/Unknown) using keywords in permission name
                $accessType = 'Unknown'
                if ($permissionName -match '(?i)write|update|manage|full|modify|add|create|delete') { $accessType = 'Write' }
                elseif ($permissionName -match '(?i)read|get|list|view') { $accessType = 'Read' }

                $permissionRows += [PSCustomObject]@{
                    ApplicationDisplayName = $app.DisplayName
                    ApplicationId = $app.AppId
                    Owners = $ownersText
                    ResourceAppId = $r.ResourceAppId
                    ResourceName = $resourceName
                    PermissionId = $permissionId
                    PermissionName = $permissionName
                    PermissionType = 'Application'
                    AdminConsent = $adminConsent
                    Access = $accessType
                }
            }
        }
        catch {
            Write-Warning ("Error processing application {0} ({1}): {2}" -f $($app.DisplayName), $($app.AppId), $_.Exception.Message)
            Write-Host "--- Exception details for app ---" -ForegroundColor Yellow
            try { $_ | Format-List * -Force } catch {}
            try { Write-Host $_.Exception.StackTrace } catch {}
            # continue to next app
            continue
        }
    }

    # Export permission rows (one row per application permission)
    Write-Host "Exporting $($permissionRows.Count) permission rows to CSV: $OutCsv"
    $permissionRows | Export-Csv -Path $OutCsv -NoTypeInformation -Encoding UTF8 -Force

    # Export unresolved permission ids for manual lookup (if any)
    $unresolved = @()
    try {
        $unresolved = $permissionRows | Where-Object { $_.PermissionName -like 'Unknown Permission*' } | Select-Object ResourceAppId, PermissionId -Unique
    } catch {}

    if ($unresolved -and $unresolved.Count -gt 0) {
        $unresolvedPath = (Join-Path (Get-Location) 'UnresolvedPermissions.csv')
        Write-Host "Exporting $($unresolved.Count) unresolved permission ids to:" $unresolvedPath
        $unresolved | Export-Csv -Path $unresolvedPath -NoTypeInformation -Encoding UTF8 -Force
    }

    # CSV export only (XLSX option removed per user request)
    Write-Host 'Done.'
}
catch {
    Write-Error "Script failed: $($_.Exception.Message)"
    Write-Host "--- Full exception details ---" -ForegroundColor Yellow
    try {
        $_ | Format-List * -Force
    } catch {}
    try {
        Write-Host "Exception stack trace:" -ForegroundColor Yellow
        Write-Host $_.Exception.StackTrace
    } catch {}
    throw
}
finally {
    try {
        $ctx = Get-MgContext -ErrorAction SilentlyContinue
        if ($ctx) { Disconnect-MgGraph -ErrorAction SilentlyContinue }
    } catch {}
}
