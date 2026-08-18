#requires -Version 5.1

function script:toStringList {
    Param ($Value)

    if ($null -eq $Value) {
        return $null
    }

    $list = New-Object 'System.Collections.Generic.List[string]'
    foreach ($item in @($Value)) {
        if ($null -ne $item -and -not [string]::IsNullOrWhiteSpace([string]$item)) {
            [void]$list.Add([string]$item)
        }
    }

    if ($list.Count -eq 0) {
        return $null
    }

    return $list
}

function script:preparePamConfigValuesFromBoundParameters {
    Param (
        [hashtable] $BoundParameters,
        [string[]] $ExcludeKeys = @()
    )

    $values = @{}
    $skip = @(
        'Verbose', 'Debug', 'ErrorAction', 'WarningAction', 'InformationAction',
        'ErrorVariable', 'WarningVariable', 'OutVariable', 'OutBuffer', 'PipelineVariable',
        'WhatIf', 'Confirm'
    ) + @($ExcludeKeys)

    foreach ($key in $BoundParameters.Keys) {
        if ($key -in $skip) { continue }
        $values[$key] = $BoundParameters[$key]
    }

    if ($BoundParameters.ContainsKey('PortMapping')) {
        $values['PortMapping'] = (toStringList $BoundParameters['PortMapping'])
    }
    if ($BoundParameters.ContainsKey('RegionNames')) {
        $values['RegionNames'] = (toStringList $BoundParameters['RegionNames'])
    }
    if ($BoundParameters.ContainsKey('ResourceGroups')) {
        $values['ResourceGroups'] = (toStringList $BoundParameters['ResourceGroups'])
    }
    if ($BoundParameters.ContainsKey('GcpRegionNames')) {
        $values['GcpRegionNames'] = (toStringList $BoundParameters['GcpRegionNames'])
    }
    if ($BoundParameters.ContainsKey('RemoveResourceRecords')) {
        $values['RemoveResourceRecords'] = (toStringList $BoundParameters['RemoveResourceRecords'])
    }
    if ($BoundParameters.ContainsKey('ForceDomainAdmin') -and $BoundParameters['ForceDomainAdmin']) {
        $values['ForceDomainAdmin'] = $true
    }

    return $values
}

function script:setPamTypedFieldValue {
    Param (
        [Parameter(Mandatory = $true)]
        [KeeperSecurity.Vault.TypedRecord] $Record,
        [Parameter(Mandatory = $true)]
        [string] $FieldType,
        [string] $FieldLabel,
        [AllowEmptyString()]
        [object] $Value
    )

    $rtf = New-Object KeeperSecurity.Vault.RecordTypeField($FieldType, $FieldLabel)
    [KeeperSecurity.Vault.ITypedField]$field = $null
    if (-not [KeeperSecurity.Vault.VaultDataExtensions]::FindTypedField($Record, $rtf, [ref]$field)) {
        if ($null -eq $Value -or [string]::IsNullOrEmpty([string]$Value)) {
            return
        }
        $field = [KeeperSecurity.Vault.VaultDataExtensions]::CreateTypedField($FieldType, $FieldLabel)
        if ($field) {
            $Record.Fields.Add($field)
        }
    }

    if (-not $field) {
        return
    }

    if ($null -eq $Value -or [string]::IsNullOrEmpty([string]$Value)) {
        while ($field.Count -gt 0) {
            $field.DeleteValueAt(0)
        }
        return
    }

    $field.ObjectValue = $Value
}

function script:setPamCheckboxField {
    Param (
        [Parameter(Mandatory = $true)]
        [KeeperSecurity.Vault.TypedRecord] $Record,
        [Parameter(Mandatory = $true)]
        [string] $Label,
        [string] $TriBool
    )

    if ([string]::IsNullOrWhiteSpace($TriBool)) {
        return
    }

    $normalized = $TriBool.Trim().ToLowerInvariant()
    if ($normalized -notin @('true', 'false')) {
        return
    }

    setPamTypedFieldValue -Record $Record -FieldType 'checkbox' -FieldLabel $Label -Value ($normalized -eq 'true')
}

function script:getPamHostnameField {
    Param (
        [Parameter(Mandatory = $true)]
        [KeeperSecurity.Vault.TypedRecord] $Record
    )

    $rtf = New-Object KeeperSecurity.Vault.RecordTypeField('pamHostname', $null)
    [KeeperSecurity.Vault.ITypedField]$field = $null
    if ([KeeperSecurity.Vault.VaultDataExtensions]::FindTypedField($Record, $rtf, [ref]$field) -and
        $field.Count -gt 0 -and
        $field.GetValueAt(0) -is [KeeperSecurity.Vault.FieldTypeHost]) {
        return [KeeperSecurity.Vault.FieldTypeHost]$field.GetValueAt(0)
    }

    return $null
}

function script:setPamHostnameField {
    Param (
        [Parameter(Mandatory = $true)]
        [KeeperSecurity.Vault.TypedRecord] $Record,
        [string] $HostName,
        [string] $Port
    )

    $hostObj = New-Object KeeperSecurity.Vault.FieldTypeHost
    $hostObj.HostName = if ($null -eq $HostName) { '' } else { $HostName }
    $hostObj.Port = if ($null -eq $Port) { '' } else { $Port }
    setPamTypedFieldValue -Record $Record -FieldType 'pamHostname' -FieldLabel $null -Value $hostObj
}

function script:applyPamConfigSchedule {
    Param (
        [Parameter(Mandatory = $true)]
        [KeeperSecurity.Vault.TypedRecord] $Record,
        [string] $DefaultSchedule,
        [bool] $IsEdit
    )

    if ($IsEdit -and [string]::IsNullOrWhiteSpace($DefaultSchedule)) {
        return
    }

    try {
        $schedule = New-Object KeeperSecurity.Vault.FieldSchedule
        $cron = if ($null -eq $DefaultSchedule) { '' } else { $DefaultSchedule.Trim() }
        if ([string]::IsNullOrEmpty($cron) -or
            [string]::Equals($cron, 'On-Demand', [StringComparison]::OrdinalIgnoreCase) -or
            [string]::Equals($cron, 'ON_DEMAND', [StringComparison]::OrdinalIgnoreCase)) {
            $schedule.Type = 'ON_DEMAND'
        }
        else {
            # Rotation CRON: 6 fields, e.g. "0 0 3 * * ?"
            $validation = [KeeperSecurity.Plugins.PAM.RotationUtils]::ValidateCronExpression($cron, $true)
            if (-not $validation.Item1) {
                throw "Invalid CRON `"$cron`" Error: $($validation.Item2)"
            }
            $schedule.Type = 'CRON'
            $schedule.Cron = $cron
            $schedule.TimeZone = 'Etc/UTC'
        }

        setPamTypedFieldValue -Record $Record -FieldType 'schedule' -FieldLabel 'defaultRotationSchedule' -Value $schedule
    }
    catch {
        if ($_.Exception.Message -match 'Invalid CRON') { throw }
        Write-Warning "Could not set default rotation schedule: $($_.Exception.Message). Ensure PAM record types are synced (Sync-Keeper)."
    }
}

function script:applyPamConfigEnvironmentFields {
    Param (
        [Parameter(Mandatory = $true)]
        [KeeperSecurity.Vault.VaultOnline] $Vault,
        [Parameter(Mandatory = $true)]
        [KeeperSecurity.Vault.TypedRecord] $Record,
        [Parameter(Mandatory = $true)]
        [hashtable] $Values,
        [bool] $IsEdit
    )

    $supplied = {
        param([string]$key)
        if ($IsEdit) {
            return $Values.ContainsKey($key)
        }
        return $Values.ContainsKey($key) -and -not [string]::IsNullOrWhiteSpace([string]$Values[$key])
    }

    switch ($Record.TypeName) {
        'pamNetworkConfiguration' {
            if (& $supplied 'NetworkId') {
                setPamTypedFieldValue -Record $Record -FieldType 'text' -FieldLabel 'networkId' -Value ([string]$Values['NetworkId'])
            }
            if (& $supplied 'NetworkCidr') {
                setPamTypedFieldValue -Record $Record -FieldType 'text' -FieldLabel 'networkCIDR' -Value ([string]$Values['NetworkCidr'])
            }
        }
        'pamAwsConfiguration' {
            if (& $supplied 'AwsId') {
                setPamTypedFieldValue -Record $Record -FieldType 'text' -FieldLabel 'awsId' -Value ([string]$Values['AwsId'])
            }
            if (& $supplied 'AccessKeyId') {
                setPamTypedFieldValue -Record $Record -FieldType 'secret' -FieldLabel 'accessKeyId' -Value ([string]$Values['AccessKeyId'])
            }
            if (& $supplied 'AccessSecretKey') {
                setPamTypedFieldValue -Record $Record -FieldType 'secret' -FieldLabel 'accessSecretKey' -Value ([string]$Values['AccessSecretKey'])
            }
            if ($Values.ContainsKey('RegionNames') -and $Values['RegionNames']) {
                setPamTypedFieldValue -Record $Record -FieldType 'multiline' -FieldLabel 'regionNames' -Value (($Values['RegionNames'] -join "`n"))
            }
        }
        'pamAzureConfiguration' {
            if (& $supplied 'AzureId') {
                setPamTypedFieldValue -Record $Record -FieldType 'text' -FieldLabel 'azureId' -Value ([string]$Values['AzureId'])
            }
            if (& $supplied 'ClientId') {
                setPamTypedFieldValue -Record $Record -FieldType 'secret' -FieldLabel 'clientId' -Value ([string]$Values['ClientId'])
            }
            if (& $supplied 'ClientSecret') {
                setPamTypedFieldValue -Record $Record -FieldType 'secret' -FieldLabel 'clientSecret' -Value ([string]$Values['ClientSecret'])
            }
            if (& $supplied 'SubscriptionId') {
                setPamTypedFieldValue -Record $Record -FieldType 'secret' -FieldLabel 'subscriptionId' -Value ([string]$Values['SubscriptionId'])
            }
            if (& $supplied 'TenantId') {
                setPamTypedFieldValue -Record $Record -FieldType 'secret' -FieldLabel 'tenantId' -Value ([string]$Values['TenantId'])
            }
            if ($Values.ContainsKey('ResourceGroups') -and $Values['ResourceGroups']) {
                setPamTypedFieldValue -Record $Record -FieldType 'multiline' -FieldLabel 'resourceGroups' -Value (($Values['ResourceGroups'] -join "`n"))
            }
        }
        'pamGcpConfiguration' {
            if (& $supplied 'GcpId') {
                setPamTypedFieldValue -Record $Record -FieldType 'text' -FieldLabel 'pamGcpId' -Value ([string]$Values['GcpId'])
            }
            if (& $supplied 'ServiceAccountKey') {
                $sak = readPamMaybeFileContent -Value ([string]$Values['ServiceAccountKey'])
                try {
                    setPamTypedFieldValue -Record $Record -FieldType 'json' -FieldLabel 'pamServiceAccountKey' -Value $sak
                }
                catch {
                    Write-Warning "Could not set GCP service-account key field: $($_.Exception.Message). Ensure PAM record types are synced (Sync-Keeper)."
                }
            }
            if (& $supplied 'GoogleAdminEmail') {
                setPamTypedFieldValue -Record $Record -FieldType 'email' -FieldLabel 'pamGoogleAdminEmail' -Value ([string]$Values['GoogleAdminEmail'])
            }
            if ($Values.ContainsKey('GcpRegionNames') -and $Values['GcpRegionNames']) {
                setPamTypedFieldValue -Record $Record -FieldType 'multiline' -FieldLabel 'pamGcpRegionName' -Value (($Values['GcpRegionNames'] -join "`n"))
            }
        }
        'pamDomainConfiguration' {
            if (& $supplied 'DomainId') {
                setPamTypedFieldValue -Record $Record -FieldType 'text' -FieldLabel 'pamDomainId' -Value ([string]$Values['DomainId'])
            }
            if ($IsEdit) {
                if ($Values.ContainsKey('DomainHostname') -or $Values.ContainsKey('DomainPort')) {
                    $existing = getPamHostnameField -Record $Record
                    $hostName = if ($Values.ContainsKey('DomainHostname')) {
                        [string]$Values['DomainHostname']
                    }
                    else {
                        if ($existing) { $existing.HostName } else { '' }
                    }
                    $port = if ($Values.ContainsKey('DomainPort')) {
                        [string]$Values['DomainPort']
                    }
                    else {
                        if ($existing) { $existing.Port } else { '' }
                    }
                    setPamHostnameField -Record $Record -HostName $hostName -Port $port
                }
            }
            else {
                $hostName = if ($Values.ContainsKey('DomainHostname')) { [string]$Values['DomainHostname'] } else { '' }
                $port = if ($Values.ContainsKey('DomainPort')) { [string]$Values['DomainPort'] } else { '' }
                if (-not [string]::IsNullOrWhiteSpace($hostName) -or -not [string]::IsNullOrWhiteSpace($port)) {
                    setPamHostnameField -Record $Record -HostName $hostName -Port $port
                }
            }

            if ($Values.ContainsKey('DomainUseSsl')) {
                setPamCheckboxField -Record $Record -Label 'useSSL' -TriBool ([string]$Values['DomainUseSsl'])
            }
            if ($Values.ContainsKey('DomainScanDcCidr')) {
                setPamCheckboxField -Record $Record -Label 'scanDCCIDR' -TriBool ([string]$Values['DomainScanDcCidr'])
            }
            if (& $supplied 'DomainNetworkCidr') {
                setPamTypedFieldValue -Record $Record -FieldType 'text' -FieldLabel 'networkCIDR' -Value ([string]$Values['DomainNetworkCidr'])
            }
            if (& $supplied 'DomainUserMatch') {
                setPamTypedFieldValue -Record $Record -FieldType 'text' -FieldLabel 'userMatch' -Value ([string]$Values['DomainUserMatch'])
            }
            if ($Values.ContainsKey('DomainAdministrativeCredential') -and -not [string]::IsNullOrWhiteSpace([string]$Values['DomainAdministrativeCredential'])) {
                $dac = ([string]$Values['DomainAdministrativeCredential']).Trim()
                $force = [bool]$Values['ForceDomainAdmin']
                if ($force) {
                    if ($dac -notmatch '^[A-Za-z0-9\-_]{22}$') {
                        Write-Host ("Warning: Invalid Domain Admin User UID: `"{0}`" (skipped)" -f (maskPamUid $dac))
                    }
                    else {
                        (New-Object KeeperSecurity.Plugins.PAM.PamConfigurationFacade($Record)).AdminCredentialRef = $dac
                    }
                }
                else {
                    $admin = $null
                    try {
                        [KeeperSecurity.Vault.TypedRecord]$byUid = $null
                        if ($dac -match '^[A-Za-z0-9\-_]{22}$' -and
                            [KeeperSecurity.Plugins.PAM.PamVaultHelpers]::TryGetUserRecord($Vault, $dac, [ref]$byUid)) {
                            $admin = $byUid
                        }
                        else {
                            $admin = [KeeperSecurity.Plugins.PAM.PamVaultHelpers]::ResolveRecord(
                                $Vault, $dac, @('pamUser'))
                        }
                        if ($admin) {
                            (New-Object KeeperSecurity.Plugins.PAM.PamConfigurationFacade($Record)).AdminCredentialRef = $admin.Uid
                        }
                        else {
                            Write-Host ("Warning: Domain Admin User UID: `"{0}`" not found (skipped)." -f (maskPamUid $dac))
                        }
                    }
                    catch {
                        Write-Host ("Warning: Domain Admin User UID: `"{0}`" not found (skipped)." -f (maskPamUid $dac))
                        Write-Debug "Domain admin resolve failed: $($_.Exception.Message)"
                    }
                }
            }
        }
        'pamOciConfiguration' {
            if (& $supplied 'OciId') {
                setPamTypedFieldValue -Record $Record -FieldType 'text' -FieldLabel 'pamOciId' -Value ([string]$Values['OciId'])
            }
            if (& $supplied 'OciAdminId') {
                setPamTypedFieldValue -Record $Record -FieldType 'secret' -FieldLabel 'adminOcid' -Value ([string]$Values['OciAdminId'])
            }
            if (& $supplied 'OciAdminPublicKey') {
                setPamTypedFieldValue -Record $Record -FieldType 'secret' -FieldLabel 'adminPublicKey' -Value (readPamMaybeFileContent -Value ([string]$Values['OciAdminPublicKey']))
            }
            if (& $supplied 'OciAdminPrivateKey') {
                setPamTypedFieldValue -Record $Record -FieldType 'secret' -FieldLabel 'adminPrivateKey' -Value (readPamMaybeFileContent -Value ([string]$Values['OciAdminPrivateKey']))
            }
            if (& $supplied 'OciTenancy') {
                setPamTypedFieldValue -Record $Record -FieldType 'text' -FieldLabel 'tenancyOci' -Value ([string]$Values['OciTenancy'])
            }
            if (& $supplied 'OciRegion') {
                setPamTypedFieldValue -Record $Record -FieldType 'text' -FieldLabel 'regionOci' -Value ([string]$Values['OciRegion'])
            }
        }
    }

    if ($Values.ContainsKey('PortMapping') -and $Values['PortMapping']) {
        setPamTypedFieldValue -Record $Record -FieldType 'multiline' -FieldLabel 'portMapping' -Value (($Values['PortMapping'] -join "`n"))
    }
    if ($Values.ContainsKey('IdentityProvider') -and -not [string]::IsNullOrWhiteSpace([string]$Values['IdentityProvider'])) {
        setPamTypedFieldValue -Record $Record -FieldType 'text' -FieldLabel 'identityProviderUid' -Value ([string]$Values['IdentityProvider'])
    }
}

function script:applyPamConfigResources {
    Param (
        [Parameter(Mandatory = $true)]
        [KeeperSecurity.Vault.VaultOnline] $Vault,
        [Parameter(Mandatory = $true)]
        [KeeperSecurity.Plugins.PAM.IPamPlugin] $Plugin,
        [Parameter(Mandatory = $true)]
        [KeeperSecurity.Vault.TypedRecord] $Record,
        [hashtable] $Values,
        [bool] $IsEdit
    )

    $facade = New-Object KeeperSecurity.Plugins.PAM.PamConfigurationFacade($Record)

    if ($Values.ContainsKey('Gateway') -and -not [string]::IsNullOrWhiteSpace([string]$Values['Gateway'])) {
        $gateway = resolvePamGatewayController -Plugin $Plugin -Identifier ([string]$Values['Gateway']) -Vault $Vault
        if ($gateway -is [KeeperSecurity.Plugins.PAM.PamController]) {
            $facade.ControllerUid = if ($gateway.ControllerUid) { $gateway.ControllerUid } else { $gateway.Uid }
        }
        elseif (-not $IsEdit) {
            Write-Host "Warning: Gateway `"$($Values['Gateway'])`" not found."
        }
    }

    if ($Values.ContainsKey('SharedFolder') -and -not [string]::IsNullOrWhiteSpace([string]$Values['SharedFolder'])) {
        $folderUid = resolvePamConfigurationFolderUid -Vault $Vault -Identifier ([string]$Values['SharedFolder'])
        if (-not [string]::IsNullOrEmpty($folderUid)) {
            $resolved = [KeeperSecurity.Plugins.PAM.PamVaultHelpers]::ResolvePamResourcesFolderUid($Vault, $folderUid)
            $facade.FolderUid = if ($resolved) { $resolved } else { $folderUid }
        }
    }
    elseif ($IsEdit -and [string]::IsNullOrEmpty($facade.FolderUid)) {
        throw 'Shared Folder not found'
    }

    if ($Values.ContainsKey('RemoveResourceRecords') -and $Values['RemoveResourceRecords']) {
        $toRemove = New-Object 'System.Collections.Generic.List[string]'
        foreach ($removeRef in @($Values['RemoveResourceRecords'])) {
            if ([string]::IsNullOrWhiteSpace([string]$removeRef)) { continue }
            $trimmed = ([string]$removeRef).Trim()
            try {
                $resolved = [KeeperSecurity.Plugins.PAM.PamVaultHelpers]::ResolveRecord(
                    $Vault, $trimmed, [KeeperSecurity.Plugins.PAM.PamRecordTypes]::Rotation)
                if ($resolved) {
                    [void]$toRemove.Add($resolved.Uid)
                }
                else {
                    Write-Warning "Failed to find PAM record: $removeRef"
                }
            }
            catch {
                Write-Warning "Failed to find PAM record: $removeRef"
                Write-Debug "PAM resource resolve failed for remove-ref: $($_.Exception.Message)"
            }
        }
        if ($toRemove.Count -gt 0) {
            $facade.RemoveResourceRefs($toRemove)
        }
    }

    return $facade
}

function script:configurePamTunnelingIfNeeded {
    Param (
        [Parameter(Mandatory = $true)]
        [KeeperSecurity.Authentication.IAuthentication] $Auth,
        [Parameter(Mandatory = $true)]
        [string] $ConfigUid,
        [hashtable] $Values
    )

    $keys = @(
        'Connections', 'Tunneling', 'Rotation', 'ConnectionsRecording',
        'TypescriptRecording', 'RemoteBrowserIsolation',
        'AiThreatDetection', 'AiTerminateSessionOnDetection'
    )
    $hasAny = $false
    foreach ($key in $keys) {
        if ($Values.ContainsKey($key) -and $null -ne $Values[$key]) {
            $hasAny = $true
            break
        }
    }
    if (-not $hasAny) {
        return
    }

    $get = {
        param($k)
        if ($Values.ContainsKey($k)) { return [string]$Values[$k] }
        return $null
    }

    [KeeperSecurity.Plugins.PAM.ConfigUtils]::ConfigureTunnelingAsync(
        $Auth,
        $ConfigUid,
        [KeeperSecurity.Plugins.PAM.ConfigUtils]::ParseTriState((& $get 'Connections')),
        [KeeperSecurity.Plugins.PAM.ConfigUtils]::ParseTriState((& $get 'Tunneling')),
        [KeeperSecurity.Plugins.PAM.ConfigUtils]::ParseTriState((& $get 'Rotation')),
        [KeeperSecurity.Plugins.PAM.ConfigUtils]::ParseTriState((& $get 'ConnectionsRecording')),
        [KeeperSecurity.Plugins.PAM.ConfigUtils]::ParseTriState((& $get 'TypescriptRecording')),
        [KeeperSecurity.Plugins.PAM.ConfigUtils]::ParseTriState((& $get 'RemoteBrowserIsolation')),
        [KeeperSecurity.Plugins.PAM.ConfigUtils]::ParseTriState((& $get 'AiThreatDetection')),
        [KeeperSecurity.Plugins.PAM.ConfigUtils]::ParseTriState((& $get 'AiTerminateSessionOnDetection'))
    ).GetAwaiter().GetResult() | Out-Null
}

function script:movePamConfigToFolder {
    Param (
        [Parameter(Mandatory = $true)]
        [KeeperSecurity.Vault.VaultOnline] $Vault,
        [Parameter(Mandatory = $true)]
        [KeeperSecurity.Vault.TypedRecord] $Record,
        [Parameter(Mandatory = $true)]
        [string] $DestinationFolderUid
    )

    [KeeperSecurity.Plugins.PAM.PamVaultHelpers]::PlacePamConfigurationInFolderAsync(
        $Vault, $Record, $DestinationFolderUid).GetAwaiter().GetResult() | Out-Null
}

function script:getPamConfigurationTypeSet {
    # Unary comma: keep HashSet as one object.
    try {
        $fromSdk = [KeeperSecurity.Plugins.PAM.PamRecordTypes]::Configuration
        if ($null -ne $fromSdk -and $fromSdk.Count -gt 0) {
            return , $fromSdk
        }
    }
    catch {
        Write-Debug "PAM configuration type set from SDK unavailable: $($_.Exception.Message)"
    }

    $fallback = [System.Collections.Generic.HashSet[string]]::new(
        [string[]]@(
            'pamAwsConfiguration'
            'pamAzureConfiguration'
            'pamGcpConfiguration'
            'pamDomainConfiguration'
            'pamNetworkConfiguration'
            'pamOciConfiguration'
            'pamGitHubConfiguration'
        ),
        [StringComparer]::Ordinal)
    return , $fallback
}

function script:isPamConfigurationTypeName {
    Param (
        [string] $TypeName,
        $AllowedTypes
    )

    if ([string]::IsNullOrEmpty($TypeName) -or $null -eq $AllowedTypes) {
        return $false
    }

    try {
        return [bool]$AllowedTypes.Contains($TypeName)
    }
    catch {
        foreach ($allowed in @($AllowedTypes)) {
            if ($allowed -is [string] -and [string]::Equals($TypeName, $allowed, [StringComparison]::Ordinal)) {
                return $true
            }
        }
        return $false
    }
}

function script:resolvePamConfigFolderInfo {
    Param (
        [Parameter(Mandatory = $true)]
        [KeeperSecurity.Vault.VaultOnline] $Vault,
        [Parameter(Mandatory = $true)]
        [string] $ConfigUid
    )

    [KeeperSecurity.Vault.TypedRecord]$typed = $null
    if (-not [KeeperSecurity.Plugins.PAM.PamVaultHelpers]::TryGetTypedRecord($Vault, $ConfigUid, [ref]$typed) -or
        $null -eq $typed) {
        return $null
    }

    [KeeperSecurity.Plugins.PAM.PamConfigurationFolderInfo]$folderInfo = $null
    if ([KeeperSecurity.Plugins.PAM.PamVaultHelpers]::TryGetConfigurationFolderInfo($Vault, $typed, [ref]$folderInfo)) {
        return $folderInfo
    }

    return $null
}

function script:ensurePamRecordTypesSynced {
    Param (
        [Parameter(Mandatory = $true)]
        [KeeperSecurity.Vault.VaultOnline] $Vault
    )

    try {
        [KeeperSecurity.Vault.SyncDownRestExtension]::EnsurePamRecordTypesAsync($Vault).GetAwaiter().GetResult() | Out-Null
    }
    catch {
        Write-Warning "Could not ensure PAM record types are synced: $($_.Exception.Message). Continuing; field schema may be incomplete."
    }
}

function script:resolvePamConfigurationRecord {
    Param (
        [Parameter(Mandatory = $true)]
        [KeeperSecurity.Vault.VaultOnline] $Vault,
        [Parameter(Mandatory = $true)]
        [string] $Identifier
    )

    $trimmed = $Identifier.Trim()
    if ([string]::IsNullOrWhiteSpace($trimmed)) {
        return $null
    }

    try {
        $resolved = [KeeperSecurity.Plugins.PAM.PamVaultHelpers]::ResolveRecord(
            $Vault, $trimmed, [KeeperSecurity.Plugins.PAM.PamRecordTypes]::Configuration)
        if ($null -ne $resolved) {
            return $resolved
        }
    }
    catch {
        if ($_.Exception.Message -match 'not unique') {
            throw "Configuration `"$trimmed`" is not unique. Use configuration UID."
        }
        Write-Debug "ResolveRecord for PAM configuration failed: $($_.Exception.Message)"
    }

    # Fallback if ResolveRecord returns null. UID list only — avoid List[TypedRecord].
    $allowedTypes = getPamConfigurationTypeSet
    $titleMatchUids = New-Object 'System.Collections.Generic.List[string]'
    foreach ($record in $Vault.KeeperRecords) {
        if ($null -eq $record -or [string]::IsNullOrEmpty($record.Uid)) { continue }
        $tn = ''
        try { $tn = [string]$record.TypeName } catch {
            Write-Debug "Record TypeName read failed: $($_.Exception.Message)"
        }
        if (-not $tn) {
            $tn = [KeeperSecurity.Utils.RecordTypesUtils]::KeeperRecordType($record)
        }
        if (-not (isPamConfigurationTypeName -TypeName $tn -AllowedTypes $allowedTypes)) { continue }

        $recUid = [string]$record.Uid
        if ([string]::Equals($recUid, $trimmed, [StringComparison]::Ordinal)) {
            [KeeperSecurity.Vault.KeeperRecord]$byUid = $null
            if ($Vault.TryGetKeeperRecord($recUid, [ref]$byUid)) {
                return ($byUid -as [KeeperSecurity.Vault.TypedRecord])
            }
            return ($record -as [KeeperSecurity.Vault.TypedRecord])
        }
        if ([string]::Equals([string]$record.Title, $trimmed, [StringComparison]::OrdinalIgnoreCase)) {
            [void]$titleMatchUids.Add($recUid)
        }
    }

    if ($titleMatchUids.Count -eq 1) {
        $matchUid = $null
        foreach ($u in $titleMatchUids) { $matchUid = [string]$u; break }
        if ($matchUid) {
            [KeeperSecurity.Vault.KeeperRecord]$byTitle = $null
            if ($Vault.TryGetKeeperRecord($matchUid, [ref]$byTitle)) {
                return ($byTitle -as [KeeperSecurity.Vault.TypedRecord])
            }
        }
    }
    if ($titleMatchUids.Count -gt 1) {
        throw "Configuration `"$trimmed`" is not unique. Use configuration UID."
    }

    return $null
}

function script:maskPamUid {
    Param ([string] $Uid)
    if ([string]::IsNullOrWhiteSpace($Uid)) { return '****' }
    $trimmed = $Uid.Trim()
    if ($trimmed.Length -lt 8) { return '****' }
    return ($trimmed.Substring(0, 4) + '...' + $trimmed.Substring($trimmed.Length - 4))
}

function script:testPamSecretFieldType {
    Param (
        [string] $FieldName,
        [string] $FieldLabel
    )

    $name = if ($FieldName) { $FieldName.ToLowerInvariant() } else { '' }
    $label = if ($FieldLabel) { $FieldLabel.ToLowerInvariant() } else { '' }
    $secretTypes = @('secret', 'password', 'hidden', 'privatekey', 'keypair', 'passkey')
    foreach ($t in $secretTypes) {
        if ($name -eq $t) { return $true }
    }
    # GCP service-account JSON and similar secrets
    if ($name -eq 'json') { return $true }
    if ($label -match 'secret|password|private|apikey|accesskey|clientsecret|serviceaccount') {
        return $true
    }
    return $false
}

function script:readPamMaybeFileContent {
    Param (
        [string] $Value,
        [int] $MaxBytes = 2097152
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $Value
    }

    $path = $Value.Trim()
    $exists = $false
    try {
        $exists = Test-Path -LiteralPath $path -PathType Leaf -ErrorAction Stop
    }
    catch {
        return $Value
    }
    if (-not $exists) {
        return $Value
    }

    try {
        $item = Get-Item -LiteralPath $path -ErrorAction Stop
        if ($item.Length -gt $MaxBytes) {
            $maxMb = [math]::Round($MaxBytes / 1MB, 2)
            throw "File `"$path`" exceeds the ${maxMb} MB limit."
        }
        return (Get-Content -LiteralPath $path -Raw -Encoding UTF8 -ErrorAction Stop)
    }
    catch {
        throw "Could not read file `"$path`": $($_.Exception.Message)"
    }
}

function script:getPamFieldDisplayName {
    Param ($Field)

    $type = if ($Field.FieldName) { [string]$Field.FieldName } else { '' }
    $label = if ($Field.FieldLabel) { [string]$Field.FieldLabel } else { '' }

    if ($type -eq 'schedule') { return 'Default Schedule' }
    if ($type -and $label) { return "($type).$label" }
    if ($type) { return "($type)" }
    return $label
}

function script:extractPamConfigDisplayFields {
    Param (
        [Parameter(Mandatory = $true)]
        [KeeperSecurity.Vault.TypedRecord] $Config
    )

    $fields = [ordered]@{}
    $all = @($Config.Fields) + @($Config.Custom)
    foreach ($field in $all) {
        if ($null -eq $field) { continue }
        $fname = [string]$field.FieldName
        if ($fname -eq 'pamResources' -or $fname -eq 'fileRef') { continue }
        if ($fname -eq 'schedule' -and [string]$field.FieldLabel -ne 'defaultRotationSchedule') {
            continue
        }

        $vals = New-Object 'System.Collections.Generic.List[string]'
        $flabel = [string]$field.FieldLabel
        if (testPamSecretFieldType -FieldName $fname -FieldLabel $flabel) {
            [void]$vals.Add('***')
        }
        elseif ($fname -eq 'schedule') {
            for ($i = 0; $i -lt $field.Count; $i++) {
                $sched = $field.GetValueAt($i)
                if ($null -eq $sched) { continue }
                $stype = ''
                try { $stype = [string]$sched.Type } catch {
                    Write-Debug "Schedule type read failed: $($_.Exception.Message)"
                }
                if ($stype -eq 'CRON') {
                    $cron = ''
                    try { $cron = [string]$sched.Cron } catch {
                        Write-Debug "Schedule cron read failed: $($_.Exception.Message)"
                    }
                    if (-not [string]::IsNullOrWhiteSpace($cron)) {
                        [void]$vals.Add($cron.Trim())
                    }
                }
            }
        }
        else {
            foreach ($v in @([KeeperSecurity.Utils.RecordTypesUtils]::GetTypedFieldValues($field))) {
                if ($null -ne $v -and -not [string]::IsNullOrWhiteSpace([string]$v)) {
                    [void]$vals.Add([string]$v)
                }
            }
        }

        if ($vals.Count -eq 0) { continue }
        $fields[(getPamFieldDisplayName $field)] = ($vals -join ', ')
    }

    return $fields
}

function script:buildPamConfigListRow {
    Param (
        [Parameter(Mandatory = $true)]
        [KeeperSecurity.Vault.VaultOnline] $Vault,
        [Parameter(Mandatory = $true)]
        [string] $ConfigUid,
        [string] $FallbackTitle = '',
        [string] $FallbackTypeName = '',
        [bool] $VerboseOutput,
        [bool] $AsCommanderJson = $false,
        [bool] $IsDetail = $false
    )

    if ([string]::IsNullOrEmpty($ConfigUid)) {
        return $null
    }

    [KeeperSecurity.Vault.TypedRecord]$typed = $null
    [void][KeeperSecurity.Plugins.PAM.PamVaultHelpers]::TryGetTypedRecord($Vault, $ConfigUid, [ref]$typed)

    $title = $FallbackTitle
    $typeName = $FallbackTypeName
    $gatewayUid = ''
    $resourceUidList = New-Object 'System.Collections.Generic.List[string]'
    $fields = $null
    $adminCred = ''

    if ($null -ne $typed) {
        if (-not $title) { $title = [string]$typed.Title }
        try {
            if (-not $typeName) { $typeName = [string]$typed.TypeName }
        }
        catch {
            Write-Debug "Config TypeName read failed: $($_.Exception.Message)"
        }
        if (-not $typeName) {
            $typeName = [KeeperSecurity.Utils.RecordTypesUtils]::KeeperRecordType($typed)
        }

        try {
            $facade = New-Object KeeperSecurity.Plugins.PAM.PamConfigurationFacade($typed)
            $gatewayUid = [string]$facade.ControllerUid
            foreach ($ref in @($facade.ResourceRef)) {
                $refUid = [string]$ref
                if (-not [string]::IsNullOrWhiteSpace($refUid)) {
                    [void]$resourceUidList.Add($refUid)
                }
            }
            $adminCred = [string]$facade.AdminCredentialRef
            if ($VerboseOutput -or $IsDetail) {
                $fields = extractPamConfigDisplayFields -Config $typed
            }
        }
        catch {
            Write-Debug "PAM configuration facade/fields read failed: $($_.Exception.Message)"
        }
    }

    $folderInfo = resolvePamConfigFolderInfo -Vault $Vault -ConfigUid $ConfigUid
    $folderSuffix = if ($folderInfo -and $folderInfo.IsNsf) { ' [NSF]' } else { '' }
    $sharedFolderText = if ($folderInfo) { "$($folderInfo.Name) ($($folderInfo.Uid))$folderSuffix" } else { '' }
    $resourceJoined = ($resourceUidList -join ', ')

    if ($AsCommanderJson) {
        $folderObj = $null
        $sfObj = $null
        if ($folderInfo) {
            $folderObj = [ordered]@{
                uid  = [string]$folderInfo.Uid
                name = [string]$folderInfo.Name
                type = if ($folderInfo.IsNsf) { 'nested_share_folder' } else { 'shared_folder' }
            }
            if (-not $folderInfo.IsNsf) {
                $sfObj = [ordered]@{
                    name = [string]$folderInfo.Name
                    uid  = [string]$folderInfo.Uid
                }
            }
        }

        if ($IsDetail) {
            $row = [ordered]@{
                uid                   = $ConfigUid
                name                  = $title
                config_type           = $typeName
                folder                = $folderObj
                shared_folder         = $sfObj
                gateway_uid           = $gatewayUid
                resource_record_uids  = @($resourceUidList.ToArray())
                fields                = if ($fields) { $fields } else { [ordered]@{} }
            }
            if ($typeName -eq 'pamDomainConfiguration' -and -not [string]::IsNullOrWhiteSpace($adminCred)) {
                $row['domain_administrative_credential'] = (maskPamUid $adminCred)
            }
            return [PSCustomObject]$row
        }

        $row = [ordered]@{
            uid                  = $ConfigUid
            config_name          = $title
            config_type          = $typeName
            folder               = $folderObj
            shared_folder        = $sfObj
            gateway_uid          = $gatewayUid
            resource_record_uids = @($resourceUidList.ToArray())
        }
        if ($VerboseOutput -and $fields) {
            $row['fields'] = $fields
        }
        return [PSCustomObject]$row
    }

    $row = [ordered]@{
        Uid                = $ConfigUid
        ConfigName         = $title
        ConfigType         = $typeName
        SharedFolder       = $sharedFolderText
        GatewayUid         = $gatewayUid
        ResourceRecordUids = $resourceJoined
    }
    if ($fields -and $fields.Count -gt 0) {
        if ($IsDetail) {
            $row['Fields'] = $fields
        }
        elseif ($VerboseOutput) {
            $parts = foreach ($k in $fields.Keys) { "$k`: $($fields[$k])" }
            $row['Fields'] = ($parts -join '; ')
        }
    }

    return [PSCustomObject]$row
}

function Get-KeeperPamConfig {
    <#
        .SYNOPSIS
        List PAM configurations.

        .DESCRIPTION
        Lists PAM configurations. Equivalent to Commander: pam-config list
        See: https://docs.keeper.io/keeperpam/commander-cli/command-reference/keeperpam-commands#sub-command-config

        .EXAMPLE
        Get-KeeperPamConfig

        .EXAMPLE
        Get-KeeperPamConfig -Config '<CONFIG_UID>' -VerboseOutput -Format json
    #>
    [CmdletBinding()]
    [Alias('pam-config-list', 'pam-cfg-list')]
    Param (
        [Parameter(Position = 0)]
        [Alias('c')]
        [string] $Config,

        [Parameter()]
        [Alias('v')]
        [switch] $VerboseOutput,

        [Parameter()]
        [ValidateSet('table', 'json')]
        [string] $Format = 'table'
    )

    $plugin = ensurePamPlugin -SyncIfNeeded $false
    if (-not $plugin) {
        Write-Error -Message 'PAM plugin is not available. Enterprise admin access is required.' -ErrorAction Stop
    }

    $vault = getPamVault

    if (-not [string]::IsNullOrWhiteSpace($Config)) {
        $configuration = $null
        try {
            $configuration = resolvePamConfigurationRecord -Vault $vault -Identifier $Config
        }
        catch {
            if ($_.Exception.Message -match 'not unique') {
                if ($Format -eq 'json') {
                    @{ error = "Configuration $Config is not unique. Use configuration UID." } | ConvertTo-Json -Depth 5
                }
                else {
                    Write-Output $_.Exception.Message
                }
                return
            }
            throw
        }

        if (-not $configuration) {
            if ($Format -eq 'json') {
                @{ error = "Configuration $Config not found" } | ConvertTo-Json -Depth 5
            }
            else {
                Write-Output "Configuration `"$Config`" not found."
            }
            return
        }

        $detail = buildPamConfigListRow -Vault $vault -ConfigUid $configuration.Uid `
            -FallbackTitle ([string]$configuration.Title) -FallbackTypeName ([string]$configuration.TypeName) `
            -VerboseOutput $true -AsCommanderJson:($Format -eq 'json') -IsDetail $true
        if ($Format -eq 'json') {
            $detail | ConvertTo-Json -Depth 8
        }
        else {
            $detailRows = New-Object 'System.Collections.Generic.List[object]'
            [void]$detailRows.Add([PSCustomObject]@{ Label = 'UID'; Value = [string]$detail.Uid })
            [void]$detailRows.Add([PSCustomObject]@{ Label = 'Name'; Value = [string]$detail.ConfigName })
            [void]$detailRows.Add([PSCustomObject]@{ Label = 'Config Type'; Value = [string]$detail.ConfigType })
            [void]$detailRows.Add([PSCustomObject]@{ Label = 'Shared Folder'; Value = [string]$detail.SharedFolder })
            [void]$detailRows.Add([PSCustomObject]@{ Label = 'Gateway UID'; Value = [string]$detail.GatewayUid })
            [void]$detailRows.Add([PSCustomObject]@{ Label = 'Resource Record UIDs'; Value = [string]$detail.ResourceRecordUids })

            if ($null -ne $detail.Fields) {
                foreach ($key in @($detail.Fields.Keys)) {
                    [void]$detailRows.Add([PSCustomObject]@{
                            Label = [string]$key
                            Value = [string]$detail.Fields[$key]
                        })
                }
            }

            $labelWidth = 0
            foreach ($r in $detailRows) {
                $len = ([string]$r.Label).Length
                if ($len -gt $labelWidth) { $labelWidth = $len }
            }
            $fmt = "{0,$labelWidth}  {1}"
            foreach ($r in $detailRows) {
                Write-Output ($fmt -f [string]$r.Label, [string]$r.Value)
            }
        }
        return
    }

    # String props for Sort-Object / Format-Table.
    $prepared = New-Object 'System.Collections.Generic.List[object]'
    $configMap = [KeeperSecurity.Plugins.PAM.PamVaultHelpers]::GetConfigurationRecords($vault)
    if ($null -ne $configMap) {
        foreach ($entry in $configMap.GetEnumerator()) {
            $typed = $entry.Value
            if ($null -eq $typed -or [string]::IsNullOrEmpty($typed.Uid)) { continue }
            [void]$prepared.Add([PSCustomObject]@{
                    Uid      = [string]$typed.Uid
                    Title    = [string]$typed.Title
                    TypeName = [string]$typed.TypeName
                })
        }
    }

    $sorted = @($prepared | Sort-Object -Property @{ Expression = { $_.Title }; Ascending = $true })
    $rows = New-Object 'System.Collections.Generic.List[object]'
    $nsfLines = New-Object 'System.Collections.Generic.List[string]'

    foreach ($item in $sorted) {
        $uid = [string]$item.Uid
        if ([string]::IsNullOrEmpty($uid)) { continue }

        [KeeperSecurity.Vault.TypedRecord]$typed = $null
        [void][KeeperSecurity.Plugins.PAM.PamVaultHelpers]::TryGetTypedRecord($vault, $uid, [ref]$typed)

        $inSharedFolder = $false
        if ($null -ne $typed) {
            $inSharedFolder = [KeeperSecurity.Plugins.PAM.PamVaultHelpers]::IsConfigurationInSharedFolder($vault, $typed)
        }
        if (-not $inSharedFolder) {
            try {
                $byPermission = [KeeperSecurity.Plugins.PAM.PamVaultHelpers]::FindSharedFolderForRecord($vault, $uid, $null)
                $inSharedFolder = ($null -ne $byPermission)
            }
            catch {
                $inSharedFolder = $false
                Write-Debug "Shared-folder permission fallback failed: $($_.Exception.Message)"
            }
        }
        if (-not $inSharedFolder) {
            [void]$nsfLines.Add(("Warning: Following configuration is not in the shared folder: UID: {0}, Title: {1}" -f $uid, [string]$item.Title))
            continue
        }

        $row = buildPamConfigListRow -Vault $vault -ConfigUid $uid `
            -FallbackTitle ([string]$item.Title) -FallbackTypeName ([string]$item.TypeName) `
            -VerboseOutput:$VerboseOutput.IsPresent -AsCommanderJson:($Format -eq 'json')
        if ($null -ne $row) {
            [void]$rows.Add($row)
        }
    }

    if ($Format -eq 'json') {
        # Host NSF warnings so JSON on the success stream stays parseable.
        foreach ($line in $nsfLines) {
            Write-Host $line
        }
        @{ configurations = @($rows.ToArray()) } | ConvertTo-Json -Depth 8
        return
    }

    foreach ($line in $nsfLines) {
        Write-Output $line
    }

    if ($rows.Count -eq 0) {
        Write-Output 'No PAM configurations found.'
        return
    }

    $rows.ToArray() | Format-Table -AutoSize
}

function New-KeeperPamConfig {
    <#
        .SYNOPSIS
        Create a new PAM configuration.

        .DESCRIPTION
        Creates a PAM configuration.
        .EXAMPLE
        New-KeeperPamConfig -Environment local -Title 'Network Config' -SharedFolder '<SF_UID>' -Gateway '<GATEWAY>' -NetworkId 'net1' -NetworkCidr '10.0.0.0/24'
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    [Alias('pam-config-new', 'pam-cfg-new')]
    Param (
        [Parameter(Mandatory = $true)]
        [Alias('env')]
        [ValidateSet('local', 'aws', 'azure', 'gcp', 'domain', 'oci', 'network', 'github')]
        [string] $Environment,

        [Parameter(Mandatory = $true)]
        [Alias('t')]
        [string] $Title,

        [Parameter(Mandatory = $true)]
        [Alias('sf', 'shared-folder')]
        [string] $SharedFolder,

        [Parameter()]
        [Alias('g')]
        [string] $Gateway,

        [Parameter()]
        [Alias('sc', 'schedule')]
        [string] $DefaultSchedule,

        [Parameter()]
        [Alias('pm', 'port-mapping')]
        [string[]] $PortMapping,

        [Parameter()]
        [Alias('idp', 'identity-provider')]
        [string] $IdentityProvider,

        [Parameter()]
        [Alias('c')]
        [ValidateSet('on', 'off', 'default')]
        [string] $Connections,

        [Parameter()]
        [Alias('u')]
        [ValidateSet('on', 'off', 'default')]
        [string] $Tunneling,

        [Parameter()]
        [Alias('r')]
        [ValidateSet('on', 'off', 'default')]
        [string] $Rotation,

        [Parameter()]
        [Alias('rbi', 'remote-browser-isolation')]
        [ValidateSet('on', 'off', 'default')]
        [string] $RemoteBrowserIsolation,

        [Parameter()]
        [Alias('cr', 'connections-recording')]
        [ValidateSet('on', 'off', 'default')]
        [string] $ConnectionsRecording,

        [Parameter()]
        [Alias('tr', 'typescript-recording')]
        [ValidateSet('on', 'off', 'default')]
        [string] $TypescriptRecording,

        [Parameter()]
        [Alias('ai-threat-detection')]
        [ValidateSet('on', 'off', 'default')]
        [string] $AiThreatDetection,

        [Parameter()]
        [Alias('ai-terminate-session-on-detection')]
        [ValidateSet('on', 'off', 'default')]
        [string] $AiTerminateSessionOnDetection,

        [Parameter()][Alias('network-id')][string] $NetworkId,
        [Parameter()][Alias('network-cidr')][string] $NetworkCidr,
        [Parameter()][Alias('aws-id')][string] $AwsId,
        [Parameter()][Alias('access-key-id')][string] $AccessKeyId,
        [Parameter()][Alias('access-secret-key')][string] $AccessSecretKey,
        [Parameter()][Alias('region-name')][string[]] $RegionNames,
        [Parameter()][Alias('azure-id')][string] $AzureId,
        [Parameter()][Alias('client-id')][string] $ClientId,
        [Parameter()][Alias('client-secret')][string] $ClientSecret,
        [Parameter()][Alias('subscription-id', 'subscription_id')][string] $SubscriptionId,
        [Parameter()][Alias('tenant-id')][string] $TenantId,
        [Parameter()][Alias('resource-group')][string[]] $ResourceGroups,
        [Parameter()][Alias('gcp-id')][string] $GcpId,
        [Parameter()][Alias('service-account-key')][string] $ServiceAccountKey,
        [Parameter()][Alias('google-admin-email')][string] $GoogleAdminEmail,
        [Parameter()][Alias('gcp-region')][string[]] $GcpRegionNames,
        [Parameter()][Alias('domain-id')][string] $DomainId,
        [Parameter()][Alias('domain-hostname')][string] $DomainHostname,
        [Parameter()][Alias('domain-port')][string] $DomainPort,
        [Parameter()][Alias('domain-use-ssl')][ValidateSet('true', 'false')][string] $DomainUseSsl,
        [Parameter()][Alias('domain-scan-dc-cidr')][ValidateSet('true', 'false')][string] $DomainScanDcCidr,
        [Parameter()][Alias('domain-network-cidr')][string] $DomainNetworkCidr,
        [Parameter()][Alias('domain-admin')][string] $DomainAdministrativeCredential,
        [Parameter()][Alias('domain-user-match')][string] $DomainUserMatch,
        [Parameter()][Alias('force-domain-admin')][switch] $ForceDomainAdmin,
        [Parameter()][Alias('oci-id')][string] $OciId,
        [Parameter()][Alias('oci-admin-id')][string] $OciAdminId,
        [Parameter()][Alias('oci-admin-public-key')][string] $OciAdminPublicKey,
        [Parameter()][Alias('oci-admin-private-key')][string] $OciAdminPrivateKey,
        [Parameter()][Alias('oci-tenancy')][string] $OciTenancy,
        [Parameter()][Alias('oci-region')][string] $OciRegion
    )

    $plugin = ensurePamPlugin
    if (-not $plugin) {
        Write-Error -Message 'PAM plugin is not available. Enterprise admin access is required.' -ErrorAction Stop
    }

    $vault = getPamVault
    $auth = getPamEnterpriseAuth

    if (writePamComingSoonMessage -Environment $Environment) {
        return
    }

    if (-not $PSCmdlet.ShouldProcess($Title, 'Create PAM configuration')) {
        return
    }

    [string]$recordType = $null
    if (-not [KeeperSecurity.Plugins.PAM.PamConfigTypes]::TryResolveRecordType($Environment, [ref]$recordType)) {
        throw "Environment parameter is required. Supported options: $([KeeperSecurity.Plugins.PAM.PamConfigTypes]::GetSupportedConfigTypes())"
    }

    ensurePamRecordTypesSynced -Vault $vault

    $values = preparePamConfigValuesFromBoundParameters -BoundParameters $PSBoundParameters

    $record = [KeeperSecurity.Plugins.PAM.ConfigUtils]::CreateConfigurationRecord($vault, $recordType, $Title)
    $facade = applyPamConfigResources -Vault $vault -Plugin $plugin -Record $record -Values $values -IsEdit:$false
    if (-not ($facade -is [KeeperSecurity.Plugins.PAM.PamConfigurationFacade])) {
        throw 'Failed to initialize PAM configuration resources.'
    }
    applyPamConfigEnvironmentFields -Vault $vault -Record $record -Values $values -IsEdit:$false
    applyPamConfigSchedule -Record $record -DefaultSchedule $DefaultSchedule -IsEdit:$false

    $moveDestinationUid = resolvePamConfigurationFolderUid -Vault $vault -Identifier $SharedFolder
    $sharedFolderUid = [KeeperSecurity.Plugins.PAM.PamVaultHelpers]::ResolvePamResourcesFolderUid($vault, $facade.FolderUid)
    if (-not $sharedFolderUid) {
        $sharedFolderUid = [KeeperSecurity.Plugins.PAM.PamVaultHelpers]::ResolvePamResourcesFolderUid($vault, $moveDestinationUid)
    }
    if ($sharedFolderUid) {
        $facade.FolderUid = $sharedFolderUid
    }

    if (-not $sharedFolderUid -or -not $moveDestinationUid) {
        throw "Could not resolve shared folder `"$SharedFolder`". Provide a shared folder or NSF folder UID, name, or path."
    }

    $isNsfFolder = [KeeperSecurity.Plugins.PAM.PamVaultHelpers]::IsKeeperNSFFolder($vault, $moveDestinationUid)
    $nsfFolderUid = if ($isNsfFolder) { $moveDestinationUid } else { $null }

    [KeeperSecurity.Utils.RecordTypesUtils]::AdjustTypedRecord($vault, $record)
    [KeeperSecurity.Plugins.PAM.ConfigUtils]::AddConfigurationRecordAsync($vault, $record, $nsfFolderUid).GetAwaiter().GetResult() | Out-Null

    try {
        [KeeperSecurity.Plugins.PAM.ConfigUtils]::EnsureConfigurationNetworkGraphAsync($auth, $record.Uid).GetAwaiter().GetResult() | Out-Null
    }
    catch {
        Write-Warning "Could not register PAM configuration network graph: $($_.Exception.Message)"
    }

    configurePamTunnelingIfNeeded -Auth $auth -ConfigUid $record.Uid -Values $values
    if (-not $isNsfFolder) {
        movePamConfigToFolder -Vault $vault -Record $record -DestinationFolderUid $moveDestinationUid
    }

    if (-not [string]::IsNullOrEmpty($facade.ControllerUid)) {
        [KeeperSecurity.Plugins.PAM.ConfigUtils]::SetConfigurationGatewayAsync(
            $auth, $record.Uid, $facade.ControllerUid).GetAwaiter().GetResult() | Out-Null
    }

    $vault.SyncDown().GetAwaiter().GetResult() | Out-Null
    [void](syncPamPlugin -Plugin $plugin -Reload $true -ThrowOnError $false)
    Write-Output $record.Uid
}

function Set-KeeperPamConfig {
    <#
        .SYNOPSIS
        Edit an existing PAM configuration.

        .DESCRIPTION
        Updates a PAM configuration.

        .EXAMPLE
        Set-KeeperPamConfig -Uid '<CONFIG_UID>' -Title 'Updated Title'
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    [Alias('pam-config-edit', 'pam-cfg-edit')]
    Param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $Uid,

        [Parameter()]
        [Alias('env')]
        [ValidateSet('local', 'aws', 'azure', 'gcp', 'domain', 'oci', 'network', 'github')]
        [string] $Environment,

        [Parameter()]
        [Alias('t')]
        [string] $Title,

        [Parameter()]
        [Alias('sf', 'shared-folder')]
        [string] $SharedFolder,

        [Parameter()]
        [Alias('g')]
        [string] $Gateway,

        [Parameter()]
        [Alias('sc', 'schedule')]
        [string] $DefaultSchedule,

        [Parameter()]
        [Alias('pm', 'port-mapping')]
        [string[]] $PortMapping,

        [Parameter()]
        [Alias('idp', 'identity-provider')]
        [string] $IdentityProvider,

        [Parameter()]
        [Alias('rrr', 'remove-resource-record')]
        [string[]] $RemoveResourceRecords,

        [Parameter()]
        [Alias('c')]
        [ValidateSet('on', 'off', 'default')]
        [string] $Connections,

        [Parameter()]
        [Alias('u')]
        [ValidateSet('on', 'off', 'default')]
        [string] $Tunneling,

        [Parameter()]
        [Alias('r')]
        [ValidateSet('on', 'off', 'default')]
        [string] $Rotation,

        [Parameter()]
        [Alias('rbi', 'remote-browser-isolation')]
        [ValidateSet('on', 'off', 'default')]
        [string] $RemoteBrowserIsolation,

        [Parameter()]
        [Alias('cr', 'connections-recording')]
        [ValidateSet('on', 'off', 'default')]
        [string] $ConnectionsRecording,

        [Parameter()]
        [Alias('tr', 'typescript-recording')]
        [ValidateSet('on', 'off', 'default')]
        [string] $TypescriptRecording,

        [Parameter()]
        [Alias('ai-threat-detection')]
        [ValidateSet('on', 'off', 'default')]
        [string] $AiThreatDetection,

        [Parameter()]
        [Alias('ai-terminate-session-on-detection')]
        [ValidateSet('on', 'off', 'default')]
        [string] $AiTerminateSessionOnDetection,

        [Parameter()][Alias('network-id')][string] $NetworkId,
        [Parameter()][Alias('network-cidr')][string] $NetworkCidr,
        [Parameter()][Alias('aws-id')][string] $AwsId,
        [Parameter()][Alias('access-key-id')][string] $AccessKeyId,
        [Parameter()][Alias('access-secret-key')][string] $AccessSecretKey,
        [Parameter()][Alias('region-name')][string[]] $RegionNames,
        [Parameter()][Alias('azure-id')][string] $AzureId,
        [Parameter()][Alias('client-id')][string] $ClientId,
        [Parameter()][Alias('client-secret')][string] $ClientSecret,
        [Parameter()][Alias('subscription-id', 'subscription_id')][string] $SubscriptionId,
        [Parameter()][Alias('tenant-id')][string] $TenantId,
        [Parameter()][Alias('resource-group')][string[]] $ResourceGroups,
        [Parameter()][Alias('gcp-id')][string] $GcpId,
        [Parameter()][Alias('service-account-key')][string] $ServiceAccountKey,
        [Parameter()][Alias('google-admin-email')][string] $GoogleAdminEmail,
        [Parameter()][Alias('gcp-region')][string[]] $GcpRegionNames,
        [Parameter()][Alias('domain-id')][string] $DomainId,
        [Parameter()][Alias('domain-hostname')][string] $DomainHostname,
        [Parameter()][Alias('domain-port')][string] $DomainPort,
        [Parameter()][Alias('domain-use-ssl')][ValidateSet('true', 'false')][string] $DomainUseSsl,
        [Parameter()][Alias('domain-scan-dc-cidr')][ValidateSet('true', 'false')][string] $DomainScanDcCidr,
        [Parameter()][Alias('domain-network-cidr')][string] $DomainNetworkCidr,
        [Parameter()][Alias('domain-admin')][string] $DomainAdministrativeCredential,
        [Parameter()][Alias('domain-user-match')][string] $DomainUserMatch,
        [Parameter()][Alias('force-domain-admin')][switch] $ForceDomainAdmin,
        [Parameter()][Alias('oci-id')][string] $OciId,
        [Parameter()][Alias('oci-admin-id')][string] $OciAdminId,
        [Parameter()][Alias('oci-admin-public-key')][string] $OciAdminPublicKey,
        [Parameter()][Alias('oci-admin-private-key')][string] $OciAdminPrivateKey,
        [Parameter()][Alias('oci-tenancy')][string] $OciTenancy,
        [Parameter()][Alias('oci-region')][string] $OciRegion
    )

    $plugin = ensurePamPlugin -SyncIfNeeded $false
    if (-not $plugin) {
        Write-Error -Message 'PAM plugin is not available. Enterprise admin access is required.' -ErrorAction Stop
    }

    $vault = getPamVault
    $auth = getPamEnterpriseAuth

    if ($PSBoundParameters.ContainsKey('Environment') -and (writePamComingSoonMessage -Environment $Environment)) {
        return
    }

    $configuration = resolvePamConfigurationRecord -Vault $vault -Identifier $Uid
    if (-not $configuration) {
        throw "PAM configuration `"$Uid`" not found"
    }

    if (-not $PSCmdlet.ShouldProcess($configuration.Title, 'Update PAM configuration')) {
        return
    }

    ensurePamRecordTypesSynced -Vault $vault

    if ($PSBoundParameters.ContainsKey('Environment')) {
        [string]$newType = $null
        if ([KeeperSecurity.Plugins.PAM.PamConfigTypes]::TryResolveRecordType($Environment, [ref]$newType) -and
            -not [string]::Equals($newType, $configuration.TypeName, [StringComparison]::Ordinal)) {
            $configuration.TypeName = $newType
            Write-Warning "Environment type changed to `"$Environment`". Review fields after edit."
        }
    }
    [KeeperSecurity.Utils.RecordTypesUtils]::AdjustTypedRecord($vault, $configuration)

    if ($PSBoundParameters.ContainsKey('Title') -and -not [string]::IsNullOrWhiteSpace($Title)) {
        $configuration.Title = $Title.Trim()
    }

    $values = preparePamConfigValuesFromBoundParameters -BoundParameters $PSBoundParameters -ExcludeKeys @('Uid')

    $facadeBefore = New-Object KeeperSecurity.Plugins.PAM.PamConfigurationFacade($configuration)
    $origGatewayUid = $facadeBefore.ControllerUid
    $origSharedFolderUid = $facadeBefore.FolderUid

    $facade = applyPamConfigResources -Vault $vault -Plugin $plugin -Record $configuration -Values $values -IsEdit:$true
    if (-not ($facade -is [KeeperSecurity.Plugins.PAM.PamConfigurationFacade])) {
        throw 'Failed to update PAM configuration resources.'
    }
    applyPamConfigEnvironmentFields -Vault $vault -Record $configuration -Values $values -IsEdit:$true
    applyPamConfigSchedule -Record $configuration -DefaultSchedule $DefaultSchedule -IsEdit:$true

    [KeeperSecurity.Utils.RecordTypesUtils]::AdjustTypedRecord($vault, $configuration)
    $vault.UpdateRecord($configuration).GetAwaiter().GetResult() | Out-Null

    $facade = New-Object KeeperSecurity.Plugins.PAM.PamConfigurationFacade($configuration)
    if (-not [string]::Equals($facade.ControllerUid, $origGatewayUid, [StringComparison]::Ordinal) -and
        -not [string]::IsNullOrEmpty($facade.ControllerUid)) {
        [KeeperSecurity.Plugins.PAM.ConfigUtils]::SetConfigurationGatewayAsync(
            $auth, $configuration.Uid, $facade.ControllerUid).GetAwaiter().GetResult() | Out-Null
    }

    if (-not [string]::Equals($facade.FolderUid, $origSharedFolderUid, [StringComparison]::Ordinal) -and
        -not [string]::IsNullOrEmpty($facade.FolderUid)) {
        $moveFolderUid = resolvePamConfigurationFolderUid -Vault $vault -Identifier $facade.FolderUid
        if (-not $moveFolderUid) { $moveFolderUid = $facade.FolderUid }
        movePamConfigToFolder -Vault $vault -Record $configuration -DestinationFolderUid $moveFolderUid
    }

    configurePamTunnelingIfNeeded -Auth $auth -ConfigUid $configuration.Uid -Values $values

    $vault.ScheduleSyncDown([TimeSpan]::FromMilliseconds(100)).GetAwaiter().GetResult() | Out-Null
    Write-Output "PAM configuration `"$($configuration.Title)`" updated."
}

function Remove-KeeperPamConfig {
    <#
        .SYNOPSIS
        Remove a PAM configuration.

        .DESCRIPTION
        Removes a PAM configuration.

        .EXAMPLE
        Remove-KeeperPamConfig -Uid '<CONFIG_UID>'
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    [Alias('pam-config-remove', 'pam-cfg-remove', 'pam-config-rm')]
    Param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $Uid
    )

    # Vault-only remove (no enterprise/PAM plugin required).
    $vault = getPamVault
    $config = resolvePamConfigurationRecord -Vault $vault -Identifier $Uid
    if (-not $config) {
        Write-Error -Message "Configuration `"$Uid`" not found" -ErrorAction Stop
    }

    $title = [string]$config.Title
    $configUid = [string]$config.Uid
    if (-not $PSCmdlet.ShouldProcess($title, 'Remove PAM configuration')) {
        return
    }

    [KeeperSecurity.Plugins.PAM.ConfigUtils]::RemovePamConfigurationAsync($vault, $configUid).GetAwaiter().GetResult() | Out-Null
    $vault.ScheduleSyncDown([TimeSpan]::FromMilliseconds(100)).GetAwaiter().GetResult() | Out-Null
    Write-Output "PAM configuration `"$title`" removed."
}
