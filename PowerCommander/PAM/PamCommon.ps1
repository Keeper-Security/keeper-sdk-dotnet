#requires -Version 5.1

# Shared PAM helpers (getPamPlugin / ensurePamPlugin / syncPamPlugin / getPamControllerList)
# live in PAM\SyncDown.ps1 (release). This file keeps rotation + config helpers.


$script:PamRotationScriptVerbs = New-Object 'System.Collections.Generic.HashSet[string]'
[void]$script:PamRotationScriptVerbs.Add('list')
[void]$script:PamRotationScriptVerbs.Add('l')
[void]$script:PamRotationScriptVerbs.Add('add')
[void]$script:PamRotationScriptVerbs.Add('new')
[void]$script:PamRotationScriptVerbs.Add('n')
[void]$script:PamRotationScriptVerbs.Add('a')
[void]$script:PamRotationScriptVerbs.Add('edit')
[void]$script:PamRotationScriptVerbs.Add('e')
[void]$script:PamRotationScriptVerbs.Add('delete')
[void]$script:PamRotationScriptVerbs.Add('d')

function script:testPamRotationScriptVerb {
    Param ([string] $Value)
    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $false
    }
    $trimmed = $Value.Trim()
    foreach ($verb in $script:PamRotationScriptVerbs) {
        if ([string]::Equals($verb, $trimmed, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }
    return $false
}

function script:encodePamByteString {
    Param (
        [Google.Protobuf.ByteString] $ByteString
    )

    if ($null -eq $ByteString -or $ByteString.IsEmpty) {
        return ''
    }

    return [KeeperSecurity.Utils.CryptoUtils]::Base64UrlEncode($ByteString.ToByteArray())
}

function script:resolvePamRotationRecord {
    Param (
        [Parameter(Mandatory = $true)]
        [KeeperSecurity.Vault.VaultOnline] $Vault,
        [Parameter(Mandatory = $true)]
        [string] $Identifier,
        [Parameter(Mandatory = $true)]
        [System.Collections.Generic.HashSet[string]] $AllowedTypes
    )

    try {
        return [KeeperSecurity.Plugins.PAM.PamVaultHelpers]::ResolveRecord($Vault, $Identifier.Trim(), $AllowedTypes)
    }
    catch [System.InvalidOperationException] {
        Write-Output $_.Exception.Message
        throw
    }
}

function script:testPamRotationScriptOwnerException {
    Param (
        [Parameter(Mandatory = $true)]
        [System.Exception] $Exception
    )

    $ex = $Exception
    while ($null -ne $ex) {
        if ($ex -is [KeeperSecurity.Authentication.KeeperApiException]) {
            $code = [string]$ex.Code
            if ($code -eq 'only_owner_can_modify_scripts' -or $code -eq 'RS_ONLY_OWNER_CAN_MODIFY_SCRIPTS') {
                return $true
            }
        }
        $ex = $ex.InnerException
    }
    return $false
}

function script:updatePamRotationScriptRecord {
    Param (
        [Parameter(Mandatory = $true)]
        [KeeperSecurity.Vault.VaultOnline] $Vault,
        [Parameter(Mandatory = $true)]
        [KeeperSecurity.Vault.TypedRecord] $Record,
        [Parameter(Mandatory = $true)]
        [ValidateSet('add', 'edit', 'remove')]
        [string] $Action
    )

    try {
        $Vault.UpdateRecord($Record).GetAwaiter().GetResult() | Out-Null
        return $true
    }
    catch {
        if (testPamRotationScriptOwnerException -Exception $_.Exception) {
            switch ($Action) {
                'add' { Write-Output 'Only the record owner can attach post-rotation scripts.' }
                'edit' { Write-Output 'Only the record owner can edit post-rotation scripts.' }
                'remove' { Write-Output 'Only the record owner can remove post-rotation scripts.' }
            }
            return $false
        }
        throw
    }
}

function script:getPamRotationVault {
    $vault = getVault
    if (-not $vault) {
        Write-Error -Message 'Vault is not available.' -ErrorAction Stop
    }

    return $vault
}

function script:confirmPamYesNo {
    Param (
        [Parameter(Mandatory = $true)]
        [string] $Prompt,
        [bool] $DefaultYes = $true
    )

    $suffix = if ($DefaultYes) { ' [Y/n]: ' } else { ' [y/N]: ' }
    $answer = Read-Host ($Prompt.TrimEnd() + $suffix)
    if ([string]::IsNullOrWhiteSpace($answer)) {
        return $DefaultYes
    }

    return ($answer.Trim().StartsWith('y', [System.StringComparison]::OrdinalIgnoreCase))
}

function script:toPamUidBytes {
    Param ([string] $Uid)
    return [KeeperSecurity.Utils.CryptoUtils]::Base64UrlDecode($Uid)
}

function script:enumeratePamTypedFields {
    Param ([KeeperSecurity.Vault.TypedRecord] $Record)

    if ($null -eq $Record) {
        return @()
    }

    $fields = New-Object System.Collections.Generic.List[object]
    if ($null -ne $Record.Fields) {
        foreach ($f in $Record.Fields) { [void]$fields.Add($f) }
    }
    if ($null -ne $Record.Custom) {
        foreach ($f in $Record.Custom) { [void]$fields.Add($f) }
    }
    return , $fields.ToArray()
}

function script:getPamDefaultScheduleFromConfig {
    Param ([KeeperSecurity.Vault.TypedRecord] $Config)

    if ($null -eq $Config) {
        return $null
    }

    $scheduleField = $null
    foreach ($field in (enumeratePamTypedFields -Record $Config)) {
        if ($field.FieldName -ne 'schedule') {
            continue
        }
        if ($field.FieldLabel -eq 'defaultRotationSchedule') {
            $scheduleField = $field
            break
        }
        if ($null -eq $scheduleField) {
            $scheduleField = $field
        }
    }

    if ($null -eq $scheduleField -or $null -eq $scheduleField.Values -or $scheduleField.Values.Count -eq 0) {
        return $null
    }

    $value = $scheduleField.Values[0]
    if ($null -eq $value) {
        return $null
    }

    if ([string]::IsNullOrWhiteSpace($value.Type) -or
        [string]::Equals($value.Type, 'On-Demand', [System.StringComparison]::OrdinalIgnoreCase)) {
        return New-Object 'System.Collections.Generic.List[object]'
    }

    $dict = New-Object 'System.Collections.Generic.Dictionary[string,object]'
    $dict['type'] = $value.Type
    if (-not [string]::IsNullOrEmpty($value.Time)) {
        $dict['time'] = $value.Time
        $dict['utcTime'] = $value.Time
    }
    if (-not [string]::IsNullOrEmpty($value.Weekday)) { $dict['weekday'] = $value.Weekday }
    if (-not [string]::IsNullOrEmpty($value.Month)) { $dict['month'] = $value.Month }
    if (-not [string]::IsNullOrEmpty($value.MonthDay)) { $dict['monthDay'] = $value.MonthDay }
    if (-not [string]::IsNullOrEmpty($value.IntervalCount)) { $dict['intervalCount'] = $value.IntervalCount }
    if (-not [string]::IsNullOrEmpty($value.Cron)) { $dict['cron'] = $value.Cron }
    if (-not [string]::IsNullOrEmpty($value.TimeZone)) { $dict['tz'] = $value.TimeZone }

    $list = New-Object 'System.Collections.Generic.List[object]'
    [void]$list.Add($dict)
    return , $list
}

function script:toPamScheduleObjectList {
    Param ($ScheduleData)

    $list = New-Object 'System.Collections.Generic.List[object]'
    if ($null -eq $ScheduleData) {
        return , $list
    }

    if ($ScheduleData -is [System.Collections.Generic.List[object]]) {
        return , $ScheduleData
    }

    if ($ScheduleData -is [System.Collections.IDictionary]) {
        [void]$list.Add($ScheduleData)
        return , $list
    }

    if (($ScheduleData -is [System.Collections.IEnumerable]) -and -not ($ScheduleData -is [string])) {
        foreach ($item in $ScheduleData) {
            if ($null -ne $item) {
                [void]$list.Add($item)
            }
        }
        return , $list
    }

    [void]$list.Add($ScheduleData)
    return , $list
}

function script:getPamDefaultResourceUidFromConfig {
    Param ([KeeperSecurity.Vault.TypedRecord] $Config)

    if ($null -eq $Config -or $null -eq $Config.Fields) {
        return $null
    }

    foreach ($field in $Config.Fields) {
        if ($field.FieldName -ne 'pamResources') {
            continue
        }
        if ($null -eq $field.Values -or $field.Values.Count -eq 0) {
            return $null
        }
        $refs = $field.Values[0].ResourceRef
        if ($null -eq $refs -or $refs.Length -ne 1) {
            return $null
        }
        return [string]$refs[0]
    }
    return $null
}

function script:testPamNoopRecord {
    Param ([KeeperSecurity.Vault.TypedRecord] $Record)

    if ($null -eq $Record -or $null -eq $Record.Fields) {
        return $false
    }

    foreach ($field in $Record.Fields) {
        if ($field.FieldName -ne 'NOOP') {
            continue
        }
        if ($null -eq $field.Values -or $field.Values.Count -eq 0) {
            return $false
        }
        $value = [string]$field.Values[0]
        return (-not [string]::IsNullOrEmpty($value) -and
            [string]::Equals($value.Trim(), 'TRUE', [System.StringComparison]::OrdinalIgnoreCase))
    }
    return $false
}

function script:formatPamPasswordComplexityInfoDisplay {
    Param ([KeeperSecurity.Utils.PasswordGenerationOptions] $Rules)

    if ($null -eq $Rules) {
        return ''
    }

    $chars = $Rules.SpecialCharacters
    if ([string]::IsNullOrEmpty($chars)) {
        $chars = '!@#$%^&*()_+=-[];,.<>?'
    }

    return ("Length: {0}; Lowercase: {1}; Uppercase: {2}; Digits: {3}; Symbols: {4}; Special Characters: {5}" -f `
        $Rules.Length, $Rules.Lower, $Rules.Upper, $Rules.Digit, $Rules.Special, $chars)
}

function script:testPamUsesDefaultRotationSchedule {
    Param (
        [KeeperSecurity.Vault.VaultOnline] $Vault,
        [string] $RecordUid,
        [string] $ConfigUid
    )

    if ($null -eq $Vault -or [string]::IsNullOrWhiteSpace($RecordUid) -or [string]::IsNullOrWhiteSpace($ConfigUid)) {
        return $false
    }

    $config = [KeeperSecurity.Plugins.PAM.PamVaultHelpers]::ResolveRecord(
        $Vault, $ConfigUid.Trim(), [KeeperSecurity.Plugins.PAM.PamRecordTypes]::Configuration)
    if ($null -eq $config) {
        return $false
    }

    $defaultSchedule = toPamScheduleObjectList (getPamDefaultScheduleFromConfig -Config $config)
    if ($defaultSchedule.Count -eq 0) {
        return $false
    }

    $cached = $Vault.GetRecordRotation($RecordUid.Trim())
    if ($null -eq $cached -or [string]::IsNullOrWhiteSpace($cached.Schedule)) {
        return $false
    }

    try {
        $recordSchedule = toPamScheduleObjectList (
            [KeeperSecurity.Plugins.PAM.RotationUtils]::ParseScheduleJsonString($cached.Schedule))
    }
    catch {
        return $false
    }

    if ($recordSchedule.Count -eq 0) {
        return $false
    }

    return [string]::Equals(
        [KeeperSecurity.Plugins.PAM.RotationUtils]::SerializeScheduleData($recordSchedule),
        [KeeperSecurity.Plugins.PAM.RotationUtils]::SerializeScheduleData($defaultSchedule),
        [System.StringComparison]::Ordinal)
}

function script:resolvePamRotationTargetRecords {
    Param (
        [KeeperSecurity.Vault.VaultOnline] $Vault,
        [string] $Record,
        [string] $Folder
    )

    $recordUids = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
    $rotationTypes = [KeeperSecurity.Plugins.PAM.PamRecordTypes]::Rotation

    if (-not [string]::IsNullOrWhiteSpace($Record)) {
        $resolved = $null
        try {
            $resolved = [KeeperSecurity.Plugins.PAM.PamVaultHelpers]::ResolveRecord($Vault, $Record.Trim(), $rotationTypes)
        }
        catch [System.InvalidOperationException] {
            Write-Error -Message $_.Exception.Message -ErrorAction Stop
        }

        if ($null -ne $resolved) {
            [void]$recordUids.Add($resolved.Uid)
        }
        else {
            Write-Output ("Record `"{0}`" not found." -f $Record.Trim())
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($Folder)) {
        $folderName = $Folder.Trim()
        $folderNode = $null
        if (-not $Vault.TryGetFolder($folderName, [ref]$folderNode)) {
            Write-Output ("Folder `"{0}`" not found. Skipping." -f $folderName)
        }
        else {
            $folderUids = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
            $stack = New-Object System.Collections.Generic.Stack[object]
            $stack.Push($folderNode)
            while ($stack.Count -gt 0) {
                $node = $stack.Pop()
                if ($null -eq $node) { continue }
                if (-not [string]::IsNullOrEmpty($node.FolderUid)) {
                    [void]$folderUids.Add($node.FolderUid)
                }
                if ($null -ne $node.Subfolders) {
                    foreach ($subUid in $node.Subfolders) {
                        $child = $null
                        if ($Vault.TryGetFolder($subUid, [ref]$child) -and $null -ne $child) {
                            $stack.Push($child)
                        }
                    }
                }
            }

            foreach ($folderUid in $folderUids) {
                $folder = $null
                if (-not $Vault.TryGetFolder($folderUid, [ref]$folder) -or $null -eq $folder) {
                    continue
                }
                if ($null -eq $folder.Records) { continue }
                foreach ($uid in $folder.Records) {
                    if ($recordUids.Contains($uid)) { continue }
                    $typed = [KeeperSecurity.Plugins.PAM.PamVaultHelpers]::ResolveRecord($Vault, $uid, $rotationTypes)
                    if ($null -ne $typed) {
                        [void]$recordUids.Add($uid)
                    }
                }
            }
        }
    }

    $records = New-Object System.Collections.Generic.List[KeeperSecurity.Vault.TypedRecord]
    foreach ($uid in $recordUids) {
        $rec = [KeeperSecurity.Plugins.PAM.PamVaultHelpers]::ResolveRecord($Vault, $uid, $rotationTypes)
        if ($null -ne $rec) {
            [void]$records.Add($rec)
        }
    }
    return , $records
}

function script:invokeKeeperPamRotationEdit {
    Param (
        [Parameter(Mandatory = $true)]
        [KeeperSecurity.Authentication.IAuthentication] $Auth,
        [Parameter(Mandatory = $true)]
        [KeeperSecurity.Vault.VaultOnline] $Vault,
        [hashtable] $Options
    )

    $Vault.SyncDown().GetAwaiter().GetResult() | Out-Null

    $complexityRules = $null
    if ($null -ne $Options.Complexity -and -not [string]::IsNullOrWhiteSpace([string]$Options.Complexity)) {
        $complexityRules = [KeeperSecurity.Plugins.PAM.RotationUtils]::ParsePasswordComplexityRules([string]$Options.Complexity)
    }
    elseif (-not [string]::IsNullOrWhiteSpace([string]$Options.ComplexityJson)) {
        try {
            $bytes = [System.Text.Encoding]::UTF8.GetBytes([string]$Options.ComplexityJson)
            $complexityRules = [KeeperSecurity.Plugins.PAM.RotationUtils]::ParsePasswordComplexityJson($bytes)
        }
        catch [System.ArgumentException] {
            Write-Error -Message $_.Exception.Message -ErrorAction Stop
        }
    }

    try {
        $scheduleData = [KeeperSecurity.Plugins.PAM.RotationUtils]::ParseScheduleOptions(
            [string]$Options.ScheduleJson,
            [string]$Options.ScheduleCron,
            [bool]$Options.OnDemand,
            [bool]$Options.ScheduleConfig)
        if ($null -ne $scheduleData) {
            $scheduleData = toPamScheduleObjectList $scheduleData
        }
    }
    catch {
        Write-Error -Message $_.Exception.Message -ErrorAction Stop
    }

    $pamConfigs = [KeeperSecurity.Plugins.PAM.PamVaultHelpers]::GetConfigurationRecords($Vault)
    $configRecord = $null
    if (-not [string]::IsNullOrWhiteSpace([string]$Options.Config)) {
        $configRecord = [KeeperSecurity.Plugins.PAM.PamVaultHelpers]::ResolveRecord(
            $Vault, [string]$Options.Config, [KeeperSecurity.Plugins.PAM.PamRecordTypes]::Configuration)
        if ($null -eq $configRecord) {
            Write-Error -Message ("Record uid {0} is not a PAM Configuration record." -f $Options.Config) -ErrorAction Stop
        }
    }

    if (-not [string]::IsNullOrWhiteSpace([string]$Options.RotationProfile)) {
        $allowed = @('general', 'iam_user', 'scripts_only', 'saas')
        $profileCheck = ([string]$Options.RotationProfile).Trim().ToLowerInvariant()
        if ($allowed -notcontains $profileCheck) {
            Write-Error -Message 'Invalid rotation profile. Allowed values: general, iam_user, scripts_only, saas' -ErrorAction Stop
        }
    }

    $records = resolvePamRotationTargetRecords -Vault $Vault -Record ([string]$Options.Record) -Folder ([string]$Options.Folder)
    if ($records.Count -eq 0) {
        $types = [string]::Join(', ', [KeeperSecurity.Plugins.PAM.PamRecordTypes]::Rotation)
        Write-Error -Message ("No PAM record is found. Valid PAM record types: {0}" -f $types) -ErrorAction Stop
    }

    Write-Output ("Selected {0} PAM record(s) for rotation" -f $records.Count)

    $skipped = New-Object System.Collections.Generic.List[object]
    $valid = New-Object System.Collections.Generic.List[object]
    $requests = New-Object System.Collections.Generic.List[Router.RouterRecordRotationRequest]
    $configuredResources = New-Object System.Collections.Generic.List[hashtable]
    $resourceTypes = [KeeperSecurity.Plugins.PAM.PamRecordTypes]::Resource

    foreach ($record in $records) {
        $typeName = [string]$record.TypeName
        if ($resourceTypes.Contains($typeName)) {
            try {
                invokePamConfigureResourceRecord `
                    -Auth $Auth -Vault $Vault -Record $record -Options $Options `
                    -PamConfigs $pamConfigs -ConfigRecord $configRecord `
                    -Skipped $skipped -ConfiguredResources $configuredResources
            }
            catch [System.InvalidOperationException] {
                if (-not [string]::IsNullOrWhiteSpace([string]$Options.Folder)) {
                    [void]$skipped.Add(@($record.Uid, $record.Title, 'Error', $_.Exception.Message))
                }
                else {
                    Write-Error -Message $_.Exception.Message -ErrorAction Stop
                }
            }
            continue
        }

        if ($typeName -ne 'pamUser') {
            continue
        }

        try {
            $editContext = resolvePamRecordEditContext -Options $Options -Record $record
            $resourceUidForDag = $null
            $configUidForDag = if ($null -ne $configRecord) { $configRecord.Uid } else { $null }

            if ($editContext.Profile -ne 'iam_user' -and -not $editContext.Noop -and -not [bool]$Options.ScheduleOnly) {
                $resourceUidForDag = resolvePamResourceUidForDag `
                    -Vault $Vault -Record $record -Options $Options `
                    -ConfigRecord $configRecord -PamConfigs $pamConfigs
                if ([string]::IsNullOrEmpty($configUidForDag)) {
                    $cached = $Vault.GetRecordRotation($record.Uid)
                    $configUidForDag = $cached.ConfigurationUid
                }
            }

            if (-not [string]::IsNullOrEmpty($resourceUidForDag) -and -not [string]::IsNullOrEmpty($configUidForDag)) {
                [KeeperSecurity.Plugins.PAM.PamRotationGraphEdit]::ConfigureUserAsync(
                    $Auth, $Vault, $record, $resourceUidForDag, $configUidForDag,
                    [bool]$editContext.Noop, [bool]$Options.ScheduleOnly
                ).GetAwaiter().GetResult() | Out-Null
                # Graph ACL repair/link can change server rotation revision (Python parity).
                $Vault.SyncDown().GetAwaiter().GetResult() | Out-Null
            }

            $request = $null
            if (tryBuildPamUserRotationRequest `
                    -Vault $Vault -Record $record -Options $Options `
                    -ConfigRecord $configRecord -PamConfigs $pamConfigs `
                    -ScheduleData $scheduleData -ComplexityRules $complexityRules `
                    -EditContext $editContext -Skipped $skipped -Valid $valid `
                    -Request ([ref]$request)) {
                [void]$requests.Add($request)
            }
        }
        catch [System.InvalidOperationException] {
            if (-not [string]::IsNullOrWhiteSpace([string]$Options.Folder)) {
                [void]$skipped.Add(@($record.Uid, $record.Title, 'Error', $_.Exception.Message))
            }
            else {
                Write-Error -Message $_.Exception.Message -ErrorAction Stop
            }
        }
    }

    if ($skipped.Count -gt 0) {
        Write-Output ''
        Write-Output 'The following record(s) were skipped:'
        Write-Output ("{0,-22} {1,-28} {2,-28} {3}" -f 'Record UID', 'Record Title', 'Problem', 'Description')
        foreach ($row in $skipped) {
            Write-Output ("{0,-22} {1,-28} {2,-28} {3}" -f $row[0], $row[1], $row[2], $row[3])
        }
    }

    foreach ($summary in $configuredResources) {
        Write-Output ''
        Write-Output ("Resource `"{0}`" ({1}) configured for PAM rotation." -f $summary.RecordTitle, $summary.RecordUid)
        Write-Output ("  PAM Configuration: {0}" -f $summary.ConfigUid)
        if (-not [string]::IsNullOrEmpty($summary.AdminUserUid)) {
            Write-Output ("  Admin user linked: {0}" -f $summary.AdminUserUid)
        }
        if ($summary.RotationEnabled -eq $true) {
            Write-Output '  Rotation: Enabled'
        }
        elseif ($summary.RotationEnabled -eq $false) {
            Write-Output '  Rotation: Disabled'
        }
    }

    if ($requests.Count -eq 0) {
        return
    }

    if ($skipped.Count -gt 0 -and -not [bool]$Options.Force) {
        if (-not (confirmPamYesNo -Prompt 'Do you want to cancel password rotation?' -DefaultYes $true)) {
            return
        }
    }

    if ($valid.Count -gt 0) {
        Write-Output ''
        Write-Output 'The following record(s) will be updated:'
        Write-Output ("{0,-22} {1,-24} {2,-8} {3,-22} {4,-22} {5,-12} {6}" -f `
            'Record UID', 'Record Title', 'Enabled', 'Configuration UID', 'Resource UID', 'Schedule', 'Complexity')
        foreach ($row in $valid) {
            $enabled = if ($row[2]) { 'X' } else { '-' }
            Write-Output ("{0,-22} {1,-24} {2,-8} {3,-22} {4,-22} {5,-12} {6}" -f `
                $row[0], $row[1], $enabled, $row[3], $row[4], $row[5], $row[6])
        }
    }

    if (-not [bool]$Options.Force) {
        if (-not (confirmPamYesNo -Prompt 'Do you want to update password rotation?' -DefaultYes $true)) {
            return
        }
    }

    $failures = New-Object System.Collections.Generic.List[string]
    foreach ($request in $requests) {
        $recordUid = [KeeperSecurity.Utils.CryptoUtils]::Base64UrlEncode($request.RecordUid.ToByteArray())
        try {
            [KeeperSecurity.Plugins.PAM.RouterUtils]::SetRecordRotationAsync($Auth, $request).GetAwaiter().GetResult() | Out-Null
        }
        catch {
            $message = ("Record `"{0}`": Set rotation error: {1}" -f $recordUid, $_.Exception.Message)
            Write-Output $message
            [void]$failures.Add($message)
        }
    }

    $Vault.SyncDown().GetAwaiter().GetResult() | Out-Null

    if ($failures.Count -gt 0) {
        Write-Error -Message (
            ("{0} of {1} record(s) failed to update rotation:`n{2}" -f `
                $failures.Count, $requests.Count, ([string]::Join([Environment]::NewLine, $failures)))
        ) -ErrorAction Stop
    }
}

function script:resolvePamRecordEditContext {
    Param (
        [hashtable] $Options,
        [KeeperSecurity.Vault.TypedRecord] $Record
    )

    $profile = $null
    if (-not [string]::IsNullOrWhiteSpace([string]$Options.RotationProfile)) {
        $profile = ([string]$Options.RotationProfile).Trim().ToLowerInvariant()
    }
    elseif (-not [string]::IsNullOrWhiteSpace([string]$Options.IamAadConfig)) {
        $profile = 'iam_user'
    }

    $noop = ($profile -eq 'scripts_only') -or (testPamNoopRecord -Record $Record)
    if ($profile -eq 'saas') {
        if ([string]::IsNullOrWhiteSpace([string]$Options.SaasConfigUid)) {
            Write-Error -Message 'SaaS rotation profile requires --saas-config-uid to be specified.' -ErrorAction Stop
        }
        $noop = $true
    }

    return @{ Profile = $profile; Noop = $noop }
}

function script:resolvePamResourceUidForDag {
    Param (
        [KeeperSecurity.Vault.VaultOnline] $Vault,
        [KeeperSecurity.Vault.TypedRecord] $Record,
        [hashtable] $Options,
        [KeeperSecurity.Vault.TypedRecord] $ConfigRecord,
        [System.Collections.Generic.Dictionary[string, KeeperSecurity.Vault.TypedRecord]] $PamConfigs
    )

    if (-not [string]::IsNullOrWhiteSpace([string]$Options.Resource)) {
        $resource = [KeeperSecurity.Plugins.PAM.PamVaultHelpers]::ResolveRecord($Vault, [string]$Options.Resource, $null)
        if ($null -eq $resource) {
            Write-Error -Message ("Resource '{0}' not found" -f $Options.Resource) -ErrorAction Stop
        }
        return $resource.Uid
    }

    $cached = $Vault.GetRecordRotation($Record.Uid)
    if ($null -ne $cached -and -not [string]::IsNullOrEmpty($cached.ResourceUid)) {
        $configUid = if ($null -ne $ConfigRecord) { $ConfigRecord.Uid } else { $cached.ConfigurationUid }
        if (-not [string]::Equals($cached.ResourceUid, $configUid, [System.StringComparison]::Ordinal)) {
            return $cached.ResourceUid
        }
    }

    $configUid = if ($null -ne $ConfigRecord) { $ConfigRecord.Uid } else { $cached.ConfigurationUid }
    if (-not [string]::IsNullOrEmpty($configUid) -and $PamConfigs.ContainsKey($configUid)) {
        return (getPamDefaultResourceUidFromConfig -Config $PamConfigs[$configUid])
    }
    return $null
}

function script:invokePamConfigureResourceRecord {
    Param (
        [KeeperSecurity.Authentication.IAuthentication] $Auth,
        [KeeperSecurity.Vault.VaultOnline] $Vault,
        [KeeperSecurity.Vault.TypedRecord] $Record,
        [hashtable] $Options,
        [System.Collections.Generic.Dictionary[string, KeeperSecurity.Vault.TypedRecord]] $PamConfigs,
        [KeeperSecurity.Vault.TypedRecord] $ConfigRecord,
        [System.Collections.Generic.List[object]] $Skipped,
        [System.Collections.Generic.List[hashtable]] $ConfiguredResources
    )

    $configUid = if ($null -ne $ConfigRecord) { $ConfigRecord.Uid } else { $null }
    if ([string]::IsNullOrEmpty($configUid) -and -not [string]::IsNullOrWhiteSpace([string]$Options.Config)) {
        $resolved = [KeeperSecurity.Plugins.PAM.PamVaultHelpers]::ResolveRecord(
            $Vault, [string]$Options.Config, [KeeperSecurity.Plugins.PAM.PamRecordTypes]::Configuration)
        $configUid = $resolved.Uid
    }

    if ([string]::IsNullOrEmpty($configUid)) {
        [void]$Skipped.Add(@($Record.Uid, $Record.Title, 'No PAM Configuration', 'Specify a configuration UID parameter [--config]'))
        return
    }

    if (-not $PamConfigs.ContainsKey($configUid)) {
        [void]$Skipped.Add(@($Record.Uid, $Record.Title, 'PAM Configuration is invalid', 'Specify a configuration UID parameter [--config]'))
        return
    }

    [KeeperSecurity.Plugins.PAM.PamRotationGraphEdit]::ConfigureResourceAsync(
        $Auth, $Vault, $Record, $configUid, [string]$Options.AdminUser,
        [bool]$Options.Enable, [bool]$Options.Disable
    ).GetAwaiter().GetResult() | Out-Null

    $adminUserUid = $null
    if (-not [string]::IsNullOrWhiteSpace([string]$Options.AdminUser)) {
        $adminUser = [KeeperSecurity.Plugins.PAM.PamVaultHelpers]::ResolveRecord(
            $Vault, ([string]$Options.AdminUser).Trim(), @('pamUser'))
        $adminUserUid = $adminUser.Uid
    }

    $rotationEnabled = [KeeperSecurity.Plugins.PAM.RotationUtils]::ResolveRotationEnabled(
        [bool]$Options.Enable, [bool]$Options.Disable)

    [void]$ConfiguredResources.Add(@{
        RecordUid       = $Record.Uid
        RecordTitle     = $Record.Title
        ConfigUid       = $configUid
        AdminUserUid    = $adminUserUid
        RotationEnabled = $rotationEnabled
    })
}

function script:tryBuildPamUserRotationRequest {
    Param (
        [KeeperSecurity.Vault.VaultOnline] $Vault,
        [KeeperSecurity.Vault.TypedRecord] $Record,
        [hashtable] $Options,
        [KeeperSecurity.Vault.TypedRecord] $ConfigRecord,
        [System.Collections.Generic.Dictionary[string, KeeperSecurity.Vault.TypedRecord]] $PamConfigs,
        $ScheduleData,
        $ComplexityRules,
        [hashtable] $EditContext,
        [System.Collections.Generic.List[object]] $Skipped,
        [System.Collections.Generic.List[object]] $Valid,
        [ref] $Request
    )

    $Request.Value = $null
    $cached = $Vault.GetRecordRotation($Record.Uid)
    $profile = $EditContext.Profile
    $noop = [bool]$EditContext.Noop

    if ([bool]$Options.ScheduleOnly) {
        if (-not [string]::IsNullOrWhiteSpace([string]$Options.Folder) -and ($null -eq $cached -or $cached.Disabled)) {
            [void]$Skipped.Add(@($Record.Uid, $Record.Title, 'Rotation not enabled', 'Skipped'))
            return $false
        }
        if ($null -eq $cached) {
            [void]$Skipped.Add(@($Record.Uid, $Record.Title, 'No rotation info', 'Skipped'))
            return $false
        }
    }

    $configUid = if ($null -ne $ConfigRecord) { $ConfigRecord.Uid } else { $null }
    if ([string]::IsNullOrEmpty($configUid) -and -not [string]::IsNullOrWhiteSpace([string]$Options.IamAadConfig)) {
        $configUid = ([string]$Options.IamAadConfig).Trim()
    }
    if ([string]::IsNullOrEmpty($configUid) -and $profile -eq 'iam_user') {
        if (-not [string]::IsNullOrWhiteSpace([string]$Options.Config)) {
            $configUid = ([string]$Options.Config).Trim()
        }
        else {
            $configUid = $cached.ConfigurationUid
        }
    }
    if ([string]::IsNullOrEmpty($configUid) -and $null -ne $cached -and -not [string]::IsNullOrEmpty($cached.ConfigurationUid)) {
        $configUid = $cached.ConfigurationUid
    }

    if ([string]::IsNullOrEmpty($configUid)) {
        [void]$Skipped.Add(@($Record.Uid, $Record.Title, 'No current PAM Configuration', 'Specify a configuration UID parameter [--config]'))
        return $false
    }

    if (-not $PamConfigs.ContainsKey($configUid)) {
        [void]$Skipped.Add(@($Record.Uid, $Record.Title, 'PAM Configuration is invalid', 'Specify a configuration UID parameter [--config]'))
        return $false
    }

    $pamConfig = $PamConfigs[$configUid]
    $recordSchedule = $null
    if ($null -ne $ScheduleData) {
        $recordSchedule = toPamScheduleObjectList $ScheduleData
    }
    elseif ($null -ne $cached -and -not [bool]$Options.ScheduleConfig -and -not [string]::IsNullOrEmpty($cached.Schedule)) {
        try {
            $recordSchedule = toPamScheduleObjectList (
                [KeeperSecurity.Plugins.PAM.RotationUtils]::ParseScheduleJsonString($cached.Schedule))
        }
        catch {
            $recordSchedule = New-Object 'System.Collections.Generic.List[object]'
        }
    }
    elseif ([bool]$Options.ScheduleConfig) {
        # Missing/empty defaultRotationSchedule => On-Demand (Commander/Python parity).
        $fromConfig = getPamDefaultScheduleFromConfig -Config $pamConfig
        $recordSchedule = if ($null -eq $fromConfig) {
            New-Object 'System.Collections.Generic.List[object]'
        }
        else {
            toPamScheduleObjectList $fromConfig
        }
    }

    $pwdComplexity = [byte[]]@()
    if ($null -ne $ComplexityRules) {
        if ([KeeperSecurity.Plugins.PAM.RotationUtils]::IsClearedPasswordComplexity($ComplexityRules)) {
            $pwdComplexity = [byte[]]@()
        }
        else {
            $pwdComplexity = [KeeperSecurity.Plugins.PAM.RotationUtils]::EncryptPasswordComplexity($ComplexityRules, $Record.RecordKey)
        }
    }
    elseif ($null -ne $cached -and $null -ne $cached.PwdComplexity) {
        $pwdComplexity = $cached.PwdComplexity
    }

    $disabled = if ($null -ne $cached) { [bool]$cached.Disabled } else { $false }
    if ([bool]$Options.Enable) { $disabled = $false }
    elseif ([bool]$Options.Disable) { $disabled = $true }

    $resourceUid = $null
    if ($profile -eq 'iam_user' -or -not [string]::IsNullOrWhiteSpace([string]$Options.IamAadConfig)) {
        $resourceUid = $null
        $noop = $false
    }
    elseif ($profile -eq 'saas') {
        $resourceUid = $null
        $noop = $true
    }
    elseif ($noop) {
        $resourceUid = $null
    }
    elseif (-not [string]::IsNullOrWhiteSpace([string]$Options.Resource)) {
        $resource = [KeeperSecurity.Plugins.PAM.PamVaultHelpers]::ResolveRecord($Vault, [string]$Options.Resource, $null)
        if ($null -eq $resource) {
            Write-Error -Message ("Resource '{0}' not found" -f $Options.Resource) -ErrorAction Stop
        }
        $resourceUid = $resource.Uid
    }
    elseif ($profile -eq 'general' -and [string]::IsNullOrWhiteSpace([string]$Options.Resource)) {
        Write-Error -Message 'General rotation profile requires --resource to be specified.' -ErrorAction Stop
    }
    elseif ($null -ne $cached -and -not [string]::IsNullOrEmpty($cached.ResourceUid) -and
            -not [string]::Equals($cached.ResourceUid, $configUid, [System.StringComparison]::Ordinal)) {
        $resourceUid = $cached.ResourceUid
    }
    elseif (-not [bool]$Options.ScheduleOnly) {
        $resourceUid = getPamDefaultResourceUidFromConfig -Config $pamConfig
        if ([string]::IsNullOrEmpty($resourceUid) -and -not $noop) {
            Write-Error -Message (
                ("Record `"{0}`" is not associated with any resource. Please use Set-KeeperPamRotation -Record RECORD -Resource RESOURCE to associate it." -f $Record.Uid)
            ) -ErrorAction Stop
        }
    }

    if (-not [string]::IsNullOrEmpty($resourceUid) -and
        [string]::Equals($resourceUid, $configUid, [System.StringComparison]::Ordinal)) {
        $resourceUid = $null
    }

    $recordScheduleList = toPamScheduleObjectList $recordSchedule
    $scheduleType = [KeeperSecurity.Plugins.PAM.RotationUtils]::GetScheduleType($recordScheduleList)
    $complexityDisplay = ''
    $decoded = $null
    if (-not [KeeperSecurity.Plugins.PAM.RotationUtils]::TryDecryptPasswordComplexity($pwdComplexity, $Record.RecordKey, [ref]$decoded)) {
        $complexityDisplay = '[decrypt failed]'
    }
    else {
        $complexityDisplay = [KeeperSecurity.Plugins.PAM.RotationUtils]::FormatPasswordComplexityDisplay($decoded)
    }

    [void]$Valid.Add(@(
        $Record.Uid,
        $Record.Title,
        (-not $disabled),
        $configUid,
        $(if ($null -eq $resourceUid) { '' } else { $resourceUid }),
        $scheduleType,
        $complexityDisplay
    ))

    $rq = New-Object Router.RouterRecordRotationRequest
    $rq.RecordUid = [Google.Protobuf.ByteString]::CopyFrom((toPamUidBytes -Uid $Record.Uid))
    $rq.ConfigurationUid = [Google.Protobuf.ByteString]::CopyFrom((toPamUidBytes -Uid $configUid))
    $rq.Schedule = [KeeperSecurity.Plugins.PAM.RotationUtils]::BuildSchedulePayload(
        [string]$Options.ScheduleJson, [bool]$Options.OnDemand, $recordScheduleList)
    $rq.PwdComplexity = [Google.Protobuf.ByteString]::CopyFrom($pwdComplexity)
    $rq.Disabled = $disabled
    $rq.Noop = $noop
    $rq.Revision = if ($null -ne $cached) { [long]$cached.Revision } else { [long]0 }

    if (-not $noop -and -not [string]::IsNullOrEmpty($resourceUid)) {
        $rq.ResourceUid = [Google.Protobuf.ByteString]::CopyFrom((toPamUidBytes -Uid $resourceUid))
    }

    if ($profile -eq 'saas' -and -not [string]::IsNullOrWhiteSpace([string]$Options.SaasConfigUid)) {
        $rq.SaasConfiguration = [Google.Protobuf.ByteString]::CopyFrom(
            (toPamUidBytes -Uid (([string]$Options.SaasConfigUid).Trim())))
    }

    $Request.Value = $rq
    return $true
}

# --- PAM config helpers ---

function script:getPamEnterpriseAuth {
    $enterprise = getEnterprise
    if (-not $enterprise -or -not $enterprise.loader -or -not $enterprise.loader.Auth) {
        Write-Error -Message 'Enterprise authentication is not available.' -ErrorAction Stop
    }

    return $enterprise.loader.Auth
}

function script:getPamVault {
    $vault = getVault
    if (-not $vault) {
        Write-Error -Message 'Vault is not available.' -ErrorAction Stop
    }

    return $vault
}

function script:resolvePamGatewayController {
    Param (
        [Parameter(Mandatory = $true)]
        [KeeperSecurity.Plugins.PAM.IPamPlugin] $Plugin,
        [Parameter(Mandatory = $true)]
        [string] $Identifier,
        [KeeperSecurity.Vault.VaultOnline] $Vault = $null
    )

    $trimmed = $Identifier.Trim()
    if ([string]::IsNullOrWhiteSpace($trimmed)) {
        return $null
    }

    # Help catch sheet mistakes where SharedFolder UID is passed as -Gateway.
    if ($null -ne $Vault) {
        [KeeperSecurity.Vault.SharedFolder]$sf = $null
        if ($Vault.TryGetSharedFolder($trimmed, [ref]$sf) -and $null -ne $sf) {
            Write-Host ("Gateway `"$trimmed`" matches shared folder `"$($sf.Name)`". " +
                'Use a gateway/controller UID or name, not the shared-folder UID.')
            return $null
        }
    }

    $controllers = getPamControllerList -Plugin $Plugin
    if ($controllers -is [object[]] -and $controllers.Length -eq 1 -and
        $controllers[0] -is [System.Collections.Generic.List[KeeperSecurity.Plugins.PAM.PamController]]) {
        $controllers = $controllers[0]
    }
    if ($null -eq $controllers) {
        $controllers = New-Object 'System.Collections.Generic.List[KeeperSecurity.Plugins.PAM.PamController]'
    }

    $controllerCount = 0
    try { $controllerCount = [int]$controllers.Count } catch { $controllerCount = 0 }
    if ($controllerCount -eq 0) {
        # Controllers empty after failed sync — retry once before giving up.
        [void](syncPamPlugin -Plugin $Plugin -Reload $true -ThrowOnError $false)
        $controllers = getPamControllerList -Plugin $Plugin
        if ($controllers -is [object[]] -and $controllers.Length -eq 1 -and
            $controllers[0] -is [System.Collections.Generic.List[KeeperSecurity.Plugins.PAM.PamController]]) {
            $controllers = $controllers[0]
        }
    }

    $controller = [KeeperSecurity.Plugins.PAM.GatewayUtils]::FindGateway($controllers, $trimmed)
    if ($controller -is [KeeperSecurity.Plugins.PAM.PamController]) {
        return $controller
    }

    $nameMatches = 0
    $nameMatch = $null
    foreach ($item in $controllers) {
        if ($item -is [KeeperSecurity.Plugins.PAM.PamController] -and
            [string]::Equals($item.ControllerName, $trimmed, [System.StringComparison]::OrdinalIgnoreCase)) {
            $nameMatches++
            $nameMatch = $item
        }
    }
    if ($nameMatches -gt 1) {
        throw (New-Object KeeperSecurity.Plugins.PAM.PamGatewayAmbiguousException($trimmed))
    }
    if ($nameMatches -eq 1) {
        return $nameMatch
    }

    return $null
}

function script:resolvePamConfigurationFolderUid {
    Param (
        [Parameter(Mandatory = $true)]
        [KeeperSecurity.Vault.VaultOnline] $Vault,
        [Parameter(Mandatory = $true)]
        [string] $Identifier
    )

    if ([string]::IsNullOrWhiteSpace($Identifier)) {
        return $null
    }

    $trimmed = $Identifier.Trim()
    $folderResolver = {
        param([string]$path)
        try {
            $ops = New-Object KeeperSecurity.Vault.BatchVaultOperations($Vault)
            return $ops.GetFolderByPath($path)
        }
        catch {
            return $null
        }
    }

    return [KeeperSecurity.Plugins.PAM.PamVaultHelpers]::ResolvePamConfigurationFolderUid(
        $Vault, $trimmed, $folderResolver)
}

function script:writePamComingSoonMessage {
    Param (
        [string] $Environment
    )

    if ([string]::IsNullOrWhiteSpace($Environment)) {
        return $false
    }

    $displayName = $null
    try {
        if ([KeeperSecurity.Plugins.PAM.PamConfigTypes]::IsComingSoonEnvironment($Environment.Trim(), [ref]$displayName)) {
            if ([string]::IsNullOrWhiteSpace($displayName)) {
                $displayName = $Environment.Trim()
            }
            Write-Host "Environment $displayName is not supported yet. It will be supported in a future release."
            return $true
        }
    }
    catch {}

    return $false
}
