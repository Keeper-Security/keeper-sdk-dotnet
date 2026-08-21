#requires -Version 5.1

function script:getPamRotationScheduleRows {
    Param (
        [Parameter(Mandatory = $true)]
        [KeeperSecurity.Plugins.PAM.IPamPlugin] $Plugin,
        [Parameter(Mandatory = $true)]
        [KeeperSecurity.Vault.VaultOnline] $Vault,
        [Parameter(Mandatory = $true)]
        [KeeperSecurity.Authentication.IAuthentication] $Auth,
        [bool] $VerboseOutput
    )

    $schedulesResponse = [KeeperSecurity.Plugins.PAM.RouterUtils]::GetRotationSchedulesAsync($Auth).GetAwaiter().GetResult()
    $schedules = @()
    if ($null -ne $schedulesResponse -and $null -ne $schedulesResponse.Schedules) {
        $schedules = @($schedulesResponse.Schedules)
    }

    $configs = [KeeperSecurity.Plugins.PAM.PamVaultHelpers]::GetConfigurationRecords($Vault)
    $rows = New-Object 'System.Collections.Generic.List[object]'

    $prepared = New-Object 'System.Collections.Generic.List[object]'
    foreach ($schedule in $schedules) {
        $recordUid = encodePamByteString $schedule.RecordUid
        if ([string]::IsNullOrEmpty($recordUid)) {
            continue
        }

        $record = $null
        if (-not [KeeperSecurity.Plugins.PAM.PamVaultHelpers]::TryGetUserRecord($Vault, $recordUid, [ref]$record)) {
            continue
        }

        $sortTitle = if ($record.Title) { $record.Title } else { $recordUid }
        $prepared.Add(@{
                Schedule  = $schedule
                Record    = $record
                RecordUid = $recordUid
                SortTitle = $sortTitle
            })
    }

    foreach ($item in ($prepared | Sort-Object { $_.SortTitle })) {
        $schedule = $item.Schedule
        $record = $item.Record
        $recordUid = $item.RecordUid

        $controllerUid = encodePamByteString $schedule.ControllerUid
        $configUid = encodePamByteString $schedule.ConfigurationUid
        $configRecord = $null
        if (-not [string]::IsNullOrEmpty($configUid) -and $configs.ContainsKey($configUid)) {
            $configRecord = $configs[$configUid]
        }

        $scheduleText = [KeeperSecurity.Plugins.PAM.RotationUtils]::FormatScheduleDisplay($schedule.ScheduleData, $schedule.NoSchedule)
        $gatewayName = resolvePamRotationGatewayName -Plugin $Plugin -GatewayUid $controllerUid -FallbackName $null
        $configText = if ($configRecord) {
            "$($configRecord.Title) ($($configRecord.TypeName))"
        }
        else {
            '[No config found]'
        }

        if ($VerboseOutput) {
            $rows.Add(@{
                    RecordUid           = $recordUid
                    RecordTitle         = $record.Title
                    RecordType          = $record.TypeName
                    Schedule            = $scheduleText
                    Gateway             = $gatewayName
                    GatewayUid          = $controllerUid
                    PamConfiguration    = $configText
                    PamConfigurationUid = $configUid
                })
        }
        else {
            $rows.Add(@{
                    RecordUid        = $recordUid
                    RecordTitle      = $record.Title
                    RecordType       = $record.TypeName
                    Schedule         = $scheduleText
                    Gateway          = $gatewayName
                    PamConfiguration = $configText
                })
        }
    }

    return $rows.ToArray()
}

function script:writePamRotationListTable {
    Param (
        $Rows,
        [bool] $VerboseOutput = $false
    )

    $rowArray = @($Rows)
    if ($rowArray.Count -eq 0) {
        return
    }

    if ($VerboseOutput) {
        $table = $rowArray | Select-Object `
            @{ Name = 'Record UID'; Expression = { $_.RecordUid } }, `
            @{ Name = 'Record Title'; Expression = { $_.RecordTitle } }, `
            @{ Name = 'Record Type'; Expression = { $_.RecordType } }, `
            @{ Name = 'Schedule'; Expression = { $_.Schedule } }, `
            @{ Name = 'Gateway'; Expression = { $_.Gateway } }, `
            @{ Name = 'Gateway UID'; Expression = { $_.GatewayUid } }, `
            @{ Name = 'PAM Configuration (Type)'; Expression = { $_.PamConfiguration } }, `
            @{ Name = 'PAM Configuration UID'; Expression = { $_.PamConfigurationUid } } |
            Format-Table -AutoSize | Out-String -Width 4096
    }
    else {
        $table = $rowArray | Select-Object `
            @{ Name = 'Record UID'; Expression = { $_.RecordUid } }, `
            @{ Name = 'Record Title'; Expression = { $_.RecordTitle } }, `
            @{ Name = 'Record Type'; Expression = { $_.RecordType } }, `
            @{ Name = 'Schedule'; Expression = { $_.Schedule } }, `
            @{ Name = 'Gateway'; Expression = { $_.Gateway } }, `
            @{ Name = 'PAM Configuration (Type)'; Expression = { $_.PamConfiguration } } |
            Format-Table -AutoSize | Out-String -Width 4096
    }

    if (-not [string]::IsNullOrWhiteSpace($table)) {
        Write-Output $table.TrimEnd()
    }
}

function script:resolvePamRotationGatewayName {
    Param (
        [object] $Plugin,
        [string] $GatewayUid,
        [string] $FallbackName
    )

    if (-not [string]::IsNullOrWhiteSpace($GatewayUid) -and $GatewayUid -ne '-' -and $Plugin) {
        $controller = $null
        try {
            $controller = $Plugin.Controllers.GetEntity($GatewayUid)
        }
        catch {
            $controller = $null
        }

        if (-not $controller) {
            foreach ($item in $Plugin.Controllers.GetAll()) {
                if ($item -and [string]::Equals($item.ControllerUid, $GatewayUid, [StringComparison]::Ordinal)) {
                    $controller = $item
                    break
                }
            }
        }

        if ($controller -and -not [string]::IsNullOrWhiteSpace($controller.ControllerName)) {
            return $controller.ControllerName
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($FallbackName)) {
        return $FallbackName
    }

    if (-not [string]::IsNullOrWhiteSpace($GatewayUid) -and $GatewayUid -ne '-') {
        return $GatewayUid
    }

    return '-'
}

function script:convertPamRotationComplexityDetailToHashtable {
    Param (
        [object] $Detail
    )

    if ($null -eq $Detail) {
        return $null
    }

    if ($Detail -is [string]) {
        return $Detail
    }

    if ($Detail -isnot [System.Collections.IDictionary]) {
        return $Detail
    }

    $ht = [ordered]@{}
    foreach ($key in $Detail.Keys) {
        $ht[[string]$key] = $Detail[$key]
    }
    return $ht
}

function script:getPamRotationInfoModel {
    Param (
        [Parameter(Mandatory = $true)]
        [object] $RotationInfo,
        [Parameter(Mandatory = $true)]
        [KeeperSecurity.Vault.TypedRecord] $Record,
        [object] $Schedule,
        [object] $Plugin = $null,
        [KeeperSecurity.Vault.VaultOnline] $Vault = $null
    )

    $statusName = [string]$RotationInfo.Status
    $isReady = ($RotationInfo.Status.ToString() -eq 'RrsOnline')
    $configUid = encodePamByteString $RotationInfo.ConfigurationUid
    $gatewayUid = encodePamByteString $RotationInfo.ControllerUid
    if ([string]::IsNullOrEmpty($gatewayUid)) { $gatewayUid = '-' }
    $gatewayName = resolvePamRotationGatewayName -Plugin $Plugin -GatewayUid $gatewayUid -FallbackName $RotationInfo.ControllerName
    $adminResourceUid = encodePamByteString $RotationInfo.ResourceUid
    if ([string]::IsNullOrEmpty($adminResourceUid)) { $adminResourceUid = $null }

    $pwdComplexityRaw = $null
    if (-not [string]::IsNullOrEmpty($RotationInfo.PwdComplexity)) {
        $pwdComplexityRaw = [KeeperSecurity.Utils.CryptoUtils]::Base64UrlDecode($RotationInfo.PwdComplexity)
    }
    $pwdComplexityDetail = $null
    $pwdComplexityDecryptFailed = $false
    if ($pwdComplexityRaw -and $pwdComplexityRaw.Length -gt 0) {
        $pwdComplexityDecryptFailed = -not [KeeperSecurity.Plugins.PAM.RotationUtils]::TryDecryptPasswordComplexity(
            $pwdComplexityRaw, $Record.RecordKey, [ref]$pwdComplexityDetail)
    }

    $scheduleType = $null
    $scheduleData = $null
    $scheduleText = $null
    if ($Schedule) {
        $scheduleType = if ($Schedule.NoSchedule) { 'manual' } else { 'scheduled' }
        $scheduleData = $Schedule.ScheduleData
        $scheduleText = if ($Schedule.NoSchedule) {
            'Manual Rotation'
        }
        else {
            [KeeperSecurity.Plugins.PAM.RotationUtils]::FormatScheduleDisplay($Schedule.ScheduleData, $false)
        }
    }

    $complexityDetailOut = $null
    $complexityDisplay = $null
    if ($pwdComplexityDecryptFailed) {
        $complexityDetailOut = '[decrypt failed]'
        $complexityDisplay = '[decrypt failed]'
    }
    elseif ($null -ne $pwdComplexityDetail) {
        $complexityDetailOut = convertPamRotationComplexityDetailToHashtable (
            [KeeperSecurity.Plugins.PAM.RotationUtils]::PasswordComplexityToDetail($pwdComplexityDetail))
        $complexityDisplay = formatPamPasswordComplexityInfoDisplay -Rules $pwdComplexityDetail
    }

    $hasComplexity = ($pwdComplexityRaw -and $pwdComplexityRaw.Length -gt 0)

    $scriptName = $null
    if (-not [string]::IsNullOrWhiteSpace($RotationInfo.ScriptName)) {
        $scriptName = [string]$RotationInfo.ScriptName
    }

    $useDefaultSchedule = $false
    if ($null -ne $Vault -and -not [string]::IsNullOrWhiteSpace($configUid)) {
        $useDefaultSchedule = testPamUsesDefaultRotationSchedule -Vault $Vault -RecordUid $Record.Uid -ConfigUid $configUid
    }

    return @{
        StatusName                 = $statusName
        IsReady                    = $isReady
        ConfigUid                  = $configUid
        NodeId                     = $RotationInfo.NodeId
        GatewayName                = $gatewayName
        GatewayUid                 = $gatewayUid
        AdminResourceUid           = $adminResourceUid
        HasComplexity              = $hasComplexity
        PasswordComplexity         = if ($hasComplexity) { $RotationInfo.PwdComplexity } else { $null }
        ComplexityDetail           = $complexityDetailOut
        ComplexityDisplay          = $complexityDisplay
        ScheduleType               = $scheduleType
        ScheduleData               = $scheduleData
        ScheduleText               = $scheduleText
        UseDefaultRotationSchedule = $useDefaultSchedule
        Disabled                   = $RotationInfo.Disabled
        ScriptName                 = $scriptName
    }
}

function script:writePamRotationInfoTable {
    Param (
        [Parameter(Mandatory = $true)]
        [object] $Model
    )

    if ($Model.IsReady) {
        Write-Output "Rotation Status: Ready to rotate ($($Model.StatusName))"
        Write-Output "PAM Config UID: $($Model.ConfigUid)"
        Write-Output "Node ID: $($Model.NodeId)"
        Write-Output "Gateway Name: $($Model.GatewayName)"
        Write-Output "Gateway UID: $($Model.GatewayUid)"

        if ($Model.AdminResourceUid) {
            Write-Output "Admin Resource Uid: $($Model.AdminResourceUid)"
        }

        if ($Model.HasComplexity) {
            Write-Output "Password Complexity: $($Model.PasswordComplexity)"
            if (-not [string]::IsNullOrEmpty($Model.ComplexityDisplay)) {
                Write-Output "Password Complexity Data: $($Model.ComplexityDisplay)"
            }
        }
        else {
            Write-Output 'Password Complexity: [not set]'
        }

        Write-Output "Is Rotation Disabled: $($Model.Disabled)"

        if (-not [string]::IsNullOrEmpty($Model.ScheduleText)) {
            Write-Output "Schedule: $($Model.ScheduleText)"
        }

        Write-Output ''
        Write-Output 'Manual rotation is not supported yet. Coming soon.'
    }
    else {
        Write-Output "Rotation Status: Not ready to rotate ($($Model.StatusName))"
    }
}

function script:writePamRotationInfoJson {
    Param (
        [Parameter(Mandatory = $true)]
        [object] $Model
    )

    $result = [ordered]@{
        status                         = $Model.StatusName
        ready_to_rotate                = $Model.IsReady
        pam_config_uid                 = $Model.ConfigUid
        node_id                        = $Model.NodeId
        gateway_name                   = $Model.GatewayName
        gateway_uid                    = $Model.GatewayUid
        admin_resource_uid             = $Model.AdminResourceUid
        password_complexity            = $Model.PasswordComplexity
        password_complexity_detail     = $Model.ComplexityDetail
        schedule_type                  = $Model.ScheduleType
        schedule_data                  = $Model.ScheduleData
        use_default_rotation_schedule  = [bool]$Model.UseDefaultRotationSchedule
        disabled                       = $Model.Disabled
        script_name                    = $Model.ScriptName
    }

    Write-Output ($result | ConvertTo-Json -Depth 8)
}

function script:escapePamCsvField {
    Param ([object] $Value)

    if ($null -eq $Value) {
        return ''
    }

    $text = $null
    if (($Value -is [System.Collections.IDictionary]) -or
        (($Value -is [System.Collections.IEnumerable]) -and -not ($Value -is [string]))) {
        $text = ($Value | ConvertTo-Json -Compress -Depth 8)
    }
    else {
        $text = [string]$Value
    }

    if ($text -match '[,"\r\n]') {
        return '"' + ($text.Replace('"', '""')) + '"'
    }
    return $text
}

function script:writePamRotationInfoCsv {
    Param (
        [Parameter(Mandatory = $true)]
        [object] $Model
    )

    $headers = @(
        'status', 'ready_to_rotate', 'pam_config_uid', 'node_id', 'gateway_name', 'gateway_uid',
        'admin_resource_uid', 'password_complexity', 'password_complexity_detail', 'schedule_type',
        'schedule_data', 'use_default_rotation_schedule', 'disabled', 'script_name'
    )
    $values = @(
        $Model.StatusName
        $Model.IsReady
        $Model.ConfigUid
        $Model.NodeId
        $Model.GatewayName
        $Model.GatewayUid
        $Model.AdminResourceUid
        $Model.PasswordComplexity
        $Model.ComplexityDetail
        $Model.ScheduleType
        $Model.ScheduleData
        $Model.UseDefaultRotationSchedule
        $Model.Disabled
        $Model.ScriptName
    )

    Write-Output ($headers -join ',')
    Write-Output (($values | ForEach-Object { escapePamCsvField $_ }) -join ',')
}

function script:testPamRotationScriptField {
    Param (
        [Parameter(Mandatory = $true)]
        [KeeperSecurity.Vault.TypedField[KeeperSecurity.Vault.FieldScript]] $Field
    )

    return ($Field.FieldName -eq 'script' -or $Field.FieldLabel -eq 'rotationScripts')
}

function script:getPamRotationScriptFields {
    Param (
        [Parameter(Mandatory = $true)]
        [KeeperSecurity.Vault.TypedRecord] $Record
    )

    $fields = New-Object 'System.Collections.Generic.List[KeeperSecurity.Vault.TypedField[KeeperSecurity.Vault.FieldScript]]'
    foreach ($field in $Record.Fields) {
        if ($field -is [KeeperSecurity.Vault.TypedField[KeeperSecurity.Vault.FieldScript]]) {
            $scriptField = [KeeperSecurity.Vault.TypedField[KeeperSecurity.Vault.FieldScript]]$field
            if (testPamRotationScriptField -Field $scriptField) {
                [void]$fields.Add($scriptField)
            }
        }
    }

    return , $fields
}

function script:getPamRotationScriptField {
    Param (
        [Parameter(Mandatory = $true)]
        [KeeperSecurity.Vault.TypedRecord] $Record
    )

    foreach ($field in $Record.Fields) {
        if ($field -is [KeeperSecurity.Vault.TypedField[KeeperSecurity.Vault.FieldScript]]) {
            $scriptField = [KeeperSecurity.Vault.TypedField[KeeperSecurity.Vault.FieldScript]]$field
            if (testPamRotationScriptField -Field $scriptField) {
                return $scriptField
            }
        }
    }

    return $null
}

function script:getOrCreatePamRotationScriptField {
    Param (
        [Parameter(Mandatory = $true)]
        [KeeperSecurity.Vault.TypedRecord] $Record
    )

    $scriptField = getPamRotationScriptField -Record $Record
    if ($scriptField) {
        return $scriptField
    }

    $scriptField = New-Object KeeperSecurity.Vault.TypedField[KeeperSecurity.Vault.FieldScript]('script', 'rotationScripts')
    $Record.Fields.Add($scriptField)
    return $scriptField
}

function script:getPamRotationFileRefUids {
    Param (
        [Parameter(Mandatory = $true)]
        [KeeperSecurity.Vault.TypedRecord] $Record
    )

    $facade = New-Object KeeperSecurity.Vault.TypedRecordFacade[KeeperSecurity.Vault.TypedRecordFileRef]($Record)
    $uids = New-Object 'System.Collections.Generic.HashSet[string]'
    if ($null -ne $facade.Fields.FileRef) {
        foreach ($uid in $facade.Fields.FileRef.Values) {
            if (-not [string]::IsNullOrEmpty($uid)) {
                [void]$uids.Add($uid)
            }
        }
    }

    return , $uids
}

function script:resolvePamRotationCredentialUids {
    Param (
        [Parameter(Mandatory = $true)]
        [KeeperSecurity.Vault.VaultOnline] $Vault,
        [string[]] $Credentials
    )

    $refs = New-Object 'System.Collections.Generic.List[string]'
    if (-not $Credentials) {
        return [string[]]@()
    }

    foreach ($credential in $Credentials) {
        if ([string]::IsNullOrWhiteSpace($credential)) {
            continue
        }

        $keeperRecord = $null
        if ($Vault.TryGetKeeperRecord($credential.Trim(), [ref]$keeperRecord)) {
            [void]$refs.Add($keeperRecord.Uid)
        }
    }

    return (toPamStringArray -Collection $refs)
}

function script:toPamStringArray {
    Param ($Collection)

    if ($null -eq $Collection) {
        return [string[]]@()
    }

    return [string[]]@($Collection)
}

function script:getPamScriptLeafName {
    Param ([string] $Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return ''
    }

    $trimmed = $Value.Trim().Trim('"').Trim("'")
    $normalized = $trimmed.Replace('/', [System.IO.Path]::DirectorySeparatorChar).Replace('\', [System.IO.Path]::DirectorySeparatorChar)
    try {
        $leaf = [System.IO.Path]::GetFileName($normalized)
        if (-not [string]::IsNullOrWhiteSpace($leaf)) {
            return $leaf
        }
    }
    catch {
    }

    return $trimmed
}

function script:findPamRotationScriptValue {
    Param (
        [Parameter(Mandatory = $true)]
        [KeeperSecurity.Vault.VaultOnline] $Vault,
        [Parameter(Mandatory = $true)]
        [KeeperSecurity.Vault.TypedRecord] $Record,
        [Parameter(Mandatory = $true)]
        [string] $ScriptName
    )

    $scriptField = getPamRotationScriptField -Record $Record
    if (-not $scriptField) {
        return $null, $null
    }

    $input = $ScriptName.Trim().Trim('"').Trim("'")
    $leaf = getPamScriptLeafName -Value $input
    $needles = New-Object 'System.Collections.Generic.List[string]'
    [void]$needles.Add($input)
    if (-not [string]::IsNullOrWhiteSpace($leaf) -and -not [string]::Equals($leaf, $input, [System.StringComparison]::OrdinalIgnoreCase)) {
        [void]$needles.Add($leaf)
    }

    foreach ($scriptValue in $scriptField.Values) {
        if ($null -eq $scriptValue -or [string]::IsNullOrEmpty($scriptValue.FileRef)) {
            continue
        }

        foreach ($needle in $needles) {
            if ([string]::Equals($scriptValue.FileRef, $needle, [System.StringComparison]::OrdinalIgnoreCase)) {
                return $scriptValue, $scriptField
            }
        }

        $keeperRecord = $null
        if (-not $Vault.TryGetKeeperRecord($scriptValue.FileRef, [ref]$keeperRecord) -or $null -eq $keeperRecord) {
            continue
        }

        $names = New-Object 'System.Collections.Generic.List[string]'
        if (-not [string]::IsNullOrEmpty($keeperRecord.Uid)) { [void]$names.Add($keeperRecord.Uid) }
        if (-not [string]::IsNullOrEmpty($keeperRecord.Title)) { [void]$names.Add($keeperRecord.Title) }
        $fileRecord = $keeperRecord -as [KeeperSecurity.Vault.FileRecord]
        if ($fileRecord -and -not [string]::IsNullOrEmpty($fileRecord.Name)) {
            [void]$names.Add($fileRecord.Name)
        }

        foreach ($name in $names) {
            foreach ($needle in $needles) {
                if ([string]::Equals($name, $needle, [System.StringComparison]::OrdinalIgnoreCase)) {
                    return $scriptValue, $scriptField
                }
            }
        }
    }

    return $null, $scriptField
}

function script:testPamRotationScriptRecord {
    Param (
        [Parameter(Mandatory = $true)]
        [KeeperSecurity.Vault.TypedRecord] $Record
    )

    $typeName = if ($Record.TypeName) { $Record.TypeName } else { '' }
    return [KeeperSecurity.Plugins.PAM.PamRecordTypes]::Script.Contains($typeName)
}

function script:testPamRotationRecordPattern {
    Param (
        [Parameter(Mandatory = $true)]
        [KeeperSecurity.Vault.KeeperRecord] $Record,
        [string] $Pattern
    )

    if ([string]::IsNullOrEmpty($Pattern)) {
        return $true
    }

    if ([string]::Equals($Record.Uid, $Pattern, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $true
    }

    return ($null -ne $Record.Title -and $Record.Title.IndexOf($Pattern, [System.StringComparison]::OrdinalIgnoreCase) -ge 0)
}

function script:getPamRotationRunCommand {
    Param (
        [string] $RunCommand,
        [string] $ScriptCommand
    )

    if (-not [string]::IsNullOrWhiteSpace($RunCommand)) {
        return $RunCommand.Trim()
    }

    if (-not [string]::IsNullOrWhiteSpace($ScriptCommand)) {
        $trimmed = $ScriptCommand.Trim()
        if (-not (testPamRotationScriptVerb -Value $trimmed)) {
            return $trimmed
        }
    }

    return ''
}

function script:resolvePamRotationScriptRecordId {
    Param (
        [string] $Record,
        [string] $RecordUid
    )

    if (-not [string]::IsNullOrWhiteSpace($Record)) {
        return $Record.Trim()
    }

    if (-not [string]::IsNullOrWhiteSpace($RecordUid)) {
        return $RecordUid.Trim()
    }

    return $null
}

function script:writePamRotationScriptTable {
    Param (
        $Rows
    )

    if ($null -eq $Rows) {
        return
    }
    if ($Rows -is [System.Array]) {
        $rowArray = $Rows
    }
    elseif ($Rows.PSObject.Methods['ToArray']) {
        $rowArray = $Rows.ToArray()
    }
    else {
        $rowArray = [object[]]::new(0)
        foreach ($row in $Rows) {
            $rowArray += $row
        }
    }

    if ($rowArray.Count -eq 0) {
        return
    }

    $table = $rowArray | Select-Object `
        @{ Name = 'Record UID'; Expression = { $_.RecordUid } }, `
        @{ Name = 'Title'; Expression = { $_.Title } }, `
        @{ Name = 'Record Type'; Expression = { $_.RecordType } }, `
        @{ Name = 'Script UID'; Expression = { $_.ScriptUid } }, `
        @{ Name = 'Script Name'; Expression = { $_.ScriptName } }, `
        @{ Name = 'Records'; Expression = { $_.Records } }, `
        @{ Name = 'Command'; Expression = { $_.Command } } |
        Format-Table -AutoSize | Out-String -Width 4096

    if (-not [string]::IsNullOrWhiteSpace($table)) {
        Write-Output $table.TrimEnd()
    }
}

function script:getPamRotationScriptListRows {
    Param (
        [Parameter(Mandatory = $true)]
        [KeeperSecurity.Vault.VaultOnline] $Vault,
        [string] $Pattern
    )

    $rows = New-Object 'System.Collections.Generic.List[object]'
    foreach ($record in @($Vault.KeeperRecords)) {
        $typed = $record -as [KeeperSecurity.Vault.TypedRecord]
        if (-not $typed -or -not (testPamRotationScriptRecord -Record $typed)) {
            continue
        }

        if (-not (testPamRotationRecordPattern -Record $typed -Pattern $Pattern)) {
            continue
        }

        foreach ($scriptField in (getPamRotationScriptFields -Record $typed)) {
            foreach ($script in $scriptField.Values) {
                if ([string]::IsNullOrEmpty($script.FileRef)) {
                    continue
                }

                $fileRecord = $null
                $vault.TryGetKeeperRecord($script.FileRef, [ref]$fileRecord) | Out-Null
                $recordRefs = if ($script.RecordRef) { ($script.RecordRef -join ', ') } else { '' }
                $scriptName = if ($fileRecord) { $fileRecord.Title } else { '[inaccessible]' }

                $rows.Add(@{
                        RecordUid  = $typed.Uid
                        Title      = $typed.Title
                        RecordType = $typed.TypeName
                        ScriptUid  = $script.FileRef
                        ScriptName = $scriptName
                        Records    = $recordRefs
                        Command    = if ($script.Command) { $script.Command } else { '' }
                    })
            }
        }
    }

    return $rows.ToArray()
}

function script:resolvePamRotationScriptRecord {
    Param (
        [Parameter(Mandatory = $true)]
        [KeeperSecurity.Vault.VaultOnline] $Vault,
        [Parameter(Mandatory = $true)]
        [string] $RecordId
    )

    return resolvePamRotationRecord -Vault $Vault -Identifier $RecordId -AllowedTypes ([KeeperSecurity.Plugins.PAM.PamRecordTypes]::Script)
}

function Get-KeeperPamRotationList {
    <#
        .Synopsis
        List PAM record rotation schedules.

        .Description
        Shows pamUser rotation schedules with record, schedule, gateway, and PAM configuration details.

        .Parameter VerboseOutput
        Include Gateway UID and PAM Configuration UID columns.

        .Example
        Get-KeeperPamRotationList

        .Example
        Get-KeeperPamRotationList -VerboseOutput
        pam-rot-list -v
    #>
    [CmdletBinding()]
    Param (
        [Alias('v')]
        [switch] $VerboseOutput
    )

    $plugin = ensurePamPlugin
    if (-not $plugin) {
        Write-Error -Message 'PAM plugin is not available. Enterprise admin access is required.' -ErrorAction Stop
    }

    $vault = getVault
    $auth = getPamEnterpriseAuth
    $rows = @(getPamRotationScheduleRows -Plugin $plugin -Vault $vault -Auth $auth -VerboseOutput $VerboseOutput.IsPresent)

    if ($rows.Count -eq 0) {
        Write-Output 'No pamUser rotation schedules found.'
        return
    }

    writePamRotationListTable -Rows $rows -VerboseOutput $VerboseOutput.IsPresent

    Write-Output ''
    Write-Output 'Manual rotation is not supported yet. Coming soon.'
}

function Get-KeeperPamRotationInfo {
    <#
        .Synopsis
        Show rotation status for a PAM record.

        .Description
        Displays readiness, gateway, PAM config, schedule, password complexity, and disabled state.

        .Parameter Record
        Record UID, name, or title.

        .Parameter RecordUid
        Record UID alias for -Record.

        .Parameter Format
        Output format: table (default), csv, or json.

        .Example
        Get-KeeperPamRotationInfo -Record "<uid>"

        .Example
        Get-KeeperPamRotationInfo -r "My PAM User" -Format json
        pam-rot-info -r "<uid>"
        pam-rot-info -RecordUid "<uid>" -Format csv
    #>
    [CmdletBinding()]
    Param (
        [Alias('r')]
        [string] $Record,

        [Alias('record-uid')]
        [string] $RecordUid,

        [ValidateSet('table', 'csv', 'json')]
        [string] $Format = 'table'
    )

    $recordId = if (-not [string]::IsNullOrWhiteSpace($Record)) { $Record } else { $RecordUid }
    if ([string]::IsNullOrWhiteSpace($recordId)) {
        Write-Output '--record or --record-uid is required'
        return
    }

    $vault = getVault
    if (-not $vault) {
        Write-Error -Message 'Vault is not available.' -ErrorAction Stop
    }

    $plugin = ensurePamPlugin -SyncIfNeeded $false
    $auth = getPamEnterpriseAuth
    try {
        $resolved = resolvePamRotationRecord -Vault $vault -Identifier $recordId -AllowedTypes ([KeeperSecurity.Plugins.PAM.PamRecordTypes]::Rotation)
    }
    catch [System.InvalidOperationException] {
        return
    }
    if (-not $resolved) {
        Write-Output "Record '$recordId' not found"
        return
    }

    $rotationInfo = [KeeperSecurity.Plugins.PAM.RotationUtils]::GetRotationInfoAsync($auth, $resolved.Uid).GetAwaiter().GetResult()
    $schedulesResponse = [KeeperSecurity.Plugins.PAM.RouterUtils]::GetRotationSchedulesAsync($auth).GetAwaiter().GetResult()
    $schedule = $null
    if ($null -ne $schedulesResponse -and $null -ne $schedulesResponse.Schedules) {
        foreach ($item in $schedulesResponse.Schedules) {
            if ((encodePamByteString $item.RecordUid) -eq $resolved.Uid) {
                $schedule = $item
                break
            }
        }
    }

    $model = getPamRotationInfoModel -RotationInfo $rotationInfo -Record $resolved -Schedule $schedule -Plugin $plugin -Vault $vault
    switch ($Format) {
        'json' { writePamRotationInfoJson -Model $model }
        'csv' { writePamRotationInfoCsv -Model $model }
        default { writePamRotationInfoTable -Model $model }
    }
}

function Set-KeeperPamRotation {
    <#
        .Synopsis
        Create or update PAM record rotation configuration.

        .Description
        Create or update rotation settings for a PAM record.
        Supports single record (-Record) or bulk folder setup (-Folder).

        .Parameter Record
        Record UID, name, or pattern to configure for rotation.

        .Parameter Folder
        Folder UID or name for bulk rotation setup.

        .Parameter Force
        Skip confirmation prompts.

        .Parameter Config
        UID or title of the PAM configuration record.

        .Parameter IamAadConfig
        UID of a PAM configuration for IAM or Azure AD users (instead of -Resource).

        .Parameter Resource
        UID or title of the admin resource record.

        .Parameter ScheduleJson
        Rotation schedule as JSON. Example:
        '{"type": "WEEKLY", "weekday": "SATURDAY", "time": "22:00", "tz": "America/New_York"}'

        .Parameter ScheduleCron
        CRON schedule string (6-field rotation format).

        .Parameter OnDemand
        Configure manual on-demand rotation.

        .Parameter ScheduleConfig
        Inherit schedule from the PAM configuration record.

        .Parameter ScheduleOnly
        Update only the rotation schedule without changing other settings.

        .Parameter Complexity
        Password complexity CSV: length,upper,lower,digits,symbols[,special-chars].
        Example: 20,1,4,2,2,.=+-

        .Parameter ComplexityJson
        Password complexity rules as JSON (alternative to -Complexity).

        .Parameter AdminUser
        PAM user record UID to set as admin credential on the resource.

        .Parameter Enable
        Enable rotation for the record.

        .Parameter Disable
        Disable rotation for the record.

        .Parameter RotationProfile
        Optional rotation profile: general, iam_user, scripts_only, saas.

        .Parameter SaasConfigUid
        SaaS configuration UID when using the saas rotation profile.

        .Example
        Set-KeeperPamRotation -Record "My PAM User" -Config "AWS Config" -Resource "My Server" -OnDemand

        .Example
        Set-KeeperPamRotation -r "<uid>" -sj '{"type": "MONTHLY_BY_DAY", "monthDay": 1, "time": "04:00", "tz": "America/Chicago"}' -c "<config-uid>" -rs "<resource-uid>"

        .Example
        Set-KeeperPamRotation -r "<uid>" -x "20,1,4,2,2,.=+-" -c "<config-uid>" -rs "<resource-uid>" -Force

        .Example
        Set-KeeperPamRotation -Folder "<folder-uid>" -c "<config-uid>" -od -so -Force
    #>
    [CmdletBinding(PositionalBinding = $false)]
    Param (
        [Alias('r')]
        [string] $Record,

        [Alias('fd')]
        [string] $Folder,

        [Alias('c')]
        [string] $Config,

        [Alias('iac')]
        [string] $IamAadConfig,

        [Alias('rp')]
        [string] $RotationProfile,

        [string] $SaasConfigUid,

        [Alias('rs')]
        [string] $Resource,

        [Alias('sj')]
        [string] $ScheduleJson,

        [Alias('sc')]
        [string] $ScheduleCron,

        [Alias('od')]
        [switch] $OnDemand,

        [Alias('sf')]
        [switch] $ScheduleConfig,

        [Alias('so')]
        [switch] $ScheduleOnly,

        [Alias('x')]
        [string] $Complexity,

        [string] $ComplexityJson,

        [Alias('a')]
        [string] $AdminUser,

        [Alias('e')]
        [switch] $Enable,

        [Alias('d')]
        [switch] $Disable,

        [Alias('f')]
        [switch] $Force
    )

    if ([string]::IsNullOrWhiteSpace($Record) -and [string]::IsNullOrWhiteSpace($Folder)) {
        Write-Output '--record or --folder is required'
        return
    }

    if ($Enable.IsPresent -and $Disable.IsPresent) {
        Write-Output 'Cannot use both --enable and --disable at the same time.'
        return
    }

    if (-not [string]::IsNullOrWhiteSpace($Record) -and -not [string]::IsNullOrWhiteSpace($Folder)) {
        Write-Output 'Cannot use both --record and --folder at the same time.'
        return
    }

    if (-not [string]::IsNullOrWhiteSpace($Resource) -and -not [string]::IsNullOrWhiteSpace($IamAadConfig)) {
        Write-Output 'Cannot use both --resource and --iam-aad-config at once. --resource configures users on a resource; --iam-aad-config configures IAM/Azure AD users.'
        return
    }

    $plugin = ensurePamPlugin
    if (-not $plugin) {
        Write-Error -Message 'PAM plugin is not available. Enterprise admin access is required.' -ErrorAction Stop
    }

    $vault = getVault
    $auth = getPamEnterpriseAuth

    invokeKeeperPamRotationEdit -Auth $auth -Vault $vault -Options @{
        Record          = $Record
        Folder          = $Folder
        Config          = $Config
        IamAadConfig    = $IamAadConfig
        RotationProfile = $RotationProfile
        SaasConfigUid   = $SaasConfigUid
        Resource        = $Resource
        ScheduleJson    = $ScheduleJson
        ScheduleCron    = $ScheduleCron
        OnDemand        = $OnDemand.IsPresent
        ScheduleConfig  = $ScheduleConfig.IsPresent
        ScheduleOnly    = $ScheduleOnly.IsPresent
        Complexity      = $Complexity
        ComplexityJson  = $ComplexityJson
        AdminUser       = $AdminUser
        Enable          = $Enable.IsPresent
        Disable         = $Disable.IsPresent
        Force           = $Force.IsPresent
    }
}

function Get-KeeperPamRotationScript {
    <#
        .Synopsis
        List post-rotation scripts on PAM records.

        .Description
        Lists post-rotation scripts attached to PAM records.

        .Parameter Pattern
        Record UID or title filter.

        .Parameter Record
        Alias for filtering by record UID or title (same as -Pattern).

        .Example
        Get-KeeperPamRotationScript
        Get-KeeperPamRotationScript -Pattern "My PAM User"
    #>
    [CmdletBinding()]
    Param (
        [string] $Pattern,
        [Alias('r')]
        [string] $Record
    )

    $vault = getVault
    if (-not $vault) {
        Write-Error -Message 'Vault is not available.' -ErrorAction Stop
    }

    $filter = if (-not [string]::IsNullOrWhiteSpace($Pattern)) { $Pattern.Trim() } else { $Record }
    $rows = @(getPamRotationScriptListRows -Vault $vault -Pattern $filter)
    if ($rows.Count -eq 0) {
        Write-Output 'No post-rotation scripts found.'
        return
    }

    writePamRotationScriptTable -Rows $rows
}

function Add-KeeperPamRotationScript {
    <#
        .Synopsis
        Upload and attach a post-rotation script to a PAM record.

        .Description
        Uploads a local script file and attaches it as a post-rotation script.

        .Parameter Record
        Record UID or title (pamUser / pamDirectory).

        .Parameter Script
        Local file path to upload.

        .Parameter RunCommand
        Command line to run the script after rotation.

        .Parameter ScriptCommand
        Alias for -RunCommand (unless value is a script subcommand name).

        .Parameter AddCredential
        Record UID(s) with rotation credentials to link.

        .Example
        Add-KeeperPamRotationScript -Record "<uid>" -Script "C:\scripts\rotate.ps1" -RunCommand "powershell -File rotate.ps1"
        Add-KeeperPamRotationScript -Record "<uid>" -Script "/tmp/rotate.sh" -RunCommand "bash rotate.sh"
        Add-KeeperPamRotationScript fajHNL7_T3qsuzt2MDGEiw -Script "C:\scripts\rotate.ps1"
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0)]
        [Alias('r')]
        [string] $Record,

        [Alias('record-uid')]
        [string] $RecordUid,

        [Parameter(Position = 1)]
        [string] $Script,

        [Alias('script-command')]
        [string] $ScriptCommand,

        [Alias('run-command')]
        [string] $RunCommand,

        [Alias('add-credential', 'ac')]
        [string[]] $AddCredential
    )

    $recordId = resolvePamRotationScriptRecordId -Record $Record -RecordUid $RecordUid
    if ([string]::IsNullOrWhiteSpace($recordId)) {
        Write-Output '--record is required (or provide record UID as a positional argument)'
        return
    }

    if ([string]::IsNullOrWhiteSpace($Script)) {
        Write-Output '--script is required'
        return
    }

    $vault = getVault
    if (-not $vault) {
        Write-Error -Message 'Vault is not available.' -ErrorAction Stop
    }

    try {
        $resolved = resolvePamRotationScriptRecord -Vault $vault -RecordId $recordId
    }
    catch [System.InvalidOperationException] {
        return
    }
    if (-not $resolved) {
        Write-Output "Record '$recordId' not found"
        return
    }

    $filePath = [Environment]::ExpandEnvironmentVariables($Script.Trim())
    if (-not (Test-Path -LiteralPath $filePath)) {
        Write-Output "File `"$Script`" not found."
        return
    }

    $runCommand = getPamRotationRunCommand -RunCommand $RunCommand -ScriptCommand $ScriptCommand
    $scriptField = getOrCreatePamRotationScriptField -Record $resolved
    $preRefs = getPamRotationFileRefUids -Record $resolved
    if ($null -eq $preRefs) {
        $preRefs = New-Object 'System.Collections.Generic.HashSet[string]'
    }

    $uploadTask = New-Object KeeperSecurity.Vault.FileAttachmentUploadTask($filePath, $null, $true)
    try {
        $vault.UploadAttachment($resolved, $uploadTask).GetAwaiter().GetResult() | Out-Null
    }
    catch {
        Write-Output $_.Exception.Message
        return
    }
    finally {
        if ($uploadTask) {
            $uploadTask.Dispose()
        }
    }

    $postRefs = getPamRotationFileRefUids -Record $resolved
    if ($null -eq $postRefs) {
        $postRefs = New-Object 'System.Collections.Generic.HashSet[string]'
    }
    $newUids = @(
        $postRefs | Where-Object {
            -not [string]::IsNullOrEmpty($_) -and -not $preRefs.Contains($_)
        }
    )
    if ($newUids.Count -ne 1) {
        Write-Output 'Failed to determine uploaded script file UID. Only the record owner can attach post-rotation scripts.'
        return
    }

    $facade = New-Object KeeperSecurity.Vault.TypedRecordFacade[KeeperSecurity.Vault.TypedRecordFileRef]($resolved)
    if ($null -ne $facade.Fields.FileRef) {
        [void]$facade.Fields.FileRef.Values.Remove($newUids[0])
    }

    $scriptValue = New-Object KeeperSecurity.Vault.FieldScript
    $scriptValue.FileRef = $newUids[0]
    $scriptValue.RecordRef = resolvePamRotationCredentialUids -Vault $vault -Credentials $AddCredential
    $scriptValue.Command = $runCommand
    $scriptField.Values.Add($scriptValue)

    if (-not (updatePamRotationScriptRecord -Vault $vault -Record $resolved -Action add)) {
        return
    }
    Write-Output "Script added to record '$($resolved.Title)' ($($resolved.Uid))."
}

function Set-KeeperPamRotationScript {
    <#
        .Synopsis
        Update a post-rotation script on a PAM record.

        .Description
        Updates an existing post-rotation script on a PAM record.

        .Parameter Record
        Record UID or title.

        .Parameter Script
        Script file UID or name to update.

        .Parameter RunCommand
        New command line to run the script.

        .Parameter AddCredential
        Credential record UID(s) to link.

        .Parameter RemoveCredential
        Credential record UID(s) to unlink.

        .Example
        Set-KeeperPamRotationScript -Record "<uid>" -Script "rotate.ps1" -RunCommand "powershell -File rotate.ps1" -ac @("<cred-uid>")
        Set-KeeperPamRotationScript fajHNL7_T3qsuzt2MDGEiw -Script E5HGAlv7lHIkGa5PzPXgbQ -RunCommand "powershell -File rotate_password_v2.ps1"
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0)]
        [Alias('r')]
        [string] $Record,

        [Alias('record-uid')]
        [string] $RecordUid,

        [Parameter(Position = 1)]
        [string] $Script,

        [Alias('script-command')]
        [string] $ScriptCommand,

        [Alias('run-command')]
        [string] $RunCommand,

        [Alias('add-credential', 'ac')]
        [string[]] $AddCredential,

        [Alias('remove-credential', 'rc')]
        [string[]] $RemoveCredential
    )

    $recordId = resolvePamRotationScriptRecordId -Record $Record -RecordUid $RecordUid
    if ([string]::IsNullOrWhiteSpace($recordId)) {
        Write-Output '--record is required (or provide record UID as a positional argument)'
        return
    }

    if ([string]::IsNullOrWhiteSpace($Script)) {
        Write-Output '--script is required'
        return
    }

    $vault = getVault
    if (-not $vault) {
        Write-Error -Message 'Vault is not available.' -ErrorAction Stop
    }

    try {
        $resolved = resolvePamRotationScriptRecord -Vault $vault -RecordId $recordId
    }
    catch [System.InvalidOperationException] {
        return
    }
    if (-not $resolved) {
        Write-Output "Record '$recordId' not found"
        return
    }

    $scriptValue, $scriptField = findPamRotationScriptValue -Vault $vault -Record $resolved -ScriptName $Script.Trim()
    if (-not $scriptField) {
        Write-Output "Record '$($resolved.Title)' has no rotation scripts."
        return
    }
    if (-not $scriptValue) {
        Write-Output "Record '$($resolved.Title)' does not have script '$Script'. Use Script UID or name from Get-KeeperPamRotationScript (file path basename is also accepted)."
        return
    }

    $modified = $false
    $refs = New-Object 'System.Collections.Generic.HashSet[string]'
    if ($scriptValue.RecordRef) {
        foreach ($item in $scriptValue.RecordRef) {
            if (-not [string]::IsNullOrEmpty($item)) {
                [void]$refs.Add($item)
            }
        }
    }

    if ($RemoveCredential) {
        foreach ($cred in (resolvePamRotationCredentialUids -Vault $vault -Credentials $RemoveCredential)) {
            if ($refs.Remove($cred)) {
                $modified = $true
            }
        }
    }

    if ($AddCredential) {
        foreach ($cred in (resolvePamRotationCredentialUids -Vault $vault -Credentials $AddCredential)) {
            if ($refs.Add($cred)) {
                $modified = $true
            }
        }
    }

    if ($modified) {
        $scriptValue.RecordRef = toPamStringArray -Collection $refs
    }

    $runCommand = getPamRotationRunCommand -RunCommand $RunCommand -ScriptCommand $ScriptCommand
    if (-not [string]::IsNullOrWhiteSpace($runCommand)) {
        $scriptValue.Command = $runCommand
        $modified = $true
    }

    if (-not $modified) {
        Write-Output 'Nothing to do'
        return
    }

    if (-not (updatePamRotationScriptRecord -Vault $vault -Record $resolved -Action edit)) {
        return
    }
    Write-Output "Script updated on record '$($resolved.Title)' ($($resolved.Uid))."
}

function Remove-KeeperPamRotationScript {
    <#
        .Synopsis
        Remove a post-rotation script from a PAM record.

        .Description
        Removes a post-rotation script from a PAM record.

        .Parameter Record
        Record UID or title.

        .Parameter Script
        Script file UID or name to remove.

        .Example
        Remove-KeeperPamRotationScript -Record "<uid>" -Script "rotate.ps1"
        Remove-KeeperPamRotationScript fajHNL7_T3qsuzt2MDGEiw -Script CTUH9gBqQK_iJoph_APtNQ
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0)]
        [Alias('r')]
        [string] $Record,

        [Alias('record-uid')]
        [string] $RecordUid,

        [Parameter(Position = 1)]
        [string] $Script
    )

    $recordId = resolvePamRotationScriptRecordId -Record $Record -RecordUid $RecordUid
    if ([string]::IsNullOrWhiteSpace($recordId)) {
        Write-Output '--record is required (or provide record UID as a positional argument)'
        return
    }

    if ([string]::IsNullOrWhiteSpace($Script)) {
        Write-Output '--script is required'
        return
    }

    $vault = getVault
    if (-not $vault) {
        Write-Error -Message 'Vault is not available.' -ErrorAction Stop
    }

    try {
        $resolved = resolvePamRotationScriptRecord -Vault $vault -RecordId $recordId
    }
    catch [System.InvalidOperationException] {
        return
    }
    if (-not $resolved) {
        Write-Output "Record '$recordId' not found"
        return
    }

    $scriptValue, $scriptField = findPamRotationScriptValue -Vault $vault -Record $resolved -ScriptName $Script.Trim()
    if (-not $scriptField) {
        Write-Output "Record '$($resolved.Title)' has no rotation scripts."
        return
    }
    if (-not $scriptValue) {
        Write-Output "Record '$($resolved.Title)' does not have script '$Script'."
        return
    }

    [void]$scriptField.Values.Remove($scriptValue)
    if (-not (updatePamRotationScriptRecord -Vault $vault -Record $resolved -Action remove)) {
        return
    }
    Write-Output "Script removed from record '$($resolved.Title)' ($($resolved.Uid))."
}

New-Alias -Name pam-rotation-list -Value Get-KeeperPamRotationList -ErrorAction SilentlyContinue
New-Alias -Name pam-rot-list -Value Get-KeeperPamRotationList -ErrorAction SilentlyContinue
New-Alias -Name pam-rotation-info -Value Get-KeeperPamRotationInfo -ErrorAction SilentlyContinue
New-Alias -Name pam-rot-info -Value Get-KeeperPamRotationInfo -ErrorAction SilentlyContinue
New-Alias -Name pam-rotation-edit -Value Set-KeeperPamRotation -ErrorAction SilentlyContinue
New-Alias -Name pam-rot-edit -Value Set-KeeperPamRotation -ErrorAction SilentlyContinue
New-Alias -Name pam-rotation-new -Value Set-KeeperPamRotation -ErrorAction SilentlyContinue
New-Alias -Name pam-rot-new -Value Set-KeeperPamRotation -ErrorAction SilentlyContinue
New-Alias -Name pam-rotation-script-list -Value Get-KeeperPamRotationScript -ErrorAction SilentlyContinue
New-Alias -Name pam-rot-script-list -Value Get-KeeperPamRotationScript -ErrorAction SilentlyContinue
New-Alias -Name pam-rotation-script-add -Value Add-KeeperPamRotationScript -ErrorAction SilentlyContinue
New-Alias -Name pam-rot-script-add -Value Add-KeeperPamRotationScript -ErrorAction SilentlyContinue
New-Alias -Name pam-rotation-script-edit -Value Set-KeeperPamRotationScript -ErrorAction SilentlyContinue
New-Alias -Name pam-rot-script-edit -Value Set-KeeperPamRotationScript -ErrorAction SilentlyContinue
New-Alias -Name pam-rotation-script-delete -Value Remove-KeeperPamRotationScript -ErrorAction SilentlyContinue
New-Alias -Name pam-rot-script-delete -Value Remove-KeeperPamRotationScript -ErrorAction SilentlyContinue
