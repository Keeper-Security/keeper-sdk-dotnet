#requires -Version 5.1
$script:KD_LABEL_WIDTH = 21
$script:KD_FOLDER_LABEL_WIDTH = 25
$script:ShareObjectsCache = $null
$script:ShareObjectsCacheAccountUid = $null

class KdFolderListItem {
    [string]$FolderUid
    [string]$Name
    [string]$ParentUid
    [int]$Subfolders
    [int]$Records
}

class KdRecordListItem {
    [string]$RecordUid
    [string]$Name
    [string]$Type
    [long]$Revision
    [int]$Version
    [bool]$Shared
    [long]$FileSize
    [long]$ThumbnailSize
}

class KdRecordDetailItem {
    [string]$RecordUid
    [string]$Title
    [string]$Type
    [int]$Version
    [long]$Revision
}

class KdUserPermission {
    [string]$Username
    [bool]$Owner
    [string]$Role
    [bool]$CanEdit
    [bool]$CanView
    [bool]$CanDelete
}

$script:KdRootFolderUid = 'AAAAAAAAAAAAAAAAAPmtNA'

$script:AccessRoleLabels = @{
    0 = 'contributor'   # Navigator
    1 = 'contributor'   # Requestor
    2 = 'viewer'
    3 = 'share-manager'
    4 = 'content-manager'
    5 = 'content-share-manager'
    6 = 'full-manager'
    7 = 'unresolved'
}

$script:AccessTypeLabels = @{
    0 = 'AT_UNKNOWN'
    1 = 'AT_OWNER'
    2 = 'AT_USER'
    3 = 'AT_TEAM'
    4 = 'AT_ENTERPRISE'
    5 = 'AT_FOLDER'
    6 = 'AT_APPLICATION'
}

$script:KdSecretFieldTypes = @('password', 'secret', 'privateKey', 'passkey', 'otp')

$script:KdFieldLabels = @{
    name     = 'File Name'
    url      = 'URL'
    otp      = 'OTP'
    login    = 'Login'
    password = 'Password'
    host     = 'Host'
    notes    = 'Notes'
    phone    = 'Phone'
    address  = 'Address'
}

function Reset-KdShareObjectsCache {
    $script:ShareObjectsCache = $null
    $script:ShareObjectsCacheAccountUid = $null
}

function Get-AccessRoleLabel {
    Param([int]$roleType)
    if ($script:AccessRoleLabels.ContainsKey($roleType)) {
        return $script:AccessRoleLabels[$roleType]
    }
    return 'unknown'
}

function Get-KdRecordTypeAndTitle {
    Param($record)

    if ($record -and $record.Type) {
        $recordType = $record.Type
    }
    elseif ($record -and $record.Version -eq 4) {
        $recordType = 'file'
    }
    elseif ($record -and $record.Version -eq 5) {
        $recordType = 'application'
    }
    else {
        $recordType = 'Unknown'
    }

    $title = if ($record -and $record.Title) { $record.Title } else { '' }

    return [PSCustomObject]@{
        Type  = $recordType
        Title = $title
    }
}

function New-KdFolderListItems {
    Param($vault)

    $result = [System.Collections.ArrayList]::new()
    foreach ($folder in $vault.KeeperNSFFolderNodes) {
        $item = [KdFolderListItem]::new()
        $item.FolderUid  = $folder.FolderUid
        $item.Name       = $folder.Name
        $item.ParentUid  = if ($folder.ParentUid) { $folder.ParentUid } else { '(root)' }
        $item.Subfolders = $folder.Subfolders.Count
        $item.Records    = $folder.Records.Count
        $result.Add($item) | Out-Null
    }
    return $result
}

function New-KdRecordListItems {
    Param($vault)

    $result = [System.Collections.ArrayList]::new()
    foreach ($record in $vault.KeeperNSFRecordEntries) {
        $meta = Get-KdRecordTypeAndTitle $record
        $item = [KdRecordListItem]::new()
        $item.RecordUid     = $record.RecordUid
        $item.Name          = if ($record.Title) { $record.Title } else { $meta.Title }
        $item.Type          = $meta.Type
        $item.Revision      = $record.Revision
        $item.Version       = $record.Version
        $item.Shared        = $record.Shared
        $item.FileSize      = $record.FileSize
        $item.ThumbnailSize = $record.ThumbnailSize
        $result.Add($item) | Out-Null
    }
    return $result
}

function Resolve-KdNsfObject {
    Param(
        $vault,
        [string]$Uid,
        [string]$Name
    )

    if ($Uid) {
        [KeeperSecurity.Vault.FolderNode]$tmpFolder = $null
        if ($vault.TryGetKeeperNSFFolder($Uid, [ref]$tmpFolder)) {
            return [PSCustomObject]@{ Record = $null; Folder = $tmpFolder }
        }

        [KeeperSecurity.Vault.KeeperNSFRecord]$tmpRecord = $null
        if ($vault.TryGetKeeperNSFRecord($Uid, [ref]$tmpRecord)) {
            return [PSCustomObject]@{ Record = $tmpRecord; Folder = $null }
        }

        return [PSCustomObject]@{ Record = $null; Folder = $null }
    }

    if ($Name) {
        foreach ($f in $vault.KeeperNSFFolderNodes) {
            if ($f.Name -and $f.Name -ieq $Name) {
                return [PSCustomObject]@{ Record = $null; Folder = $f }
            }
        }
        foreach ($r in $vault.KeeperNSFRecordEntries) {
            if ($r.Title -and $r.Title -ieq $Name) {
                return [PSCustomObject]@{ Record = $r; Folder = $null }
            }
        }
        foreach ($f in $vault.KeeperNSFFolderNodes) {
            if ($f.Name -and $f.Name -ilike "*$Name*") {
                return [PSCustomObject]@{ Record = $null; Folder = $f }
            }
        }
        foreach ($r in $vault.KeeperNSFRecordEntries) {
            if ($r.Title -and $r.Title -ilike "*$Name*") {
                return [PSCustomObject]@{ Record = $r; Folder = $null }
            }
        }
    }

    return [PSCustomObject]@{ Record = $null; Folder = $null }
}

function Resolve-KdNsfRecord {
    Param(
        $vault,
        [string]$Identifier
    )

    [KeeperSecurity.Vault.KeeperNSFRecord]$tmpRecord = $null
    if ($vault.TryGetKeeperNSFRecord($Identifier, [ref]$tmpRecord)) {
        return $tmpRecord
    }

    foreach ($r in $vault.KeeperNSFRecordEntries) {
        if ($r.Title -and $r.Title -ieq $Identifier) { return $r }
    }
    foreach ($r in $vault.KeeperNSFRecordEntries) {
        if ($r.Title -and $r.Title -ilike "*$Identifier*") { return $r }
    }
    return $null
}

function Get-KdFolderNodeMap {
    Param($vault)

    $map = @{}
    foreach ($node in $vault.KeeperNSFFolderNodes) {
        if ($node.FolderUid) {
            $map[$node.FolderUid] = $node
        }
    }
    return $map
}

function Get-KeeperNSFFolderList {
    <#
	.Synopsis
	Lists all Keeper NSF folders.

	.Description
	Displays all Keeper NSF folders synced to the vault, including UID, name, parent, and subfolder/record counts.
#>
    [CmdletBinding()]
    Param(
        [Parameter(DontShow = $true)]
        $Vault
    )

    if (-not $Vault) {
        try {
            [KeeperSecurity.Vault.VaultOnline]$Vault = getVault
        } catch {
            Write-Host "Error getting vault: $($_.Exception.Message)" -ForegroundColor Red
            return
        }
    }

    if (-not $Vault.KeeperNSFFolderNodes) {
        Write-Host "No Keeper NSF folders found."
        return
    }

    $result = New-KdFolderListItems $Vault
    $result | Format-Table -AutoSize
}
New-Alias -Name nsf-folders -Value Get-KeeperNSFFolderList

function Get-KeeperNSFRecordList {
    <#
	.Synopsis
	Lists all Keeper NSF records.

	.Description
	Displays all Keeper NSF records synced to the vault, including UID, name, record type, revision, version, sharing, and file/thumbnail sizes.
#>
    [CmdletBinding()]
    Param(
        [Parameter(DontShow = $true)]
        $Vault
    )

    if (-not $Vault) {
        try {
            [KeeperSecurity.Vault.VaultOnline]$Vault = getVault
        } catch {
            Write-Host "Error getting vault: $($_.Exception.Message)" -ForegroundColor Red
            return
        }
    }

    if (-not $Vault.KeeperNSFRecordEntries) {
        Write-Host "No Keeper NSF records found."
        return
    }

    $result = New-KdRecordListItems $Vault
    $result | Format-Table -AutoSize
}
New-Alias -Name nsf-records -Value Get-KeeperNSFRecordList

function Get-KeeperNSFList {
    <#
	.Synopsis
	Lists all Keeper NSF folders and records.

	.Description
	Displays Keeper NSF folders and records. Supports table, csv, and json output formats.
	Use -Folders or -Records to show only folders or records.

	.Parameter Folders
	Show only folders.

	.Parameter Records
	Show only records.

	.Parameter Format
	Output format: table (default), csv, or json.

	.Parameter Output
	Path to output file. Ignored for table format.
#>
    [CmdletBinding()]
    Param(
        [Parameter()]
        [switch] $Folders,

        [Parameter()]
        [switch] $Records,

        [Parameter()]
        [ValidateSet('table', 'csv', 'json')]
        [string] $Format = 'table',

        [Parameter()]
        [string] $Output
    )

    try {
        [KeeperSecurity.Vault.VaultOnline]$vault = getVault
    } catch {
        Write-Host "Error getting vault: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    $showFolders = -not $Records.IsPresent -or $Folders.IsPresent
    $showRecords = -not $Folders.IsPresent -or $Records.IsPresent

    $combined = [System.Collections.ArrayList]::new()
    $folderItems = $null
    $recordItems = $null

    if ($showFolders) {
        $folderItems = New-KdFolderListItems $vault
        foreach ($item in $folderItems) {
            $combined.Add(@{
                ItemType    = 'Folder'
                UID         = $item.FolderUid
                Title       = if ($item.Name) { $item.Name } else { '' }
                Type        = 'folder'
                Description = "Subfolders: $($item.Subfolders), Records: $($item.Records)"
                Parent      = $item.ParentUid
            }) | Out-Null
        }
    }

    if ($showRecords) {
        $recordItems = New-KdRecordListItems $vault
        foreach ($item in $recordItems) {
            $combined.Add(@{
                ItemType    = 'Record'
                UID         = $item.RecordUid
                Title       = $item.Name
                Type        = $item.Type
                Description = "Rev: $($item.Revision), Shared: $($item.Shared)"
                Parent      = ''
            }) | Out-Null
        }
    }

    if ($combined.Count -eq 0) {
        Write-Host "No Keeper NSF data found. Run Sync-Keeper to refresh." -ForegroundColor DarkYellow
        return
    }

    if ($Format -eq 'json') {
        $jsonData = $combined | ForEach-Object {
            [ordered]@{
                item_type   = $_.ItemType
                uid         = $_.UID
                title       = $_.Title
                type        = $_.Type
                description = $_.Description
                parent      = $_.Parent
            }
        }
        $jsonText = $jsonData | ConvertTo-Json -Depth 4
        if ($Output) {
            $jsonText | Out-File -FilePath $Output -Encoding utf8
            Write-Host "JSON output written to '$Output' ($($combined.Count) items)." -ForegroundColor Green
        } else {
            $jsonText
        }
        return
    }

    if ($Format -eq 'csv') {
        $csvData = $combined | ForEach-Object {
            [PSCustomObject]@{
                ItemType    = $_.ItemType
                UID         = $_.UID
                Title       = $_.Title
                Type        = $_.Type
                Description = $_.Description
                Parent      = $_.Parent
            }
        }
        if ($Output) {
            $csvData | Export-Csv -Path $Output -NoTypeInformation -Encoding utf8
            Write-Host "CSV output written to '$Output' ($($combined.Count) items)." -ForegroundColor Green
        } else {
            $csvData | ConvertTo-Csv -NoTypeInformation
        }
        return
    }

    $folderCount = @($combined | Where-Object { $_.ItemType -eq 'Folder' }).Count
    $recordCount = @($combined | Where-Object { $_.ItemType -eq 'Record' }).Count

    Write-Host ""
    Write-Host "=== Keeper NSF Summary ===" -ForegroundColor Cyan
    Write-Host "  Folders: $folderCount"
    Write-Host "  Records: $recordCount"
    Write-Host ""

    if ($showFolders -and $folderCount -gt 0) {
        Write-Host "--- Folders ---" -ForegroundColor Yellow
        $folderItems | Format-Table -AutoSize
    }

    if ($showRecords -and $recordCount -gt 0) {
        Write-Host "--- Records ---" -ForegroundColor Yellow
        $recordItems | Format-Table -AutoSize
    }
}
New-Alias -Name nsf-list -Value Get-KeeperNSFList

function Get-KeeperNSFRecord {
    <#
	.Synopsis
	Get detailed information about a Keeper NSF record or folder.

	.Description
	Retrieves and displays detailed information about a specific Keeper NSF record or folder by UID or name.
	Shows metadata, user permissions, and share administrators.

	.Parameter Uid
	Record or folder UID to look up.

	.Parameter Name
	Record or folder name to search for (case-insensitive).

	.Parameter Format
	Output format: detail (default) or json.
#>
    [CmdletBinding()]
    Param (
        [string] $Uid,
        [string] $Name,

        [Parameter()]
        [ValidateSet('detail', 'json')]
        [string] $Format = 'detail'
    )
    try {
        [KeeperSecurity.Vault.VaultOnline]$vault = getVault
    } catch {
        Write-Host "Error getting vault: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    if (-not $Uid -and -not $Name) {
        Write-Host "Please provide either -Uid or -Name parameter." -ForegroundColor Red
        return
    }

    $storage = $vault.Storage
    $currentAccountUid = [KeeperSecurity.Utils.CryptoUtils]::Base64UrlEncode($vault.Auth.AuthContext.AccountUid)

    $resolved = Resolve-KdNsfObject -vault $vault -Uid $Uid -Name $Name
    $kdRecord = $resolved.Record
    $kdFolder = $resolved.Folder

    if (-not $kdRecord -and -not $kdFolder) {
        $id = if ($Uid) { $Uid } else { $Name }
        Write-Host "Keeper NSF object with identifier '$id' not found." -ForegroundColor Red
        return
    }

    if ($Format -eq 'json') {
        if ($kdRecord) {
            $jsonObj = Build-KdRecordJson $vault $storage $kdRecord $currentAccountUid
        } else {
            $jsonObj = Build-KdFolderJson $vault $storage $kdFolder $currentAccountUid
        }
        $jsonObj | ConvertTo-Json -Depth 8
        return
    }

    if ($kdRecord) {
        Show-KdRecordDetail $vault $storage $kdRecord $currentAccountUid
    }
    else {
        Show-KdFolderDetail $vault $storage $kdFolder $currentAccountUid
    }
}

function Get-KdNsfDecryptedRecordData {
    Param($record, $storage)

    if (-not $record -or -not $record.RecordKey) { return $null }

    $storageRecord = $storage.KdRecords.GetEntity($record.RecordUid)
    if (-not $storageRecord -or [string]::IsNullOrEmpty($storageRecord.Data)) { return $null }

    try {
        $encrypted = [KeeperSecurity.Utils.CryptoUtils]::Base64UrlDecode($storageRecord.Data)
        $decrypted = [KeeperSecurity.Utils.CryptoUtils]::DecryptAesV2($encrypted, $record.RecordKey)
        $jsonText = [System.Text.Encoding]::UTF8.GetString($decrypted)
        return ($jsonText | ConvertFrom-Json -ErrorAction Stop)
    }
    catch {
        Write-Verbose "Could not decrypt NSF record data for $($record.RecordUid): $($_.Exception.Message)"
        return $null
    }
}

function Get-KdNsfRecordFields {
    Param($record, $storage)

    $data = Get-KdNsfDecryptedRecordData -record $record -storage $storage
    if ($data -and $data.fields) {
        $fields = [System.Collections.ArrayList]::new()
        foreach ($f in @($data.fields)) {
            if (-not $f -or [string]::IsNullOrWhiteSpace($f.type)) { continue }

            $values = [System.Collections.ArrayList]::new()
            if ($null -ne $f.value) {
                foreach ($v in @($f.value)) {
                    if ($null -ne $v) {
                        $values.Add($v) | Out-Null
                    }
                }
            }

            $fields.Add([PSCustomObject]@{
                Type  = [string]$f.type
                Value = @($values)
            }) | Out-Null
        }
        return @($fields)
    }

    if ($record.Fields) {
        return @($record.Fields)
    }
    return @()
}

function ConvertFrom-KdNsfFieldJson {
    Param([string]$RawValue)

    if ([string]::IsNullOrWhiteSpace($RawValue)) { return $null }

    $trimmed = $RawValue.Trim()
    if (-not ($trimmed.StartsWith('{') -or $trimmed.StartsWith('['))) {
        return $RawValue
    }

    try {
        return ($trimmed | ConvertFrom-Json -ErrorAction Stop)
    }
    catch {
        return $RawValue
    }
}

function Get-KdNsfJsonProperty {
    Param($Object, [string]$Name)

    if ($null -eq $Object) { return $null }

    if ($Object -is [hashtable]) {
        foreach ($key in $Object.Keys) {
            if ($key -ieq $Name) { return $Object[$key] }
        }
        return $null
    }

    $prop = $Object.PSObject.Properties | Where-Object { $_.Name -ieq $Name } | Select-Object -First 1
    if ($prop) { return $prop.Value }
    return $null
}

function Format-KdNsfHostDisplayValue {
    Param($Value)

    if ($null -eq $Value) { return $null }

    if ($Value -is [string]) {
        $parsed = ConvertFrom-KdNsfFieldJson -RawValue $Value
        if ($parsed -ne $Value) {
            return Format-KdNsfHostDisplayValue -Value $parsed
        }
        if (-not [string]::IsNullOrWhiteSpace($Value)) {
            return $Value.Trim()
        }
        return $null
    }

    if ($Value -is [System.Collections.IEnumerable]) {
        $entries = @()
        foreach ($item in @($Value)) {
            $formatted = Format-KdNsfHostDisplayValue -Value $item
            if ($formatted) { $entries += $formatted }
        }
        if ($entries.Count -gt 0) {
            return ($entries -join '; ')
        }
        return $null
    }

    $hostName = Get-KdNsfJsonProperty -Object $Value -Name 'hostName'
    if (-not $hostName) { $hostName = Get-KdNsfJsonProperty -Object $Value -Name 'host' }
    $port = Get-KdNsfJsonProperty -Object $Value -Name 'port'

    if ($hostName -or $port) {
        $parts = @()
        if ($hostName) { $parts += "hostName: $hostName" }
        if ($port) { $parts += "port: $port" }
        return ($parts -join ', ')
    }
    return $null
}

function Test-KdNsfSecretField {
    Param([string]$FieldType)

    return $script:KdSecretFieldTypes -contains $FieldType
}

function Format-KdNsfDateFieldValue {
    Param($Value)

    if ($Value -match '^\d+$') {
        try {
            $timestamp = [long]$Value
            if ($timestamp -le 0) { return $Value }
            if ($timestamp -gt 9999999999) {
                return [DateTimeOffset]::FromUnixTimeMilliseconds($timestamp).ToString('yyyy-MM-dd')
            }
            return [DateTimeOffset]::FromUnixTimeSeconds($timestamp).ToString('yyyy-MM-dd')
        } catch { }
    }
    return $Value
}

function Format-KdNsfComplexFieldValue {
    Param(
        [string]$FieldType,
        $Value
    )

    if ($Value -isnot [System.Management.Automation.PSCustomObject]) {
        if ($FieldType -eq 'date') {
            return Format-KdNsfDateFieldValue -Value $Value
        }
        return $Value
    }

    switch ($FieldType) {
        'name' {
            $parts = @(
                (Get-KdNsfJsonProperty -Object $Value -Name 'first'),
                (Get-KdNsfJsonProperty -Object $Value -Name 'middle'),
                (Get-KdNsfJsonProperty -Object $Value -Name 'last')
            ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
            if ($parts.Count -gt 0) { return ($parts -join ' ') }
            return $null
        }
        'address' {
            $parts = @(
                (Get-KdNsfJsonProperty -Object $Value -Name 'street1'),
                (Get-KdNsfJsonProperty -Object $Value -Name 'street2'),
                (Get-KdNsfJsonProperty -Object $Value -Name 'city'),
                (Get-KdNsfJsonProperty -Object $Value -Name 'state'),
                (Get-KdNsfJsonProperty -Object $Value -Name 'zip'),
                (Get-KdNsfJsonProperty -Object $Value -Name 'country')
            ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
            if ($parts.Count -gt 0) { return ($parts -join ', ') }
            return $null
        }
        'phone' {
            $number = Get-KdNsfJsonProperty -Object $Value -Name 'number'
            if (-not $number) { return $null }
            $result = $number
            $ext = Get-KdNsfJsonProperty -Object $Value -Name 'ext'
            if ($ext) { $result += " ext. $ext" }
            $type = Get-KdNsfJsonProperty -Object $Value -Name 'type'
            if ($type) { $result += " ($type)" }
            return $result
        }
        default {
            $parts = @($Value.PSObject.Properties | ForEach-Object {
                if ($null -ne $_.Value -and "$($_.Value)" -ne '') {
                    "$($_.Name): $($_.Value)"
                }
            })
            if ($parts.Count -gt 0) { return ($parts -join ', ') }
            return ($Value | ConvertTo-Json -Compress -Depth 10)
        }
    }
}

function Format-KdNsfFieldDisplayValue {
    Param(
        [string]$FieldType,
        $RawValue
    )

    if ($null -eq $RawValue) { return $null }
    if ($RawValue -is [string] -and [string]::IsNullOrWhiteSpace($RawValue)) { return $null }

    if ((Test-KdNsfSecretField -FieldType $FieldType) -and -not (Get-KeeperPasswordVisible)) {
        return '********'
    }

    if ($FieldType -eq 'host') {
        return Format-KdNsfHostDisplayValue -Value $RawValue
    }

    if ($RawValue -is [System.Management.Automation.PSCustomObject] -or $RawValue -is [hashtable]) {
        return Format-KdNsfComplexFieldValue -FieldType $FieldType -Value $RawValue
    }

    $parsed = ConvertFrom-KdNsfFieldJson -RawValue ([string]$RawValue)

    if ($parsed -is [System.Management.Automation.PSCustomObject] -or $parsed -is [hashtable]) {
        return Format-KdNsfComplexFieldValue -FieldType $FieldType -Value $parsed
    }

    if ($parsed -is [System.Collections.IEnumerable] -and $parsed -isnot [string]) {
        $items = @()
        foreach ($item in @($parsed)) {
            $formatted = Format-KdNsfFieldDisplayValue -FieldType $FieldType -RawValue $item
            if ($formatted) { $items += $formatted }
        }
        if ($items.Count -gt 0) {
            return ($items -join '; ')
        }
        return $null
    }

    if ($FieldType -eq 'date') {
        return Format-KdNsfDateFieldValue -Value ([string]$RawValue)
    }

    return [string]$RawValue
}

function Get-KdNsfFieldLabel {
    Param([string]$FieldType)

    if ($script:KdFieldLabels.ContainsKey($FieldType)) {
        return $script:KdFieldLabels[$FieldType]
    }
    if ([string]::IsNullOrWhiteSpace($FieldType)) {
        return $FieldType
    }
    return (Get-Culture).TextInfo.ToTitleCase($FieldType.ToLower())
}

function Show-KdRecordDetail {
    Param($vault, $storage, $record, $currentAccountUid)

    $meta = Get-KdRecordTypeAndTitle $record
    $recordType = $meta.Type
    $title = $meta.Title

    Write-Host ""
    Write-Host ("{0,$script:KD_LABEL_WIDTH}: {1}" -f "UID", $record.RecordUid)
    Write-Host ("{0,$script:KD_LABEL_WIDTH}: {1}" -f "Type", $recordType)
    Write-Host ("{0,$script:KD_LABEL_WIDTH}: {1}" -f "Title", $title)

    if ($record.Notes) {
        Write-Host ("{0,$script:KD_LABEL_WIDTH}: {1}" -f "Notes", $record.Notes)
    }

    $recordFields = Get-KdNsfRecordFields -record $record -storage $storage
    if ($recordFields.Count -gt 0) {
        foreach ($field in $recordFields) {
            if (-not $field -or [string]::IsNullOrWhiteSpace($field.Type)) { continue }

            $rawValues = @($field.Value) | Where-Object { $null -ne $_ }
            if ($rawValues.Count -eq 0) { continue }

            if ($field.Type -eq 'name') {
                $nameValue = Format-KdNsfFieldDisplayValue -FieldType 'name' -RawValue $rawValues[0]
                if ($nameValue -eq $title) { continue }
            }

            $displayValues = @()
            foreach ($raw in $rawValues) {
                $formatted = Format-KdNsfFieldDisplayValue -FieldType $field.Type -RawValue $raw
                if ($formatted) { $displayValues += $formatted }
            }
            if ($displayValues.Count -eq 0) { continue }

            $label = Get-KdNsfFieldLabel -FieldType $field.Type
            Write-Host ("{0,$script:KD_LABEL_WIDTH}: {1}" -f $label, $displayValues[0])
            for ($i = 1; $i -lt $displayValues.Count; $i++) {
                Write-Host ("{0,$script:KD_LABEL_WIDTH}  {1}" -f "", $displayValues[$i])
            }
        }
    }

    if ($record.FileSize -gt 0) {
        Write-Host ("{0,$script:KD_LABEL_WIDTH}: {1}" -f "File Size", ("{0:N0}" -f $record.FileSize))
    }
    if ($record.ThumbnailSize -gt 0) {
        Write-Host ("{0,$script:KD_LABEL_WIDTH}: {1}" -f "Thumbnail Size", ("{0:N0}" -f $record.ThumbnailSize))
    }

    Write-Host ""

    $recordAccesses = Get-KdRecordAccesses $vault $storage $record
    $shareAdminEmails = Get-KdRecordShareAdminEmails $vault $record.RecordUid

    Show-KdPermissions $vault $recordAccesses $shareAdminEmails $currentAccountUid 'record'

    Write-Host ""
}

function Show-KdFolderDetail {
    Param($vault, $storage, $folder, $currentAccountUid)

    Write-Host ""
    Write-Host ("{0,$script:KD_FOLDER_LABEL_WIDTH}: {1}" -f "Nested Share Folder UID", $folder.FolderUid)
    Write-Host ("{0,$script:KD_FOLDER_LABEL_WIDTH}: {1}" -f "Name", $folder.Name)

    $storedFolder = $storage.KdFolders.GetEntity($folder.FolderUid)
    $ownerAccountUid = if ($storedFolder) { $storedFolder.OwnerAccountUid } else { $null }
    $ownerUsername = if ($storedFolder) { $storedFolder.OwnerUsername } else { $null }

    $folderAccesses = Get-KdFolderAccesses $vault $storage $folder
    Show-KdFolderPermissions $vault $folderAccesses $currentAccountUid $ownerAccountUid $ownerUsername
}

function Resolve-KdUsername {
    Param($vault, $accessTypeUid, $currentAccountUid)

    if ($accessTypeUid -eq $currentAccountUid) {
        return $vault.Auth.Username
    }
    try {
        $enterprise = $Script:Context.Enterprise
        if ($enterprise -and $enterprise.enterpriseData) {
            foreach ($eu in $enterprise.enterpriseData.Users) {
                $euAccountUid = [KeeperSecurity.Utils.CryptoUtils]::Base64UrlEncode($eu.AccountUid)
                if ($euAccountUid -eq $accessTypeUid) {
                    return $eu.Email
                }
            }
        }
    } catch { }

    if ($script:ShareObjectsCacheAccountUid -and $script:ShareObjectsCacheAccountUid -ne $currentAccountUid) {
        Reset-KdShareObjectsCache
    }

    if ($null -eq $script:ShareObjectsCache) {
        try {
            $rq = New-Object Records.GetShareObjectsRequest
            $rs = $vault.Auth.ExecuteAuthRest("vault/get_share_objects", $rq, [Records.GetShareObjectsResponse]).GetAwaiter().GetResult()
            $cache = @{}
            foreach ($userList in @($rs.ShareRelationships, $rs.ShareFamilyUsers, $rs.ShareEnterpriseUsers, $rs.ShareMCEnterpriseUsers)) {
                foreach ($su in $userList) {
                    if ($su.UserAccountUid -and -not $su.UserAccountUid.IsEmpty) {
                        $suUid = [KeeperSecurity.Utils.CryptoUtils]::Base64UrlEncode($su.UserAccountUid.ToByteArray())
                        if ($su.Username -and -not $cache.ContainsKey($suUid)) {
                            $cache[$suUid] = $su.Username
                        }
                    }
                }
            }
            $script:ShareObjectsCache = $cache
            $script:ShareObjectsCacheAccountUid = $currentAccountUid
        } catch {
            Write-Verbose "Could not load share objects cache: $($_.Exception.Message)"
            return $accessTypeUid
        }
    }

    if ($script:ShareObjectsCache.ContainsKey($accessTypeUid)) {
        return $script:ShareObjectsCache[$accessTypeUid]
    }

    return $accessTypeUid
}

function Test-KdIsFolderOwner {
    Param($access, $username, $ownerAccountUid, $ownerUsername)

    if ($ownerAccountUid -and $access.AccessTypeUid -eq $ownerAccountUid) {
        return $true
    }
    if ($ownerUsername -and $username -and $username.ToLower() -eq $ownerUsername.ToLower()) {
        return $true
    }
    return $false
}

function Get-KdUserPermissions {
    Param($vault, $directAccesses, $currentAccountUid, $objectType, $ownerAccountUid, $ownerUsername)

    $userPerms = [System.Collections.ArrayList]::new()
    foreach ($access in $directAccesses) {
        $hint = $null
        if ($access.PSObject.Properties.Match('AccessorEmail').Count -gt 0) {
            $hint = $access.AccessorEmail
        }
        if ($hint) {
            $username = $hint
        } else {
            $username = Resolve-KdUsername $vault $access.AccessTypeUid $currentAccountUid
        }
        if ($objectType -eq 'record') {
            $isOwner = $access.Owner
        } else {
            $isOwner = Test-KdIsFolderOwner $access $username $ownerAccountUid $ownerUsername
        }

        $perm = [KdUserPermission]::new()
        $perm.Username = $username
        $perm.Owner    = $isOwner
        $perm.Role     = Get-AccessRoleLabel $access.AccessRoleType
        if ($objectType -eq 'record') {
            $perm.CanEdit   = $access.CanEdit
            $perm.CanView   = $access.CanView
            $perm.CanDelete = $access.CanDelete
        }
        $userPerms.Add($perm) | Out-Null
    }
    return $userPerms
}

function ConvertTo-KdPermissionsJson {
    Param($userPerms, $objectType)

    $result = [System.Collections.ArrayList]::new()
    foreach ($perm in $userPerms) {
        if ($objectType -eq 'record') {
            $entry = [ordered]@{
                user      = $perm.Username
                shareable = $(if ($perm.CanEdit -or $perm.Owner) { 'Yes' } else { 'No' })
                read_only = $(if (-not $perm.CanEdit -and -not $perm.Owner) { 'Yes' } else { 'No' })
            }
            if ($perm.Owner) { $entry.owner = 'Yes' } else { $entry.role = $perm.Role }
            $result.Add($entry) | Out-Null
        }
    }
    return $result
}

function Resolve-KdFolderParentUid {
    Param($rawParent, $folderMap)

    if ([string]::IsNullOrEmpty($rawParent) -or $rawParent -eq $script:KdRootFolderUid -or -not $folderMap.ContainsKey($rawParent)) {
        return $null
    }
    return $rawParent
}

function Format-KdNsfFolderPath {
    Param($path)

    if ([string]::IsNullOrEmpty($path) -or $path -eq '/') {
        return '/'
    }
    return $path.TrimStart('/')
}

function ConvertTo-KdFolderPermissionsJson {
    Param($vault, $folderAccesses, $currentAccountUid, $ownerAccountUid, $ownerUsername)

    $userPerms = [System.Collections.ArrayList]::new()
    $teamPerms = [System.Collections.ArrayList]::new()
    $shareAdmins = [System.Collections.ArrayList]::new()

    foreach ($access in $folderAccesses) {
        $hint = $null
        if ($access.PSObject.Properties.Match('AccessorEmail').Count -gt 0) {
            $hint = $access.AccessorEmail
        }
        $username = if ($hint) { $hint } else { Resolve-KdUsername $vault $access.AccessTypeUid $currentAccountUid }

        $atInt = [int]$access.AccessType
        $atLabel = if ($script:AccessTypeLabels.ContainsKey($atInt)) { $script:AccessTypeLabels[$atInt] } else { 'AT_UNKNOWN' }
        $accessor = if ($username) { $username } else { $access.AccessTypeUid }

        $isOwner = Test-KdIsFolderOwner $access $username $ownerAccountUid $ownerUsername

        $roleInt = [int]$access.AccessRoleType
        $roleLabel = if ($isOwner) { 'owner' } else { (Get-AccessRoleLabel $roleInt) }

        $inherited = $false
        if ($access.PSObject.Properties.Match('Inherited').Count -gt 0) {
            $inherited = [bool]$access.Inherited
        }

        $entry = [ordered]@{
            accessor    = $accessor
            access_type = $atLabel
            role        = $roleLabel
            inherited   = $inherited
        }

        if ($atLabel -eq 'AT_TEAM') {
            $teamPerms.Add($entry) | Out-Null
        }
        else {
            $userPerms.Add($entry) | Out-Null
        }

        if ($roleInt -eq 6) {
            $shareAdmins.Add($accessor) | Out-Null
        }
    }

    return @{
        user_permissions = @($userPerms)
        team_permissions = @($teamPerms)
        share_admins     = @($shareAdmins | Select-Object -Unique)
    }
}

function Get-KdRecordAccesses {
    Param($vault, $storage, $record)

    try {
        $rq = New-Object Record.V3.Details.RecordAccessRequest
        $rq.RecordUids.Add([Google.Protobuf.ByteString]::CopyFrom([KeeperSecurity.Utils.CryptoUtils]::Base64UrlDecode($record.RecordUid)))
        $rs = $vault.Auth.ExecuteAuthRest("vault/records/v3/details/access", $rq, [Record.V3.Details.RecordAccessResponse]).GetAwaiter().GetResult()
        $converted = [System.Collections.ArrayList]::new()
        foreach ($ra in $rs.RecordAccesses) {
            $d = $ra.Data
            if ($null -eq $d) { continue }
            $emailHint = $null
            if ($ra.AccessorInfo -and $ra.AccessorInfo.Name) { $emailHint = $ra.AccessorInfo.Name }
            $converted.Add([PSCustomObject]@{
                AccessTypeUid  = [KeeperSecurity.Utils.CryptoUtils]::Base64UrlEncode($d.AccessTypeUid.ToByteArray())
                AccessType     = [int]$d.AccessType
                AccessRoleType = [int]$d.AccessRoleType
                Owner          = [bool]$d.Owner
                Inherited      = [bool]$d.Inherited
                CanEdit        = [bool]$d.CanEdit
                CanView        = [bool]$d.CanView
                CanDelete      = [bool]$d.CanDelete
                AccessorEmail  = $emailHint
            }) | Out-Null
        }
        return @($converted)
    }
    catch {
        Write-Verbose "Could not retrieve record access from server: $($_.Exception.Message)"
        return @($storage.KdRecordAccesses.GetLinksForSubject($record.RecordUid))
    }
}

function Get-KdRecordShareAdminEmails {
    Param($vault, $recordUid)

    $shareAdminEmails = [System.Collections.ArrayList]::new()
    try {
        $rq = New-Object Enterprise.GetSharingAdminsRequest
        $rq.RecordUid = [Google.Protobuf.ByteString]::CopyFrom([KeeperSecurity.Utils.CryptoUtils]::Base64UrlDecode($recordUid))
        $response = $vault.Auth.ExecuteAuthRest("enterprise/get_sharing_admins", $rq, [Enterprise.GetSharingAdminsResponse]).GetAwaiter().GetResult()
        foreach ($profile in $response.UserProfileExts) {
            if ($profile.Email) { $shareAdminEmails.Add($profile.Email) | Out-Null }
        }
    }
    catch {
        Write-Verbose "Could not retrieve share admins: $($_.Exception.Message)"
    }
    return @($shareAdminEmails)
}

function Get-KdFolderAccesses {
    Param($vault, $storage, $folder)

    try {
        $rq = New-Object Folder.V3.GetFolderAccessRequest
        $rq.FolderUid.Add([Google.Protobuf.ByteString]::CopyFrom([KeeperSecurity.Utils.CryptoUtils]::Base64UrlDecode($folder.FolderUid)))
        $rs = $vault.Auth.ExecuteAuthRest("vault/folders/v3/access", $rq, [Folder.V3.GetFolderAccessResponse]).GetAwaiter().GetResult()
        foreach ($result in $rs.FolderAccessResults) {
            if ($null -eq $result.Error) {
                $converted = [System.Collections.ArrayList]::new()
                foreach ($a in $result.Accessors) {
                    $converted.Add([PSCustomObject]@{
                        AccessTypeUid  = [KeeperSecurity.Utils.CryptoUtils]::Base64UrlEncode($a.AccessTypeUid.ToByteArray())
                        AccessType     = [int]$a.AccessType
                        AccessRoleType = [int]$a.AccessRoleType
                        Inherited      = [bool]$a.Inherited
                    }) | Out-Null
                }
                return @($converted)
            }
        }
    }
    catch {
        Write-Verbose "Could not retrieve folder access: $($_.Exception.Message)"
    }

    $cached = [System.Collections.ArrayList]::new()
    foreach ($a in $storage.KdFolderAccesses.GetLinksForSubject($folder.FolderUid)) {
        $cached.Add([PSCustomObject]@{
            AccessTypeUid  = $a.AccessTypeUid
            AccessType     = $a.AccessType
            AccessRoleType = $a.AccessRoleType
            Inherited      = [bool]$a.Inherited
        }) | Out-Null
    }
    return @($cached)
}

function Show-KdFolderPermissions {
    Param($vault, $folderAccesses, $currentAccountUid, $ownerAccountUid, $ownerUsername)

    if (-not $folderAccesses -or $folderAccesses.Count -eq 0) {
        Write-Host "No permissions found for this folder."
        Write-Host ""
        return
    }

    $users = [System.Collections.ArrayList]::new()
    $teams = [System.Collections.ArrayList]::new()
    $shareAdmins = [System.Collections.ArrayList]::new()

    foreach ($access in $folderAccesses) {
        $hint = $null
        if ($access.PSObject.Properties.Match('AccessorEmail').Count -gt 0) {
            $hint = $access.AccessorEmail
        }
        $username = if ($hint) { $hint } else { Resolve-KdUsername $vault $access.AccessTypeUid $currentAccountUid }

        $atInt = [int]$access.AccessType
        $atLabel = if ($script:AccessTypeLabels.ContainsKey($atInt)) { $script:AccessTypeLabels[$atInt] } else { 'AT_UNKNOWN' }
        $accessor = if ($username) { $username } else { $access.AccessTypeUid }

        $isOwner = Test-KdIsFolderOwner $access $username $ownerAccountUid $ownerUsername
        $roleInt = [int]$access.AccessRoleType
        $roleLabel = if ($isOwner) { 'owner' } else { (Get-AccessRoleLabel $roleInt) }

        $entry = [PSCustomObject]@{
            Accessor = $accessor
            RoleLabel = $roleLabel
            IsOwner = $isOwner
        }

        if ($atLabel -eq 'AT_TEAM') {
            $teams.Add($entry) | Out-Null
        }
        else {
            $users.Add($entry) | Out-Null
        }

        if ($roleInt -eq 6) {
            $shareAdmins.Add($entry) | Out-Null
        }
    }

    if ($users.Count -gt 0) {
        Write-Host ""
        Write-Host ("{0,$script:KD_FOLDER_LABEL_WIDTH}:" -f "User Permissions")
        foreach ($entry in $users) {
            Write-Host ("{0,$script:KD_FOLDER_LABEL_WIDTH}: {1}" -f $entry.Accessor, $entry.RoleLabel)
        }
    }

    if ($teams.Count -gt 0) {
        Write-Host ""
        Write-Host ("{0,$script:KD_FOLDER_LABEL_WIDTH}:" -f "Team Permissions")
        foreach ($entry in $teams) {
            Write-Host ("{0,$script:KD_FOLDER_LABEL_WIDTH}: {1}" -f $entry.Accessor, $entry.RoleLabel)
        }
    }

    if ($shareAdmins.Count -gt 0) {
        Write-Host ""
        Write-Host ("{0,$script:KD_FOLDER_LABEL_WIDTH}:" -f "Share Administrators")
        foreach ($entry in $shareAdmins) {
            $adminRole = if ($entry.IsOwner) { 'owner' } else { 'full-manager' }
            Write-Host ("{0,$script:KD_FOLDER_LABEL_WIDTH}: {1}" -f $entry.Accessor, $adminRole)
        }
    }

    Write-Host ""
}

function Show-KdPermissions {
    Param($vault, $directAccesses, $shareAdminEmails, $currentAccountUid, $objectType, $ownerAccountUid, $ownerUsername)

    $userPerms = Get-KdUserPermissions $vault $directAccesses $currentAccountUid $objectType $ownerAccountUid $ownerUsername

    if ($userPerms.Count -gt 0) {
        if ($objectType -ne 'folder') {
            Write-Host ("{0,$script:KD_LABEL_WIDTH}:" -f "User Permissions")
            Write-Host ""
            foreach ($perm in $userPerms) {
                Write-Host ("{0,$script:KD_LABEL_WIDTH}: {1}" -f "User", $perm.Username)
                if ($perm.Owner) {
                    Write-Host ("{0,$script:KD_LABEL_WIDTH}: {1}" -f "Owner", "Yes")
                }
                else {
                    Write-Host ("{0,$script:KD_LABEL_WIDTH}: {1}" -f "Role", $perm.Role)
                }
                Write-Host ("{0,$script:KD_LABEL_WIDTH}: {1}" -f "Shareable", $(if ($perm.CanEdit -or $perm.Owner) { 'Yes' } else { 'No' }))
                Write-Host ("{0,$script:KD_LABEL_WIDTH}: {1}" -f "Read-Only", $(if (-not $perm.CanEdit -and -not $perm.Owner) { 'Yes' } else { 'No' }))
                Write-Host ""
            }
        }
    }

    if ($objectType -ne 'folder' -and $shareAdminEmails -and $shareAdminEmails.Count -gt 0) {
        $maxShow = 10
        $total = $shareAdminEmails.Count
        Write-Host ""
        if ($total -gt $maxShow) {
            Write-Host ("{0,$script:KD_LABEL_WIDTH}:" -f "Share Admins ($total, showing first $maxShow)")
        }
        else {
            Write-Host ("{0,$script:KD_LABEL_WIDTH}:" -f "Share Admins ($total)")
        }
        $shown = 0
        foreach ($email in $shareAdminEmails) {
            if ($shown -ge $maxShow) { break }
            Write-Host "  $email"
            $shown++
        }
        if ($total -gt $maxShow) {
            Write-Host "  ... and $($total - $maxShow) more"
        }
    }
    elseif ($userPerms.Count -eq 0) {
        Write-Host "No permissions found for this $objectType."
    }
}

function Build-KdRecordFieldsJson {
    Param($fields)

    $result = [System.Collections.ArrayList]::new()
    if (-not $fields) { return $result }

    foreach ($f in $fields) {
        $values = [System.Collections.ArrayList]::new()
        if ($f.Value) {
            foreach ($v in $f.Value) {
                if ($null -eq $v) {
                    $values.Add($null) | Out-Null
                    continue
                }

                if ((Test-KdNsfSecretField -FieldType $f.Type) -and -not (Get-KeeperPasswordVisible)) {
                    $values.Add('********') | Out-Null
                    continue
                }

                if ($v -is [string]) {
                    $parsed = ConvertFrom-KdNsfFieldJson -RawValue $v.Trim()
                    if ($parsed -isnot [string]) {
                        $values.Add($parsed) | Out-Null
                    }
                    else {
                        $values.Add($v) | Out-Null
                    }
                }
                else {
                    $values.Add($v) | Out-Null
                }
            }
        }
        $result.Add([ordered]@{
            type  = $f.Type
            value = @($values)
        }) | Out-Null
    }
    return $result
}

function Build-KdRecordJson {
    Param($vault, $storage, $record, $currentAccountUid)

    $meta = Get-KdRecordTypeAndTitle $record
    $recordType = $meta.Type
    $title = $meta.Title

    $recordAccesses = Get-KdRecordAccesses $vault $storage $record
    $shareAdminEmails = Get-KdRecordShareAdminEmails $vault $record.RecordUid
    $userPerms = Get-KdUserPermissions $vault $recordAccesses $currentAccountUid 'record'
    $permissions = ConvertTo-KdPermissionsJson $userPerms 'record'

    $folderMap = Get-KdFolderNodeMap $vault
    $folderPath = if ($record.FolderUid) { Get-KdFolderPath $vault $record.FolderUid $folderMap } else { '/' }

    return [ordered]@{
        uid            = $record.RecordUid
        type           = $recordType
        title          = $title
        notes          = $record.Notes
        folder         = [ordered]@{
            uid  = $record.FolderUid
            name = $record.FolderName
            path = $folderPath
        }
        fields         = (Build-KdRecordFieldsJson (Get-KdNsfRecordFields $record $storage))
        file_size      = $record.FileSize
        thumbnail_size = $record.ThumbnailSize
        version        = $record.Version
        revision       = $record.Revision
        shared         = [bool]$record.Shared
        permissions    = $permissions
        share_admins   = @($shareAdminEmails)
    }
}

function Get-KdFolderPath {
    Param(
        $vault,
        $folder,
        $folderMap
    )

    if (-not $folderMap) {
        $folderMap = Get-KdFolderNodeMap $vault
    }

    if ($folder -is [string]) {
        $node = if ($folderMap.ContainsKey($folder)) { $folderMap[$folder] } else { $null }
        if ($node) {
            $folder = $node
        }
        elseif ([string]::IsNullOrEmpty($folder)) {
            return '/'
        }
        else {
            return $null
        }
    }

    $components = @()

    $current = if ($folder.ParentUid -and $folderMap.ContainsKey($folder.ParentUid)) {
        $folderMap[$folder.ParentUid]
    }
    else {
        $null
    }

    while ($current) {
        if ($current.Name) {
            $components += $current.Name
        }

        if (-not $current.ParentUid) {
            break
        }

        if ($folderMap.ContainsKey($current.ParentUid)) {
            $current = $folderMap[$current.ParentUid]
        }
        else {
            break
        }
    }

    if ($components.Count -eq 0) {
        return '/'
    }

    [Array]::Reverse($components)
    return '/' + ($components -join '/')
}

function Build-KdFolderJson {
    Param($vault, $storage, $folder, $currentAccountUid)

    $folderAccesses = Get-KdFolderAccesses $vault $storage $folder
    $storedFolder = $storage.KdFolders.GetEntity($folder.FolderUid)
    $ownerAccountUid = if ($storedFolder) { $storedFolder.OwnerAccountUid } else { $null }
    $ownerUsername   = if ($storedFolder) { $storedFolder.OwnerUsername } else { $null }
    $permJson = ConvertTo-KdFolderPermissionsJson $vault $folderAccesses $currentAccountUid $ownerAccountUid $ownerUsername

    $records = [System.Collections.ArrayList]::new()
    foreach ($recordUid in $folder.Records) {
        [KeeperSecurity.Vault.KeeperNSFRecord]$kdRecord = $null
        $recordName = $recordUid
        if ($vault.TryGetKeeperNSFRecord($recordUid, [ref]$kdRecord)) {
            if ($kdRecord.Title) {
                $recordName = $kdRecord.Title
            }
            else {
                $meta = Get-KdRecordTypeAndTitle $kdRecord
                $recordName = $meta.Title
            }
        }
        $records.Add([ordered]@{
            record_uid  = $recordUid
            record_name = $recordName
        }) | Out-Null
    }

    $folderMap = Get-KdFolderNodeMap $vault
    $parentUid = Resolve-KdFolderParentUid $folder.ParentUid $folderMap
    $parentPath = if ($parentUid) {
        Format-KdNsfFolderPath (Get-KdFolderPath $vault $parentUid $folderMap)
    }
    else {
        '/'
    }

    $json = [ordered]@{
        folder_uid = $folder.FolderUid
        type       = 'nested_share_folder'
        name       = $folder.Name
        parent_uid = $parentUid
        folder     = [ordered]@{ uid = $parentUid; path = $parentPath }
        records    = $records
    }
    if ($ownerUsername) {
        $json['owner'] = $ownerUsername
    }
    if ($permJson.user_permissions.Count -gt 0) {
        $json['user_permissions'] = $permJson.user_permissions
    }
    if ($permJson.team_permissions.Count -gt 0) {
        $json['team_permissions'] = $permJson.team_permissions
    }
    if ($permJson.share_admins.Count -gt 0) {
        $json['share_admins'] = $permJson.share_admins
    }
    return $json
}

New-Alias -Name nsf-get -Value Get-KeeperNSFRecord

function Get-KeeperNSFRecordDetails {
    <#
	.Synopsis
	Get record metadata (title, type, version, revision) for one or more Keeper NSF records.

	.Description
	Retrieves and displays record metadata for the specified Keeper NSF records.
	Each identifier may be a record UID or an exact/partial title match.
	Supports output in table or JSON format.

	.Parameter RecordUids
	One or more record UIDs or titles to retrieve metadata for.

	.Parameter Format
	Output format: 'table' (default) or 'json'.
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ValueFromRemainingArguments = $true)]
        [string[]] $RecordUids,

        [Parameter()]
        [ValidateSet('table', 'json')]
        [string] $Format = 'table'
    )
    try {
        [KeeperSecurity.Vault.VaultOnline]$vault = getVault
    } catch {
        Write-Host "Error getting vault: $($_.Exception.Message)" -ForegroundColor Red
        return
    }
    if (-not $RecordUids -or $RecordUids.Count -eq 0) {
        Write-Host 'At least one record UID or title is required.' -ForegroundColor Red
        return
    }

    $resolvedUids = [System.Collections.Generic.List[string]]::new()
    foreach ($uid in $RecordUids) {
        $uid = $uid.Trim()
        if ([string]::IsNullOrEmpty($uid)) { continue }
        $resolved = Resolve-KdNsfRecord -vault $vault -Identifier $uid
        $resolvedUids.Add($(if ($resolved) { $resolved.RecordUid } else { $uid })) | Out-Null
    }

    if ($resolvedUids.Count -eq 0) {
        Write-Host 'At least one record UID or title is required.' -ForegroundColor Red
        return
    }

    try {
        $details = $vault.GetKeeperNSFRecordDetails([string[]]$resolvedUids.ToArray()).GetAwaiter().GetResult()
    }
    catch {
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    if ($Format -eq 'json') {
        $data = foreach ($entry in $details.Data) {
            [ordered]@{
                record_uid = $entry.RecordUid
                title      = $entry.Title
                type       = $entry.Type
                version    = $entry.Version
                revision   = $entry.Revision
            }
        }
        @{
            data              = @($data)
            forbidden_records = @($details.ForbiddenRecords)
        } | ConvertTo-Json -Depth 5
    }
    else {
        foreach ($entry in $details.Data) {
            Write-Host ("{0,$script:KD_LABEL_WIDTH}: {1}" -f "Record UID", $entry.RecordUid)
            Write-Host ("{0,$script:KD_LABEL_WIDTH}: {1}" -f "Title", $entry.Title)
            Write-Host ("{0,$script:KD_LABEL_WIDTH}: {1}" -f "Type", $entry.Type)
            Write-Host ("{0,$script:KD_LABEL_WIDTH}: {1}" -f "Version", $entry.Version)
            Write-Host ("{0,$script:KD_LABEL_WIDTH}: {1}" -f "Revision", $entry.Revision)
            Write-Host ""
        }
        if ($details.ForbiddenRecords.Count -gt 0) {
            Write-Host "Forbidden records: $($details.ForbiddenRecords.Count)" -ForegroundColor Yellow
            foreach ($uid in $details.ForbiddenRecords) {
                Write-Host "  $uid"
            }
        }
        Write-Host "Total records retrieved: $($details.Data.Count)"
    }
}
New-Alias -Name nsf-record-details -Value Get-KeeperNSFRecordDetails
