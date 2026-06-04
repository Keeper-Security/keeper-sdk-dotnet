#requires -Version 5.1
$script:KD_LABEL_WIDTH = 21
$script:KD_FOLDER_LABEL_WIDTH = 25
$script:ShareObjectsCache = $null

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

function Get-AccessRoleLabel {
    Param([int]$roleType)
    if ($script:AccessRoleLabels.ContainsKey($roleType)) {
        return $script:AccessRoleLabels[$roleType]
    }
    return 'unknown'
}

$script:KeeperVaultCategoryClassic = 'Classic'
$script:KeeperVaultCategoryNestedRecord = 'Nested'
$script:KeeperVaultCategoryNestedFolder = 'Nested Shared Folder'

function Test-KeeperNSFFolderByIdentifier {
    Param(
        [Parameter(Mandatory = $true)][string] $Identifier,
        [Parameter(Mandatory = $true)][KeeperSecurity.Vault.VaultOnline] $Vault
    )

    [KeeperSecurity.Vault.FolderNode]$folder = $null
    if ($Vault.TryGetKeeperNSFFolder($Identifier, [ref]$folder)) {
        return $folder
    }

    $match = @($Vault.KeeperNSFFolderNodes | Where-Object { $_.Name -and $_.Name -ieq $Identifier })
    if ($match.Count -eq 1) { return $match[0] }
    return $null
}

function Test-KeeperNSFRecordByIdentifier {
    Param(
        [Parameter(Mandatory = $true)][string] $Identifier,
        [Parameter(Mandatory = $true)][KeeperSecurity.Vault.VaultOnline] $Vault
    )

    [KeeperSecurity.Vault.KeeperNSFRecord]$record = $null
    if ($Vault.TryGetKeeperNSFRecord($Identifier, [ref]$record)) {
        return $record
    }

    $titleMatch = @($Vault.KeeperNSFRecordEntries | Where-Object {
            $_.Title -and $_.Title -ieq $Identifier
        })
    if ($titleMatch.Count -eq 1) { return $titleMatch[0] }

    if ($titleMatch.Count -eq 0 -and $Vault.TryResolveKeeperNSFRecord($Identifier, [ref]$record)) {
        return $record
    }

    return $null
}

function Test-KeeperClassicFolderByIdentifier {
    Param(
        [Parameter(Mandatory = $true)][string] $Identifier,
        [Parameter(Mandatory = $true)][KeeperSecurity.Vault.VaultOnline] $Vault
    )

    [KeeperSecurity.Vault.FolderNode]$folder = $null
    if ($Vault.TryGetFolder($Identifier, [ref]$folder)) {
        return $folder
    }

    $match = @($Vault.Folders | Where-Object {
            -not [string]::IsNullOrEmpty($_.FolderUid) -and $_.Name -and $_.Name -ieq $Identifier
        })
    if ($match.Count -eq 1) { return $match[0] }
    return $null
}

function Test-KeeperClassicRecordByIdentifier {
    Param(
        [Parameter(Mandatory = $true)][string] $Identifier,
        [Parameter(Mandatory = $true)][KeeperSecurity.Vault.VaultOnline] $Vault
    )

    [KeeperSecurity.Vault.KeeperRecord]$record = $null
    if ($Vault.TryGetKeeperRecord($Identifier, [ref]$record)) {
        return $record
    }

    $match = @($Vault.KeeperRecords | Where-Object {
            $_.Title -and $_.Title -ieq $Identifier -and ($_.Version -eq 2 -or $_.Version -eq 3)
        })
    if ($match.Count -eq 1) { return $match[0] }
    return $null
}

function Find-KeeperVaultItemByName {
    Param(
        [Parameter(Mandatory = $true)][string] $Name,
        [Parameter(Mandatory = $true)][KeeperSecurity.Vault.VaultOnline] $Vault,
        [Parameter()][switch] $AllowPartialMatch
    )

    $nsfFolder = Test-KeeperNSFFolderByIdentifier -Identifier $Name -Vault $Vault
    if ($nsfFolder) {
        return [PSCustomObject]@{
            Category      = $script:KeeperVaultCategoryNestedFolder
            ItemType      = 'Folder'
            NsfFolder     = $nsfFolder
        }
    }

    $nsfRecord = Test-KeeperNSFRecordByIdentifier -Identifier $Name -Vault $Vault
    if ($nsfRecord) {
        return [PSCustomObject]@{
            Category      = $script:KeeperVaultCategoryNestedRecord
            ItemType      = 'Record'
            NsfRecord     = $nsfRecord
        }
    }

    $classicFolder = Test-KeeperClassicFolderByIdentifier -Identifier $Name -Vault $Vault
    if ($classicFolder) {
        return [PSCustomObject]@{
            Category      = $script:KeeperVaultCategoryClassic
            ItemType      = 'Folder'
            ClassicFolder = $classicFolder
        }
    }

    $classicRecord = Test-KeeperClassicRecordByIdentifier -Identifier $Name -Vault $Vault
    if ($classicRecord) {
        return [PSCustomObject]@{
            Category      = $script:KeeperVaultCategoryClassic
            ItemType      = 'Record'
            ClassicRecord = $classicRecord
        }
    }

    if (-not $AllowPartialMatch) { return $null }

    $nsfFolderMatches = @($Vault.KeeperNSFFolderNodes | Where-Object { $_.Name -and $_.Name -ilike "*$Name*" })
    if ($nsfFolderMatches.Count -gt 1) {
        Write-Warning "Multiple nested shared folders match '$Name'. Use -Uid or a more specific -Name."
    }
    if ($nsfFolderMatches.Count -ge 1) {
        return [PSCustomObject]@{
            Category  = $script:KeeperVaultCategoryNestedFolder
            ItemType  = 'Folder'
            NsfFolder = $nsfFolderMatches[0]
        }
    }

    $nsfRecordMatches = @($Vault.KeeperNSFRecordEntries | Where-Object {
            ($_.Title -and $_.Title -ilike "*$Name*") -or ($_.RecordUid -ilike "*$Name*")
        })
    if ($nsfRecordMatches.Count -gt 1) {
        Write-Warning "Multiple nested records match '$Name'. Use -Uid or a more specific -Name."
    }
    if ($nsfRecordMatches.Count -ge 1) {
        return [PSCustomObject]@{
            Category   = $script:KeeperVaultCategoryNestedRecord
            ItemType   = 'Record'
            NsfRecord  = $nsfRecordMatches[0]
        }
    }

    $classicFolderMatches = @($Vault.Folders | Where-Object {
            -not [string]::IsNullOrEmpty($_.FolderUid) -and $_.Name -and $_.Name -ilike "*$Name*"
        })
    if ($classicFolderMatches.Count -gt 1) {
        Write-Warning "Multiple classic folders match '$Name'. Use -Uid or a more specific -Name."
    }
    if ($classicFolderMatches.Count -ge 1) {
        return [PSCustomObject]@{
            Category      = $script:KeeperVaultCategoryClassic
            ItemType      = 'Folder'
            ClassicFolder = $classicFolderMatches[0]
        }
    }

    $classicRecordMatches = @($Vault.KeeperRecords | Where-Object {
            $_.Title -and $_.Title -ilike "*$Name*" -and ($_.Version -eq 2 -or $_.Version -eq 3)
        })
    if ($classicRecordMatches.Count -gt 1) {
        Write-Warning "Multiple classic records match '$Name'. Use -Uid or a more specific -Name."
    }
    if ($classicRecordMatches.Count -ge 1) {
        return [PSCustomObject]@{
            Category      = $script:KeeperVaultCategoryClassic
            ItemType      = 'Record'
            ClassicRecord = $classicRecordMatches[0]
        }
    }

    return $null
}

function Get-KeeperVaultAmbiguousNameMessage {
    Param(
        [Parameter(Mandatory = $true)][string] $Name,
        [Parameter(Mandatory = $true)][KeeperSecurity.Vault.VaultOnline] $Vault
    )

    $parts = [System.Collections.ArrayList]::new()

    $nsfFolders = @($Vault.KeeperNSFFolderNodes | Where-Object { $_.Name -and $_.Name -ieq $Name })
    if ($nsfFolders.Count -gt 1) {
        $parts.Add("$($nsfFolders.Count) nested shared folders") | Out-Null
    }

    $nsfRecords = @($Vault.KeeperNSFRecordEntries | Where-Object { $_.Title -and $_.Title -ieq $Name })
    if ($nsfRecords.Count -gt 1) {
        $parts.Add("$($nsfRecords.Count) nested records") | Out-Null
    }

    $classicFolders = @($Vault.Folders | Where-Object {
            -not [string]::IsNullOrEmpty($_.FolderUid) -and $_.Name -and $_.Name -ieq $Name
        })
    if ($classicFolders.Count -gt 1) {
        $parts.Add("$($classicFolders.Count) classic folders") | Out-Null
    }

    $classicRecords = @($Vault.KeeperRecords | Where-Object {
            $_.Title -and $_.Title -ieq $Name -and ($_.Version -eq 2 -or $_.Version -eq 3)
        })
    if ($classicRecords.Count -gt 1) {
        $parts.Add("$($classicRecords.Count) classic records") | Out-Null
    }

    if ($parts.Count -eq 0) { return $null }
    return "Multiple vault items named '$Name' ($($parts -join '; ')). Use -Uid to specify the correct one."
}

function Resolve-KeeperVaultItem {
    Param(
        [Parameter(Mandatory = $true)][KeeperSecurity.Vault.VaultOnline] $Vault,
        [string] $Uid,
        [string] $Name,
        [Parameter()][switch] $AllowPartialMatch
    )

    if ($Uid) {
        $nsfFolder = Test-KeeperNSFFolderByIdentifier -Identifier $Uid -Vault $Vault
        if ($nsfFolder) {
            return [PSCustomObject]@{
                Category  = $script:KeeperVaultCategoryNestedFolder
                ItemType  = 'Folder'
                NsfFolder = $nsfFolder
            }
        }

        $nsfRecord = Test-KeeperNSFRecordByIdentifier -Identifier $Uid -Vault $Vault
        if ($nsfRecord) {
            return [PSCustomObject]@{
                Category   = $script:KeeperVaultCategoryNestedRecord
                ItemType   = 'Record'
                NsfRecord  = $nsfRecord
            }
        }

        $classicFolder = Test-KeeperClassicFolderByIdentifier -Identifier $Uid -Vault $Vault
        if ($classicFolder) {
            return [PSCustomObject]@{
                Category      = $script:KeeperVaultCategoryClassic
                ItemType      = 'Folder'
                ClassicFolder = $classicFolder
            }
        }

        $classicRecord = Test-KeeperClassicRecordByIdentifier -Identifier $Uid -Vault $Vault
        if ($classicRecord) {
            return [PSCustomObject]@{
                Category      = $script:KeeperVaultCategoryClassic
                ItemType      = 'Record'
                ClassicRecord = $classicRecord
            }
        }

        return $null
    }

    if ($Name) {
        return Find-KeeperVaultItemByName -Name $Name -Vault $Vault -AllowPartialMatch:$AllowPartialMatch
    }

    return $null
}

function New-KeeperVaultListRow {
    Param(
        [string] $ItemType,
        [string] $Uid,
        [string] $Title,
        [string] $Type,
        [string] $Category,
        [string] $Description,
        [string] $Parent = ''
    )

    return [PSCustomObject]@{
        ItemType    = $ItemType
        UID         = $Uid
        Title       = $Title
        Type        = $Type
        Category    = $Category
        Description = $Description
        Parent      = $Parent
    }
}

function Get-KdRecordTypeAndTitle {
    Param($record)

    $dataFields = $null
    if ($record -and $record.DecryptedData) {
        try { $dataFields = $record.DecryptedData | ConvertFrom-Json } catch { }
    }

    if ($dataFields -and $dataFields.type) {
        $recordType = $dataFields.type
    }
    elseif ($record -and $record.Type) {
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

    $title = ''
    if ($record -and $record.Title) { $title = $record.Title }
    elseif ($dataFields -and $dataFields.title) { $title = $dataFields.title }
    elseif ($dataFields -and $dataFields.name) { $title = $dataFields.name }

    return [PSCustomObject]@{
        Type   = $recordType
        Title  = $title
        Fields = $dataFields
    }
}

function Get-KeeperNSFFolderList {
    <#
	.Synopsis
	Lists all Keeper NSF folders.

	.Description
	Displays all Keeper NSF folders synced to the vault, including UID, name, parent, and subfolder/record counts.
#>
    [CmdletBinding()]
    Param()

    try{
        [KeeperSecurity.Vault.VaultOnline]$vault = getVault
    } catch {
        Write-Host "Error getting vault: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    $folders = $vault.KeeperNSFFolderNodes
    if (-not $folders) {
        Write-Host "No Keeper NSF folders found."
        return
    }

    $result = [System.Collections.ArrayList]::new()
    foreach ($folder in $folders) {
        $item = [KdFolderListItem]::new()
        $item.FolderUid  = $folder.FolderUid
        $item.Name       = $folder.Name
        $item.ParentUid  = if ($folder.ParentUid) { $folder.ParentUid } else { '(root)' }
        $item.Subfolders = $folder.Subfolders.Count
        $item.Records    = $folder.Records.Count
        $result.Add($item) | Out-Null
    }
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
    Param()

    try{
        [KeeperSecurity.Vault.VaultOnline]$vault = getVault
    } catch {
        Write-Host "Error getting vault: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    $records = $vault.KeeperNSFRecordEntries
    if (-not $records) {
        Write-Host "No Keeper NSF records found."
        return
    }

    $result = [System.Collections.ArrayList]::new()
    foreach ($record in $records) {
        $meta = Get-KdRecordTypeAndTitle $record
        $item = [KdRecordListItem]::new()
        $item.RecordUid    = $record.RecordUid
        $item.Name         = if ($record.Title) { $record.Title } else { $meta.Title }
        $item.Type         = $meta.Type
        $item.Revision     = $record.Revision
        $item.Version      = $record.Version
        $item.Shared       = $record.Shared
        $item.FileSize     = $record.FileSize
        $item.ThumbnailSize = $record.ThumbnailSize
        $result.Add($item) | Out-Null
    }
    $result | Format-Table -AutoSize
}
New-Alias -Name nsf-records -Value Get-KeeperNSFRecordList

function Get-KeeperNSFList {
    <#
	.Synopsis
	Lists classic vault and nested shared folder (NSF) folders and records.

	.Description
	Displays classic and nested shared folder items with a Category column:
	Classic, Nested (records), or Nested Shared Folder (folders).
	Supports table, csv, and json output formats. Use -Folders or -Records to filter.

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

    try{
        [KeeperSecurity.Vault.VaultOnline]$vault = getVault
    } catch {
        Write-Host "Error getting vault: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    $showFolders = -not $Records.IsPresent -or $Folders.IsPresent
    $showRecords = -not $Folders.IsPresent -or $Records.IsPresent

    $combined = [System.Collections.ArrayList]::new()

    if ($showFolders) {
        foreach ($folder in $vault.KeeperNSFFolderNodes) {
            $combined.Add((New-KeeperVaultListRow `
                -ItemType 'Folder' `
                -Uid $folder.FolderUid `
                -Title $(if ($folder.Name) { $folder.Name } else { '' }) `
                -Type 'folder' `
                -Category $script:KeeperVaultCategoryNestedFolder `
                -Description "Subfolders: $($folder.Subfolders.Count), Records: $($folder.Records.Count)" `
                -Parent $(if ($folder.ParentUid) { $folder.ParentUid } else { '(root)' }))) | Out-Null
        }
        foreach ($folder in $vault.Folders) {
            if ([string]::IsNullOrEmpty($folder.FolderUid)) { continue }
            $combined.Add((New-KeeperVaultListRow `
                -ItemType 'Folder' `
                -Uid $folder.FolderUid `
                -Title $(if ($folder.Name) { $folder.Name } else { '' }) `
                -Type ([string]$folder.FolderType) `
                -Category $script:KeeperVaultCategoryClassic `
                -Description "Subfolders: $($folder.Subfolders.Count), Records: $($folder.Records.Count)" `
                -Parent $(if ($folder.ParentUid) { $folder.ParentUid } else { '(root)' }))) | Out-Null
        }
    }

    if ($showRecords) {
        foreach ($record in $vault.KeeperNSFRecordEntries) {
            $meta = Get-KdRecordTypeAndTitle $record
            $combined.Add((New-KeeperVaultListRow `
                -ItemType 'Record' `
                -Uid $record.RecordUid `
                -Title $meta.Title `
                -Type $meta.Type `
                -Category $script:KeeperVaultCategoryNestedRecord `
                -Description "Rev: $($record.Revision), Shared: $($record.Shared)")) | Out-Null
        }
        foreach ($record in $vault.KeeperRecords) {
            if ($record.Version -ne 2 -and $record.Version -ne 3) { continue }
            $recType = [KeeperSecurity.Utils.RecordTypesUtils]::KeeperRecordType($record)
            $combined.Add((New-KeeperVaultListRow `
                -ItemType 'Record' `
                -Uid $record.Uid `
                -Title $(if ($record.Title) { $record.Title } else { '' }) `
                -Type $recType `
                -Category $script:KeeperVaultCategoryClassic `
                -Description "Version: $($record.Version), Shared: $($record.Shared)")) | Out-Null
        }
    }

    if ($combined.Count -eq 0) {
        Write-Host "No vault folders or records found. Run Sync-Keeper to refresh." -ForegroundColor DarkYellow
        return
    }

    if ($Format -eq 'json') {
        $jsonData = $combined | ForEach-Object {
            [ordered]@{
                item_type   = $_.ItemType
                uid         = $_.UID
                title       = $_.Title
                type        = $_.Type
                category    = $_.Category
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
        $csvData = $combined | Select-Object ItemType, UID, Title, Type, Category, Description, Parent
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
    $nestedCount = @($combined | Where-Object {
            $_.Category -eq $script:KeeperVaultCategoryNestedFolder `
                -or $_.Category -eq $script:KeeperVaultCategoryNestedRecord
        }).Count
    $classicCount = @($combined | Where-Object { $_.Category -eq $script:KeeperVaultCategoryClassic }).Count
    $vaultNestedFolders = $vault.KeeperNSFFolderCount
    $vaultNestedRecords = $vault.KeeperNSFRecordCount

    Write-Host ""
    Write-Host "=== Vault Summary (Classic + Nested Shared) ===" -ForegroundColor Cyan
    Write-Host "  Listed folders: $folderCount, records: $recordCount"
    Write-Host "  Listed by category — Classic: $classicCount, Nested: $nestedCount"
    Write-Host "  Nested shared store (KeeperDrive sync) — folders: $vaultNestedFolders, records: $vaultNestedRecords" -ForegroundColor DarkGray
    if ($vaultNestedFolders -eq 0 -and $vaultNestedRecords -eq 0) {
        Write-Host "  Tip: Create nested data with nsf-mkdir / nsf-record-add, then Sync-Keeper." -ForegroundColor DarkYellow
    }
    Write-Host ""

    $tableRows = $combined | Select-Object ItemType, UID, Title, Type, Category, @{
        Name = 'Summary'
        Expression = {
            $d = $_.Description
            if ($d.Length -gt 42) { $d.Substring(0, 39) + '...' } else { $d }
        }
    }, Parent

    if ($showFolders -and $showRecords) {
        $tableRows | Format-Table -AutoSize
    }
    elseif ($showFolders) {
        $tableRows | Where-Object { $_.ItemType -eq 'Folder' } | Format-Table -AutoSize
    }
    else {
        $tableRows | Where-Object { $_.ItemType -eq 'Record' } | Format-Table -AutoSize
    }
    Write-Host "Full Description/Parent: use nsf-list -Format json or -Format csv" -ForegroundColor DarkGray
}
New-Alias -Name nsf-list -Value Get-KeeperNSFList

function Get-KeeperNSFRecord {
    <#
	.Synopsis
	Get detailed information about a classic or nested shared folder/record.

	.Description
	Retrieves metadata, permissions, and share administrators by UID or name.
	Category is Classic, Nested (record), or Nested Shared Folder (folder).
	Similar to Commander's 'nsf-get' command.

	.Parameter Uid
	Record or folder UID to look up.

	.Parameter Name
	Record or folder name to search for (case-insensitive exact match).

	.Parameter Partial
	Allow substring name matching when no exact match is found (first match wins).

	.Parameter Format
	Output format: detail (default) or json.
#>
    [CmdletBinding()]
    Param (
        [string] $Uid,
        [string] $Name,

        [Parameter()]
        [switch] $Partial,

        [Parameter()]
        [ValidateSet('detail', 'json')]
        [string] $Format = 'detail'
    )
    try{
        [KeeperSecurity.Vault.VaultOnline]$vault = getVault
    } catch {
        Write-Host "Error getting vault: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    if (-not $Uid -and -not $Name) {
        Write-Host "Please provide either -Uid or -Name parameter." -ForegroundColor Red
        return
    }

    if ($Uid -and $Name) {
        Write-Warning "Both -Uid and -Name were provided; using -Uid only."
    }

    $storage = $vault.Storage
    $currentAccountUid = [KeeperSecurity.Utils.CryptoUtils]::Base64UrlEncode($vault.Auth.AuthContext.AccountUid)

    $resolved = Resolve-KeeperVaultItem -Vault $vault -Uid $Uid -Name $Name -AllowPartialMatch:$Partial.IsPresent
    if (-not $resolved) {
        if ($Name -and -not $Uid) {
            $ambiguous = Get-KeeperVaultAmbiguousNameMessage -Name $Name -Vault $vault
            if ($ambiguous) {
                Write-Host $ambiguous -ForegroundColor Red
                return
            }
        }
        $id = if ($Uid) { $Uid } else { $Name }
        Write-Host "Vault item with identifier '$id' not found or not accessible." -ForegroundColor Red
        if ($Name -and -not $Partial.IsPresent) {
            Write-Host "Tip: use -Partial for substring name matching, or -Uid from nsf-list." -ForegroundColor DarkYellow
        }
        return
    }

    if ($Format -eq 'json') {
        if ($resolved.NsfRecord) {
            $jsonObj = Build-KdRecordJson $vault $storage $resolved.NsfRecord $currentAccountUid $resolved.Category
        }
        elseif ($resolved.NsfFolder) {
            $jsonObj = Build-KdFolderJson $vault $storage $resolved.NsfFolder $currentAccountUid $resolved.Category
        }
        elseif ($resolved.ClassicRecord) {
            $jsonObj = Build-ClassicRecordJson $resolved.ClassicRecord
        }
        else {
            $jsonObj = Build-ClassicFolderJson $vault $resolved.ClassicFolder
        }
        $jsonObj | ConvertTo-Json -Depth 5
        return
    }

    if ($resolved.NsfRecord) {
        Show-KdRecordDetail $vault $storage $resolved.NsfRecord $currentAccountUid $resolved.Category
    }
    elseif ($resolved.NsfFolder) {
        Show-KdFolderDetail $vault $storage $resolved.NsfFolder $currentAccountUid $resolved.Category
    }
    elseif ($resolved.ClassicRecord) {
        Show-ClassicRecordDetail $resolved.ClassicRecord $resolved.Category
    }
    else {
        Show-ClassicFolderDetail $vault $resolved.ClassicFolder $resolved.Category
    }
}

function Show-ClassicRecordDetail {
    Param(
        [KeeperSecurity.Vault.KeeperRecord] $Record,
        [string] $Category = $script:KeeperVaultCategoryClassic
    )

    $recordType = [KeeperSecurity.Utils.RecordTypesUtils]::KeeperRecordType($Record)
    Write-Host ""
    Write-Host ("{0,$script:KD_LABEL_WIDTH}: {1}" -f "UID", $Record.Uid)
    Write-Host ("{0,$script:KD_LABEL_WIDTH}: {1}" -f "Type", $recordType)
    Write-Host ("{0,$script:KD_LABEL_WIDTH}: {1}" -f "Category", $Category)
    Write-Host ("{0,$script:KD_LABEL_WIDTH}: {1}" -f "Title", $Record.Title)
    Write-Host ("{0,$script:KD_LABEL_WIDTH}: {1}" -f "Version", $Record.Version)
    Write-Host ("{0,$script:KD_LABEL_WIDTH}: {1}" -f "Shared", $(if ($Record.Shared) { 'Yes' } else { 'No' }))
    Write-Host ("{0,$script:KD_LABEL_WIDTH}: {1}" -f "Owner", $(if ($Record.Owner) { 'Yes' } else { 'No' }))
    Write-Host ""
}

function Show-ClassicFolderDetail {
    Param(
        $Vault,
        [KeeperSecurity.Vault.FolderNode] $Folder,
        [string] $Category = $script:KeeperVaultCategoryClassic
    )

    $path = getVaultFolderPath $Vault $Folder.FolderUid
    Write-Host ""
    Write-Host ("{0,$script:KD_LABEL_WIDTH}: {1}" -f "Folder UID", $Folder.FolderUid)
    Write-Host ("{0,$script:KD_LABEL_WIDTH}: {1}" -f "Name", $Folder.Name)
    Write-Host ("{0,$script:KD_LABEL_WIDTH}: {1}" -f "Folder Type", $Folder.FolderType)
    Write-Host ("{0,$script:KD_LABEL_WIDTH}: {1}" -f "Category", $Category)
    if ($Folder.ParentUid) {
        Write-Host ("{0,$script:KD_LABEL_WIDTH}: {1}" -f "Parent Folder UID", $Folder.ParentUid)
    }
    Write-Host ("{0,$script:KD_LABEL_WIDTH}: {1}" -f "Full Path", $path)
    Write-Host ("{0,$script:KD_LABEL_WIDTH}: {1}" -f "Subfolders", $Folder.Subfolders.Count)
    Write-Host ("{0,$script:KD_LABEL_WIDTH}: {1}" -f "Records", $Folder.Records.Count)
    Write-Host ""
}

function Build-ClassicRecordJson {
    Param([KeeperSecurity.Vault.KeeperRecord] $Record)

    return [ordered]@{
        uid      = $Record.Uid
        type     = [KeeperSecurity.Utils.RecordTypesUtils]::KeeperRecordType($Record)
        category = $script:KeeperVaultCategoryClassic
        title    = $Record.Title
        version  = $Record.Version
        shared   = [bool]$Record.Shared
        owner    = [bool]$Record.Owner
    }
}

function Build-ClassicFolderJson {
    Param($Vault, [KeeperSecurity.Vault.FolderNode] $Folder)

    return [ordered]@{
        uid         = $Folder.FolderUid
        name        = $Folder.Name
        folder_type = [string]$Folder.FolderType
        category    = $script:KeeperVaultCategoryClassic
        parent      = if ($Folder.ParentUid) { $Folder.ParentUid } else { $null }
        full_path   = getVaultFolderPath $Vault $Folder.FolderUid
        subfolders  = $Folder.Subfolders.Count
        records     = $Folder.Records.Count
    }
}

function Show-KdRecordDetail {
    Param($vault, $storage, $record, $currentAccountUid, [string] $Category = $script:KeeperVaultCategoryNestedRecord)

    $meta = Get-KdRecordTypeAndTitle $record
    $dataFields = $meta.Fields
    $recordType = $meta.Type
    $title = $meta.Title

    Write-Host ""
    Write-Host ("{0,$script:KD_LABEL_WIDTH}: {1}" -f "UID", $record.RecordUid)
    Write-Host ("{0,$script:KD_LABEL_WIDTH}: {1}" -f "Type", $recordType)
    Write-Host ("{0,$script:KD_LABEL_WIDTH}: {1}" -f "Category", $Category)
    Write-Host ("{0,$script:KD_LABEL_WIDTH}: {1}" -f "Title", $title)

    if ($dataFields -and $dataFields.name -and $dataFields.name -ne $title) {
        Write-Host ("{0,$script:KD_LABEL_WIDTH}: {1}" -f "File Name", $dataFields.name)
    }
    if ($record.FileSize -gt 0) {
        Write-Host ("{0,$script:KD_LABEL_WIDTH}: {1}" -f "File Size", ("{0:N0}" -f $record.FileSize))
    }
    if ($record.ThumbnailSize -gt 0) {
        Write-Host ("{0,$script:KD_LABEL_WIDTH}: {1}" -f "Thumbnail Size", ("{0:N0}" -f $record.ThumbnailSize))
    }

    Write-Host ""

    $recordAccesses = @()
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
            $obj = [PSCustomObject]@{
                AccessTypeUid  = [KeeperSecurity.Utils.CryptoUtils]::Base64UrlEncode($d.AccessTypeUid.ToByteArray())
                AccessType     = [int]$d.AccessType
                AccessRoleType = [int]$d.AccessRoleType
                Owner          = [bool]$d.Owner
                Inherited      = [bool]$d.Inherited
                CanEdit        = [bool]$d.CanEdit
                CanView        = [bool]$d.CanView
                CanDelete      = [bool]$d.CanDelete
                AccessorEmail  = $emailHint
            }
            $converted.Add($obj) | Out-Null
        }
        $recordAccesses = @($converted)
    } catch {
        Write-Verbose "Could not retrieve record access from server: $($_.Exception.Message)"
        $recordAccesses = @($storage.KdRecordAccesses.GetLinksForSubject($record.RecordUid))
    }

    $shareAdminEmails = [System.Collections.ArrayList]::new()
    try {
        $rq = New-Object Enterprise.GetSharingAdminsRequest
        $rq.RecordUid = [Google.Protobuf.ByteString]::CopyFrom([KeeperSecurity.Utils.CryptoUtils]::Base64UrlDecode($record.RecordUid))
        $response = $vault.Auth.ExecuteAuthRest("enterprise/get_sharing_admins", $rq, [Enterprise.GetSharingAdminsResponse]).GetAwaiter().GetResult()
        foreach ($profile in $response.UserProfileExts) {
            if ($profile.Email) { $shareAdminEmails.Add($profile.Email) | Out-Null }
        }
    } catch {
        Write-Verbose "Could not retrieve share admins: $($_.Exception.Message)"
    }

    Show-KdPermissions $vault $recordAccesses $shareAdminEmails $currentAccountUid 'record'

    Write-Host ""
}

function Show-KdFolderDetail {
    Param($vault, $storage, $folder, $currentAccountUid, [string] $Category = $script:KeeperVaultCategoryNestedFolder)

    Write-Host ""
    Write-Host ("{0,$script:KD_FOLDER_LABEL_WIDTH}: {1}" -f "Nested Share Folder UID", $folder.FolderUid)
    Write-Host ("{0,$script:KD_FOLDER_LABEL_WIDTH}: {1}" -f "Name", $folder.Name)
    Write-Host ("{0,$script:KD_FOLDER_LABEL_WIDTH}: {1}" -f "Category", $Category)

    Write-Host ""

    $folderAccesses = @()
    try {
        $rq = New-Object Folder.V3.GetFolderAccessRequest
        $rq.FolderUid.Add([Google.Protobuf.ByteString]::CopyFrom([KeeperSecurity.Utils.CryptoUtils]::Base64UrlDecode($folder.FolderUid)))
        $rs = $vault.Auth.ExecuteAuthRest("vault/folders/v3/access", $rq, [Folder.V3.GetFolderAccessResponse]).GetAwaiter().GetResult()
        foreach ($result in $rs.FolderAccessResults) {
            if ($null -eq $result.Error) {
                $converted = [System.Collections.ArrayList]::new()
                foreach ($a in $result.Accessors) {
                    $obj = [PSCustomObject]@{
                        AccessTypeUid  = [KeeperSecurity.Utils.CryptoUtils]::Base64UrlEncode($a.AccessTypeUid.ToByteArray())
                        AccessType     = [int]$a.AccessType
                        AccessRoleType = [int]$a.AccessRoleType
                    }
                    $converted.Add($obj) | Out-Null
                }
                $folderAccesses = @($converted)
            }
        }
    } catch {
        Write-Verbose "Could not retrieve folder access: $($_.Exception.Message)"
        $folderAccesses = @($storage.KdFolderAccesses.GetLinksForSubject($folder.FolderUid))
    }

    $storedFolder = $storage.KdFolders.GetEntity($folder.FolderUid)
    $ownerAccountUid = if ($storedFolder) { $storedFolder.OwnerAccountUid } else { $null }
    $ownerUsername = if ($storedFolder) { $storedFolder.OwnerUsername } else { $null }

    Show-KdPermissions $vault $folderAccesses @() $currentAccountUid 'folder' $ownerAccountUid $ownerUsername

    Write-Host ""
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

    if (-not $script:ShareObjectsCache) {
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
        } catch {
            $script:ShareObjectsCache = @{}
        }
    }

    if ($script:ShareObjectsCache.ContainsKey($accessTypeUid)) {
        return $script:ShareObjectsCache[$accessTypeUid]
    }

    return $accessTypeUid
}

function Show-KdPermissions {
    Param($vault, $directAccesses, $shareAdminEmails, $currentAccountUid, $objectType, $ownerAccountUid, $ownerUsername)

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
            $isOwner = $false
            if ($ownerAccountUid -and $access.AccessTypeUid -eq $ownerAccountUid) {
                $isOwner = $true
            } elseif ($ownerUsername -and $username -and $username.ToLower() -eq $ownerUsername.ToLower()) {
                $isOwner = $true
            }
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

    if ($userPerms.Count -gt 0) {
        if ($objectType -eq 'folder') {
            Write-Host ("{0,$script:KD_FOLDER_LABEL_WIDTH}:" -f "User Permissions")
            foreach ($perm in $userPerms) {
                $label = if ($perm.Owner) { 'owner' } else { $perm.Role }
                Write-Host ("{0}: {1}" -f $perm.Username, $label)
            }

            $owners = @($userPerms | Where-Object { $_.Owner })
            if ($owners.Count -gt 0) {
                Write-Host ""
                Write-Host ("{0,$script:KD_FOLDER_LABEL_WIDTH}:" -f "Share Administrators")
                foreach ($owner in $owners) {
                    Write-Host ("{0}: owner" -f $owner.Username)
                }
            }
        }
        else {
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

function Build-KdRecordJson {
    Param($vault, $storage, $record, $currentAccountUid, [string] $Category = $script:KeeperVaultCategoryNestedRecord)

    $meta = Get-KdRecordTypeAndTitle $record
    $recordType = $meta.Type
    $title = $meta.Title

    $permissions = [System.Collections.ArrayList]::new()
    $recordAccesses = @($storage.KdRecordAccesses.GetLinksForSubject($record.RecordUid))
    foreach ($access in $recordAccesses) {
        $username = Resolve-KdUsername $vault $access.AccessTypeUid $currentAccountUid
        $permissions.Add([ordered]@{
            username  = $username
            owner     = [bool]$access.Owner
            can_edit  = [bool]$access.CanEdit
            can_view  = [bool]$access.CanView
            can_delete = [bool]$access.CanDelete
        }) | Out-Null
    }

    return [ordered]@{
        uid            = $record.RecordUid
        type           = $recordType
        category       = $Category
        title          = $title
        file_size   = $record.FileSize
        thumbnail_size = $record.ThumbnailSize
        version     = $record.Version
        revision    = $record.Revision
        shared      = [bool]$record.Shared
        permissions = $permissions
    }
}

function Build-KdFolderJson {
    Param($vault, $storage, $folder, $currentAccountUid, [string] $Category = $script:KeeperVaultCategoryNestedFolder)

    $permissions = [System.Collections.ArrayList]::new()
    try {
        $rq = New-Object Folder.V3.GetFolderAccessRequest
        $rq.FolderUid.Add([Google.Protobuf.ByteString]::CopyFrom([KeeperSecurity.Utils.CryptoUtils]::Base64UrlDecode($folder.FolderUid)))
        $rs = $vault.Auth.ExecuteAuthRest("vault/folders/v3/access", $rq, [Folder.V3.GetFolderAccessResponse]).GetAwaiter().GetResult()
        foreach ($result in $rs.FolderAccessResults) {
            if ($null -eq $result.Error) {
                $storedFolder = $storage.KdFolders.GetEntity($folder.FolderUid)
                $ownerAccountUid = if ($storedFolder) { $storedFolder.OwnerAccountUid } else { $null }
                $ownerUsername   = if ($storedFolder) { $storedFolder.OwnerUsername } else { $null }

                foreach ($a in $result.Accessors) {
                    $accessUid = [KeeperSecurity.Utils.CryptoUtils]::Base64UrlEncode($a.AccessTypeUid.ToByteArray())
                    $username = Resolve-KdUsername $vault $accessUid $currentAccountUid
                    $isOwner = $false
                    if ($ownerAccountUid -and $accessUid -eq $ownerAccountUid) { $isOwner = $true }
                    elseif ($ownerUsername -and $username -and $username.ToLower() -eq $ownerUsername.ToLower()) { $isOwner = $true }
                    $permissions.Add([ordered]@{
                        username = $username
                        owner    = $isOwner
                        role     = Get-AccessRoleLabel ([int]$a.AccessRoleType)
                    }) | Out-Null
                }
            }
        }
    } catch { }

    return [ordered]@{
        uid         = $folder.FolderUid
        name        = $folder.Name
        category    = $Category
        parent      = if ($folder.ParentUid) { $folder.ParentUid } else { $null }
        subfolders  = $folder.Subfolders.Count
        records     = $folder.Records.Count
        permissions = $permissions
    }
}

New-Alias -Name nsf-get -Value Get-KeeperNSFRecord

function Get-KeeperNSFRecordDetails {
    <#
	.Synopsis
	Get record metadata (title, type, version, revision) for one or more Keeper NSF records.

	.Description
	Retrieves and displays record metadata for the specified Keeper NSF records.
	Supports output in table or JSON format.

	.Parameter RecordUids
	One or more record UIDs to retrieve details for.

	.Parameter Format
	Output format: 'table' (default) or 'json'.
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromRemainingArguments = $true)]
        [string[]] $RecordUids,

        [Parameter()]
        [ValidateSet('table', 'json')]
        [string] $Format = 'table'
    )
    try{
        [KeeperSecurity.Vault.VaultOnline]$vault = getVault
    } catch {
        Write-Host "Error getting vault: $($_.Exception.Message)" -ForegroundColor Red
        return
    }   
    $results = [System.Collections.ArrayList]::new()
    $forbidden = [System.Collections.ArrayList]::new()

    foreach ($uid in $RecordUids) {
        $uid = $uid.Trim()
        $resolved = $null

        [KeeperSecurity.Vault.KeeperNSFRecord]$tmpRecord = $null
        if ($vault.TryGetKeeperNSFRecord($uid, [ref]$tmpRecord)) {
            $resolved = $tmpRecord
        }
        else {
            foreach ($r in $vault.KeeperNSFRecordEntries) {
                if ($r.Title -and $r.Title -ieq $uid) { $resolved = $r; break }
            }
            if (-not $resolved) {
                foreach ($r in $vault.KeeperNSFRecordEntries) {
                    if ($r.Title -and $r.Title -ilike "*$uid*") { $resolved = $r; break }
                }
            }
        }

        if ($resolved) {
            $meta = Get-KdRecordTypeAndTitle $resolved
            $title = $meta.Title
            $recordType = $meta.Type

            $item = [KdRecordDetailItem]::new()
            $item.RecordUid = $resolved.RecordUid
            $item.Title     = $title
            $item.Type      = $recordType
            $item.Version   = $resolved.Version
            $item.Revision  = $resolved.Revision
            $results.Add($item) | Out-Null
        }
        else {
            $forbidden.Add($uid) | Out-Null
        }
    }

    if ($Format -eq 'json') {
        $output = @{ data = $results }
        if ($forbidden.Count -gt 0) { $output.forbidden_records = $forbidden }
        $output | ConvertTo-Json -Depth 5
    }
    else {
        foreach ($r in $results) {
            Write-Host ("{0,$script:KD_LABEL_WIDTH}: {1}" -f "Record UID", $r.RecordUid)
            Write-Host ("{0,$script:KD_LABEL_WIDTH}: {1}" -f "Title", $r.Title)
            Write-Host ("{0,$script:KD_LABEL_WIDTH}: {1}" -f "Type", $r.Type)
            Write-Host ("{0,$script:KD_LABEL_WIDTH}: {1}" -f "Version", $r.Version)
            Write-Host ("{0,$script:KD_LABEL_WIDTH}: {1}" -f "Revision", $r.Revision)
            Write-Host ""
        }
        if ($forbidden.Count -gt 0) {
            Write-Host "Forbidden records: $($forbidden.Count)" -ForegroundColor Yellow
            foreach ($uid in $forbidden) {
                Write-Host "  $uid"
            }
        }
        Write-Host "Total records retrieved: $($results.Count)"
    }
}
New-Alias -Name nsf-record-details -Value Get-KeeperNSFRecordDetails
