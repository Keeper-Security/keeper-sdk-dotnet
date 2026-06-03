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
        Type   = $recordType
        Title  = $title
        Fields = if ($record) { $record.Fields } else { $null }
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
            $combined.Add(@{
                ItemType    = 'Folder'
                UID         = $folder.FolderUid
                Title       = if ($folder.Name) { $folder.Name } else { '' }
                Type        = 'folder'
                Description = "Subfolders: $($folder.Subfolders.Count), Records: $($folder.Records.Count)"
                Parent      = if ($folder.ParentUid) { $folder.ParentUid } else { '(root)' }
            }) | Out-Null
        }
    }

    if ($showRecords) {
        foreach ($record in $vault.KeeperNSFRecordEntries) {
            $meta = Get-KdRecordTypeAndTitle $record
            $combined.Add(@{
                ItemType    = 'Record'
                UID         = $record.RecordUid
                Title       = $meta.Title
                Type        = $meta.Type
                Description = "Rev: $($record.Revision), Shared: $($record.Shared)"
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
        Get-KeeperNSFFolderList
    }

    if ($showRecords -and $recordCount -gt 0) {
        Write-Host "--- Records ---" -ForegroundColor Yellow
        Get-KeeperNSFRecordList
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
  
    $storage = $vault.Storage
    $currentAccountUid = [KeeperSecurity.Utils.CryptoUtils]::Base64UrlEncode($vault.Auth.AuthContext.AccountUid)

    $kdRecord = $null
    $kdFolder = $null

    if ($Uid) {
        [KeeperSecurity.Vault.FolderNode]$tmpFolder = $null
        if ($vault.TryGetKeeperNSFFolder($Uid, [ref]$tmpFolder)) {
            $kdFolder = $tmpFolder
        }
        else {
            [KeeperSecurity.Vault.KeeperNSFRecord]$tmpRecord = $null
            if ($vault.TryGetKeeperNSFRecord($Uid, [ref]$tmpRecord)) {
                $kdRecord = $tmpRecord
            }
        }
    }
    elseif ($Name) {
        foreach ($f in $vault.KeeperNSFFolderNodes) {
            if ($f.Name -and $f.Name -ieq $Name) { $kdFolder = $f; break }
        }
        if (-not $kdFolder) {
            foreach ($r in $vault.KeeperNSFRecordEntries) {
                if ($r.Title -and $r.Title -ieq $Name) { $kdRecord = $r; break }
            }
        }
        if (-not $kdFolder -and -not $kdRecord) {
            foreach ($f in $vault.KeeperNSFFolderNodes) {
                if ($f.Name -and $f.Name -ilike "*$Name*") { $kdFolder = $f; break }
            }
        }
        if (-not $kdFolder -and -not $kdRecord) {
            foreach ($r in $vault.KeeperNSFRecordEntries) {
                if ($r.Title -and $r.Title -ilike "*$Name*") { $kdRecord = $r; break }
            }
        }
    }

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
        $jsonObj | ConvertTo-Json -Depth 5
        return
    }

    if ($kdRecord) {
        Show-KdRecordDetail $vault $storage $kdRecord $currentAccountUid
    }
    else {
        Show-KdFolderDetail $vault $storage $kdFolder $currentAccountUid
    }
}

function Show-KdRecordDetail {
    Param($vault, $storage, $record, $currentAccountUid)

    $meta = Get-KdRecordTypeAndTitle $record
    $dataFields = $meta.Fields
    $recordType = $meta.Type
    $title = $meta.Title

    Write-Host ""
    Write-Host ("{0,$script:KD_LABEL_WIDTH}: {1}" -f "UID", $record.RecordUid)
    Write-Host ("{0,$script:KD_LABEL_WIDTH}: {1}" -f "Type", $recordType)
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
    Param($vault, $storage, $folder, $currentAccountUid)

    Write-Host ""
    Write-Host ("{0,$script:KD_FOLDER_LABEL_WIDTH}: {1}" -f "Nested Share Folder UID", $folder.FolderUid)
    Write-Host ("{0,$script:KD_FOLDER_LABEL_WIDTH}: {1}" -f "Name", $folder.Name)

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
    Param($vault, $storage, $record, $currentAccountUid)

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
        uid         = $record.RecordUid
        type        = $recordType
        title       = $title
        file_size   = $record.FileSize
        thumbnail_size = $record.ThumbnailSize
        version     = $record.Version
        revision    = $record.Revision
        shared      = [bool]$record.Shared
        permissions = $permissions
    }
}

function Get-KdFolderPath {
    Param(
        $vault,
        $folder
    )

    $components = @()
    $current = $folder
    while ($current) {
        if ($current.Name) {
            $components += $current.Name
        }
        if (-not $current.ParentUid) {
            break
        }
        $current = $vault.KeeperNSFFolderNodes | Where-Object { $_.FolderUid -eq $current.ParentUid } | Select-Object -First 1
    }

    if ($components.Count -eq 0) {
        return '/'
    }

    [Array]::Reverse($components)
    return '/' + ($components -join '/')
}

function Build-KdFolderJson {
    Param($vault, $storage, $folder, $currentAccountUid)

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

    $folderPath = Get-KdFolderPath $vault $folder

    return [ordered]@{
        folder_uid = $folder.FolderUid
        type       = 'nested_share_folder'
        name       = $folder.Name
        parent_uid = if ($folder.ParentUid) { $folder.ParentUid } else { $null }
        folder     = [ordered]@{ uid = $folder.ParentUid; path = $folderPath }
        records    = $records
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
