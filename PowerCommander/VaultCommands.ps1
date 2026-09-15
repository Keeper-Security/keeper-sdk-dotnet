#requires -Version 5.1

. "$PSScriptRoot/ImportSampleData.ps1"

$Script:PathDelimiter = [System.IO.Path]::DirectorySeparatorChar

function getVault {
    if (-not $Script:Context.Auth) {
        Write-Error -Message "Not Connected" -ErrorAction Stop
    }
    if (-not $Script:Context.Vault) {
        Write-Error -Message "Not Connected to Keeper vault. Please login first." -ErrorAction Stop
    }
    $Script:Context.Vault
}

function resolveKeeperNSFFolder {
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

function resolveKeeperNSFRecord {
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

function Get-KeeperLocation {
    <#
	.Synopsis
	Get current Keeper folder
#>
    [CmdletBinding()]

    [KeeperSecurity.Vault.VaultOnline]$vault = getVault

    [string]$currentFolder = $Script:Context.CurrentFolder
    [KeeperSecurity.Vault.FolderNode]$folder = $vault.RootFolder
    if ($currentFolder) {
        $vault.TryGetFolder($currentFolder, [ref]$folder) | Out-Null
    }
    exportKeeperNode $folder
}
New-Alias -Name kpwd -Value Get-KeeperLocation


function Set-KeeperLocation {
    <#
	.Synopsis
	Change current Keeper folder

	.Parameter Path
	New location
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseShouldProcessForStateChangingFunctions", "")]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0)][string] $Path
    )
    [KeeperSecurity.Vault.VaultOnline]$vault = getVault

    if ($Path) {
        [KeeperSecurity.Vault.FolderNode]$folder = $null
        if (!$vault.TryGetFolder($Script:Context.CurrentFolder, [ref]$folder)) {
            $folder = $vault.RootFolder
        }

        $components = splitKeeperPath $Path
        $rs = parseKeeperPath $components $vault $folder
        if ($rs -and !$rs[1]) {
            $folder = $rs[0]
            $uid = $folder.FolderUid
            if ($vault.TryGetFolder($uid, [ref]$folder)) {
                $Script:Context.CurrentFolder = $uid
            }
            else {
                $Script:Context.CurrentFolder = ''
            }
        }
    }
    getVaultFolderPath $vault $Script:Context.CurrentFolder
}

$Keeper_FolderPathRecordCompleter = {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)

    $result = @()
    [KeeperSecurity.Vault.VaultOnline]$vault = $Script:Context.Vault
    if ($vault) {
        [KeeperSecurity.Vault.FolderNode] $folder = $null
        if (!$vault.TryGetFolder($Script:Context.CurrentFolder, [ref]$folder)) {
            $folder = $vault.RootFolder
        }

        $pattern = ''
        $toComplete = $wordToComplete
        if ($toComplete.Length -ge 2) {
            if ($toComplete[0] -eq '''' -and $toComplete[-1] -eq '''') {
                $toComplete = $toComplete.Substring(1, $toComplete.Length - 2)
                $toComplete = $toComplete -replace '''', ''''
            }
        }
        if ($toComplete) {
            $components = splitKeeperPath $toComplete
            if ($components.Count -gt 1) {
                if ($components[-1]) {
                    $pattern = $components[-1]
                    $components[-1] = ''
                }
                $rs = parseKeeperPath $components $vault $folder
                if ($rs -and $rs.Count -eq 2) {
                    if (!$rs[1]) {
                        $folder = $rs[0]
                    }
                    else {
                        $folder = $null
                    }
                }
            }
            else {
                if ($components) {
                    $pattern = $components
                    $components = @('')
                }
                else {
                    $folder = $vault.RootFolder
                    $pattern = ''
                    $components = @('')
                }
            }
        }
        else {
            $components = @('')
            $pattern = $wordToComplete
        }

        if ($folder) {
            $pattern += '*'
            foreach ($uid in $folder.Subfolders) {
                $subfolder = $null
                if ($vault.TryGetFolder($uid, [ref]$subfolder)) {
                    if ($subfolder.Name -like $pattern) {
                        $path = @()
                        $components | ForEach-Object { $path += $_ }
                        $path[-1] = $subfolder.Name
                        $expansion = ($path | ForEach-Object { $_ -replace '\\', '\\' }) -join $Script:PathDelimiter
                        if ($expansion -match '[\s'']') {
                            $expansion = $expansion -replace '''', ''''''
                            $expansion = "'${expansion}'"
                        }
                        $result += $expansion
                    }
                }
            }
        }
    }
    if ($result.Count -gt 0) {
        return $result
    }
    else {
        return $null
    }
}
Register-ArgumentCompleter -CommandName Set-KeeperLocation -ParameterName Path -ScriptBlock $Keeper_FolderPathRecordCompleter
New-Alias -Name kcd -Value Set-KeeperLocation


function Get-KeeperChildItem {
    <#
	.Synopsis
	Get the content of Keeper folder. Output and parameters are similar to Get-ChildItem cmdlet

	.Parameter Path
	Keeper folder

	.Parameter Filter
	Match the string in Title, Uid, Login, and Link fields

	.Parameter Recursive
	Get child items in subfolders recursively

	.Parameter Depth
	Recursion depth

	.Parameter SkipGrouping
	Do not group result set by folder

	.Parameter ObjectType
	Limit result set to Folders or Records only

	.Parameter List
	Display detailed list output

	.Parameter Format
	Output format: table, csv, or json

	.Parameter Output
	Path to output file. If specified, formatted output is written to the file
#>

    [CmdletBinding()]
    Param (
        [Parameter(Position = 0)][string] $Path,
        [string] $Filter,
        [Switch] $Recursive,
        [int] $Depth,
        [Switch] $SkipGrouping,
        [ValidateSet('Folder' , 'Record')][string] $ObjectType,
        [Alias('l')][Switch] $List,
        [ValidateSet('table', 'csv', 'json')][string] $Format,
        [string] $Output
    )

    $showFolder = $true
    $showRecord = $true
    if ($ObjectType) {
        $showFolder = $ObjectType -eq 'Folder'
        $showRecord = !$showFolder
    }

    [KeeperSecurity.Vault.VaultOnline]$vault = getVault
    [KeeperSecurity.Vault.FolderNode] $currentDir = $null
    if (!$vault.TryGetFolder($Script:Context.CurrentFolder, [ref]$currentDir)) {
        $currentDir = $vault.RootFolder
    }

    [KeeperSecurity.Vault.FolderNode] $baseDir = $null
    if ($Path) {
        if (-not $vault.TryGetFolder($Path, [ref]$baseDir)) {
            $components = splitKeeperPath $Path
            $rs = parseKeeperPath $components $vault $currentDir
            if ($rs -is [array]) {
                if (-not $rs[1]) {
                    $baseDir = $rs[0]
                }
            }
        }
    } else {
        $baseDir = $currentDir
    }
    if (-not $baseDir) {
        Write-Error -Message "Cannot find path '$Path'" -ErrorAction Stop            
    }

    [KeeperSecurity.Vault.FolderNode[]]$folders = @($baseDir)
    if ($Recursive.IsPresent) {
        $pos = 0
        $dep = 0
        while ($pos -lt $folders.Count) {
            if ($Depth -gt 0) {
                if ($dep -ge $Depth) {
                    break
                }
            }
            $lastPos = $folders.Count
            for ($i = $pos; $i -lt $lastPos; $i++) {
                foreach ($uid in $folders[$i].Subfolders) {
                    [KeeperSecurity.Vault.FolderNode] $sf = $null;
                    if ($vault.TryGetFolder($uid, [ref]$sf)) {
                        $folders += $sf
                    }
                }
            }
            $pos = $lastPos
            $dep++
        }
    }
    $entries = @()
    $recordEntries = @{}
    for ($i = 0; $i -lt $folders.Count; $i++) {
        [KeeperSecurity.Vault.FolderNode]$f = $folders[$i]
        $path = getVaultFolderPath $vault $f.FolderUid
        if ($showFolder) {
            foreach ($uid in $f.Subfolders) {
                [KeeperSecurity.Vault.FolderNode]$sf = $null
                if ($vault.TryGetFolder($uid, [ref]$sf)) {
                    $match = $true
                    if ($Filter) {
                        $match = @($sf.Name, $sf.FolderUid) | Select-String $Filter | Select-Object -First 1
                    }
                    if ($match) {
                        $entry = [PSCustomObject]@{
                            PSTypeName  = "KeeperSecurity.Commander.FolderEntry$(if ($SkipGrouping.IsPresent) {'Flat'} else {''})"
                            Uid         = $sf.FolderUid
                            Name        = $sf.Name
                            OwnerFolder = $path
                            FolderType  = $sf.FolderType
                            Shared      = $sf.FolderType -ne [KeeperSecurity.Vault.FolderType]::UserFolder
                            SortGroup   = 0
                        }
                        $entries += $entry
                    }
                }
            }
        }
        if ($showRecord) {
            foreach ($uid in $f.Records) {
                [KeeperSecurity.Vault.KeeperRecord] $r = $null
                if ($vault.TryGetKeeperRecord($uid, [ref]$r)) {
                    if ($r.Version -ne 2 -and $r.Version -ne 3) {
                        continue
                    }
                    $match = $true
                    if ($Filter) {
                        $match = @($r.Title, $r.Uid) | Select-String $Filter | Select-Object -First 1
                    }
                    if ($match) {
                        if ($Flat.IsPresent -and $recordEntries.ContainsKey($uid)) {
                            $entry = $recordEntries[$uid]
                            $entry.OwnerFolder += $path
                        }
                        else {
                            $type = [KeeperSecurity.Utils.RecordTypesUtils]::KeeperRecordType($r)
                            $publicInfo = [KeeperSecurity.Utils.RecordTypesUtils]::KeeperRecordPublicInformation($r)
                            $entry = [PSCustomObject]@{
                                PSTypeName        = "KeeperSecurity.Commander.RecordEntry$(if ($SkipGrouping.IsPresent) {'Flat'} else {''})"
                                Uid               = $r.Uid
                                Name              = $r.Title
                                Shared            = $r.Shared
                                Owner             = $r.Owner
                                Type              = $type
                                PublicInformation = $publicInfo
                                HasAttachments    = ($vault.RecordAttachments($r).Count -gt 0)
                                SortGroup         = 1
                            }
                            if ($SkipGrouping.IsPresent) {
                                Add-Member -InputObject $entry -NotePropertyName OwnerFolder -NotePropertyValue @($path)
                            }
                            else {
                                Add-Member -InputObject $entry -NotePropertyName OwnerFolder -NotePropertyValue $path
                            }

                            $recordEntries[$uid] = $entry
                            $entry = $null
                        }
                    }
                }
            }
        }
    }
    if ($recordEntries) {
        $entries += $recordEntries.Values
    }
    if ($entries) {
        $sortedEntries = if ($SkipGrouping.IsPresent) {
            @($entries | Sort-Object SortGroup, Name)
        }
        else {
            @($entries | Sort-Object OwnerFolder, SortGroup, Name)
        }

        $useFormattedOutput = $List.IsPresent -or $PSBoundParameters.ContainsKey('Format') -or $PSBoundParameters.ContainsKey('Output')
        if (-not $useFormattedOutput) {
            $sortedEntries
            return
        }

        $selectedFormat = if ($PSBoundParameters.ContainsKey('Format')) { $Format } else { 'table' }
        $result = foreach ($entry in $sortedEntries) {
            if ($entry.PSTypeNames -contains 'KeeperSecurity.Commander.FolderEntry' -or
                $entry.PSTypeNames -contains 'KeeperSecurity.Commander.FolderEntryFlat') {
                [PSCustomObject][ordered]@{
                    EntryType    = 'Folder'
                    Uid          = $entry.Uid
                    Name         = $(if ($entry.Name) { $entry.Name } else { '' })
                    FolderType   = $entry.FolderType
                    Shared       = $entry.Shared
                    OwnerFolder  = $entry.OwnerFolder
                    RecordType   = ''
                    Description  = ''
                    Owner        = ''
                    HasAttachments = ''
                }
            }
            else {
                [PSCustomObject][ordered]@{
                    EntryType      = 'Record'
                    Uid            = $entry.Uid
                    Name           = $(if ($entry.Name) { $entry.Name } else { '' })
                    FolderType     = ''
                    Shared         = $entry.Shared
                    OwnerFolder    = $entry.OwnerFolder
                    RecordType     = $entry.Type
                    Description    = $entry.PublicInformation
                    Owner          = $entry.Owner
                    HasAttachments = $entry.HasAttachments
                }
            }
        }

        if ($Output) {
            switch ($selectedFormat) {
                'json' { Set-Content -Path $Output -Value ($result | ConvertTo-Json -Depth 5) -Encoding utf8 }
                'csv'  { $result | Export-Csv -Path $Output -NoTypeInformation -Encoding utf8 }
                default { $result | Format-Table -AutoSize | Out-String | Set-Content -Path $Output -Encoding utf8 }
            }
            Write-Host "Output written to $Output"
            return
        }

        switch ($selectedFormat) {
            'json' { $result | ConvertTo-Json -Depth 5 }
            'csv'  { $result | ConvertTo-Csv -NoTypeInformation }
            default { $result | Format-Table -AutoSize }
        }
    }
}
Register-ArgumentCompleter -CommandName Get-KeeperChildItem -ParameterName Path -ScriptBlock $Keeper_FolderPathRecordCompleter
New-Alias -Name kdir -Value Get-KeeperChildItem

function Get-KeeperTree {
    <#
    .Synopsis
    Display the Keeper folder tree.

    .Description
    With -Shares, displays classic shared-folder and direct record permissions.
    With -NsfShares, displays NSF folder and record permissions from the sync cache.
    JSON output is intended for machine-readable integrations.
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0)][string] $Path,
        [Alias('r')][Switch] $Record,
        [Alias('s')][Switch] $Shares,
        [Alias('ns')][Switch] $NsfShares,
        [Alias('v')][Switch] $VerboseOutput,
        [Alias('f')][ValidateSet('table', 'json')][string] $Format = 'table',
        [Alias('hk')][Switch] $HideSharesKey,
        [Alias('t')][string] $Title,
        [string] $Output
    )

    [KeeperSecurity.Vault.VaultOnline]$vault = getVault
    [KeeperSecurity.Vault.FolderNode]$base = $null
    if ($Path -and $vault.TryGetKeeperNSFFolder($Path, [ref]$base)) {
        # NSF UID was supplied directly.
    }
    elseif ($Path -and $vault.TryGetFolder($Path, [ref]$base)) {
        # Classic UID was supplied directly.
    }
    elseif ($Path) {
        $current = $null
        if (!$vault.TryGetFolder($Script:Context.CurrentFolder, [ref]$current)) { $current = $vault.RootFolder }
        $rs = parseKeeperPath (splitKeeperPath $Path) $vault $current
        if ($rs -is [array] -and !$rs[1]) { $base = $rs[0] }
    }
    else {
        $base = $vault.RootFolder
    }
    if (!$base) { Write-Error "Cannot find path '$Path'" -ErrorAction Stop }

    $nsfFolders = @{}
    foreach ($folder in @($vault.KeeperNSFFolderNodes)) { $nsfFolders[$folder.FolderUid] = $folder }
    $nsfRecords = @{}
    foreach ($item in @($vault.KeeperNSFRecordEntries)) { $nsfRecords[$item.RecordUid] = $item }
    $classicRecordUidSet = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($item in @($vault.KeeperRecords)) { [void]$classicRecordUidSet.Add($item.Uid) }

    $classicRecordUids = New-Object 'System.Collections.Generic.HashSet[string]'
    $nsfRecordUids = New-Object 'System.Collections.Generic.HashSet[string]'
    $nsfFolderUids = New-Object 'System.Collections.Generic.HashSet[string]'
    $collectVisited = New-Object 'System.Collections.Generic.HashSet[string]'
    $collectPending = New-Object 'System.Collections.Generic.Stack[object]'
    [void]$collectVisited.Add($(if ($base.FolderUid) { $base.FolderUid } else { '__root__' }))
    [void]$collectPending.Push($base)
    while ($collectPending.Count -gt 0) {
        $folder = $collectPending.Pop()
        if ($NsfShares -and $nsfFolders.ContainsKey($folder.FolderUid)) { [void]$nsfFolderUids.Add($folder.FolderUid) }
        if ($Record) {
            foreach ($uid in @($folder.Records)) {
                if ($NsfShares -and $nsfRecords.ContainsKey($uid)) { [void]$nsfRecordUids.Add($uid) }
                elseif ($Shares -and $classicRecordUidSet.Contains($uid)) { [void]$classicRecordUids.Add($uid) }
            }
        }
        foreach ($uid in @($folder.Subfolders)) {
            $child = $null
            if ($vault.TryGetFolder($uid, [ref]$child) -or $vault.TryGetKeeperNSFFolder($uid, [ref]$child)) {
                $childKey = if ($child.FolderUid) { $child.FolderUid } else { '__root__' }
                if ($collectVisited.Add($childKey)) { [void]$collectPending.Push($child) }
            }
        }
    }
    if ($NsfShares -and [string]::IsNullOrEmpty($base.FolderUid)) {
        foreach ($uid in $nsfFolders.Keys) { [void]$nsfFolderUids.Add($uid) }
        if ($Record) {
            foreach ($uid in $nsfRecords.Keys) { [void]$nsfRecordUids.Add($uid) }
        }
    }

    $classicShares = @{}
    if ($Shares -and $classicRecordUids.Count -gt 0) {
        foreach ($share in @($vault.GetSharesForRecords($classicRecordUids))) { $classicShares[$share.RecordUid] = $share }
    }
    $nsfSharePermissions = $null
    if ($NsfShares) {
        $nsfSharePermissions = $vault.GetKeeperNSFSharePermissions($nsfFolderUids, $nsfRecordUids)
    }

    $resolveName = {
        Param([string]$uid, [int]$accessType)
        if ($accessType -eq 3) {
            $team = $null
            if ($vault.TryGetTeam($uid, [ref]$team)) { return $team.Name }
        }
        if ($accessType -eq 6) {
            [KeeperSecurity.Vault.KeeperRecord]$application = $null
            if ($vault.TryGetKeeperRecord($uid, [ref]$application)) { return $application.Title }
        }
        $username = $null
        if ($vault.TryGetUsername($uid, [ref]$username)) { return $username }
        return $uid
    }
    $nsfPermission = {
        Param([string]$uid, [bool]$recordPermission)
        $entries = if ($recordPermission) { $nsfSharePermissions.RecordPermissions[$uid] } else { $nsfSharePermissions.FolderPermissions[$uid] }
        $users = New-Object 'System.Collections.Generic.List[object]'
        $teams = New-Object 'System.Collections.Generic.List[object]'
        $applications = New-Object 'System.Collections.Generic.List[object]'
        foreach ($entry in @($entries)) {
            $accessor = & $resolveName $entry.AccessTypeUid $entry.AccessType
            $role = if ($entry.Owner) { 'owner' } else { switch ([int]$entry.AccessRoleType) { 2 { 'viewer'; break } 3 { 'share-manager'; break } 4 { 'content-manager'; break } 5 { 'content-share-manager'; break } 6 { 'full-manager'; break } default { 'unresolved' } } }
            $row = [ordered]@{ accessor = $accessor; access_type = $(if ($entry.AccessType -eq 1) { 'AT_OWNER' } elseif ($entry.AccessType -eq 3) { 'AT_TEAM' } elseif ($entry.AccessType -eq 6) { 'AT_APPLICATION' } else { 'AT_USER' }); role = $role; inherited = $entry.Inherited }
            if ($entry.AccessType -eq 3) { [void]$teams.Add([pscustomobject]$row) }
            elseif ($entry.AccessType -eq 6) { [void]$applications.Add([pscustomobject]$row) }
            else { [void]$users.Add([pscustomobject]$row) }
        }
        return [pscustomobject][ordered]@{ user_permissions = @($users); team_permissions = @($teams); application_permissions = @($applications) }
    }
    $nsfRoleCode = {
        Param([string]$role)
        switch ($role) {
            'owner' { 'OW'; break }
            'viewer' { 'VW'; break }
            'share-manager' { 'SM'; break }
            'content-manager' { 'CM'; break }
            'content-share-manager' { 'CSM'; break }
            'full-manager' { 'FM'; break }
            default { $role }
        }
    }
    $classicFolderPermission = {
        Param($folder)
        $sf = $null
        if (!$vault.TryGetSharedFolder($folder.FolderUid, [ref]$sf)) { return $null }
        $users = @($sf.UsersPermissions | Where-Object UserType -eq ([KeeperSecurity.Vault.UserType]::User) | ForEach-Object { [pscustomobject][ordered]@{ accessor = $_.Name; access_type = 'AT_USER'; manage_records = $_.ManageRecords; manage_users = $_.ManageUsers; expiration = $(if ($_.Expiration) { $_.Expiration.ToUnixTimeMilliseconds() } else { 'never' }) } })
        $teams = @($sf.UsersPermissions | Where-Object UserType -eq ([KeeperSecurity.Vault.UserType]::Team) | ForEach-Object { [pscustomobject][ordered]@{ accessor = $_.Name; access_type = 'AT_TEAM'; manage_records = $_.ManageRecords; manage_users = $_.ManageUsers } })
        return [pscustomobject][ordered]@{ user_permissions = $users; team_permissions = $teams }
    }
    $classicRecordPermission = {
        Param($share)
        return [pscustomobject][ordered]@{
            user_permissions = @($share.UserPermissions | ForEach-Object { [pscustomobject][ordered]@{ username = $_.Username; owner = $_.Owner; shareable = $_.CanShare; editable = $_.CanEdit; expiration = $(if ($_.Expiration) { $_.Expiration.ToUnixTimeMilliseconds() } else { $null }) } })
            shared_folder_permissions = @($share.SharedFolderPermissions | ForEach-Object { [pscustomobject][ordered]@{ shared_folder_uid = $_.SharedFolderUid; reshareable = $_.CanShare; editable = $_.CanEdit; expiration = $(if ($_.Expiration) { $_.Expiration.ToUnixTimeMilliseconds() } else { $null }) } })
        }
    }

    # Table output is streamed from the vault graph. Do not create a nested PowerShell object graph:
    # PowerShell 5.1 can retain circular PSCustomObject references and exhaust memory on large vaults.
    if ($Format -ne 'json') {
        $treeWriter = $null
        if ($Output) { $treeWriter = [System.IO.StreamWriter]::new($Output, $false, [System.Text.UTF8Encoding]::new($false)) }
        $writeTreeLine = {
            Param([string]$line)
            if ($treeWriter) { $treeWriter.WriteLine($line) }
            else { Write-Output $line }
        }
        try {
        if (($Shares -or $NsfShares) -and !$HideSharesKey) {
            & $writeTreeLine 'Share Permissions Key:'
            & $writeTreeLine '======================'
            if ($Shares) {
                foreach ($line in @('RO = Read-Only', 'MU = Can Manage Users', 'MR = Can Manage Records', 'CE = Can Edit', 'CS = Can Share', 'OW = Owner')) { & $writeTreeLine $line }
            }
            if ($NsfShares) {
                foreach ($line in @('OW = NSF Owner', 'VW = NSF Viewer', 'SM = NSF Share Manager', 'CM = NSF Content Manager', 'CSM = NSF Content + Share Manager', 'FM = NSF Full Manager')) { & $writeTreeLine $line }
            }
            & $writeTreeLine '======================'
            & $writeTreeLine ''
        }
        if ($Title) { & $writeTreeLine $Title }

        $tableVisited = New-Object 'System.Collections.Generic.HashSet[string]'
        $baseKey = if ($base.FolderUid) { $base.FolderUid } else { '__root__' }
        [void]$tableVisited.Add($baseKey)
        $tablePending = New-Object 'System.Collections.Generic.Stack[object]'
        [void]$tablePending.Push([pscustomobject]@{ Kind = 'folder'; Folder = $base; Prefix = ''; Last = $true })
        while ($tablePending.Count -gt 0) {
            $entry = $tablePending.Pop()
            $prefix = $entry.Prefix
            $last = $entry.Last
            if ($entry.Kind -eq 'record') {
                $label = $entry.Label
            }
            else {
                $folder = $entry.Folder
                $isNsf = $nsfFolders.ContainsKey($folder.FolderUid)
                $label = if ($folder.Name) { [string]$folder.Name } else { 'My Vault' }
                if ($VerboseOutput -and $folder.FolderUid) { $label += " ($($folder.FolderUid))" }
                if ($isNsf) {
                    $label += ' [Nested Share Folder]'
                    if ($NsfShares) {
                        $permissions = & $nsfPermission $folder.FolderUid $false
                        $parts = @()
                        if (@($permissions.user_permissions).Count -gt 0) { $parts += 'users:' + ((@($permissions.user_permissions) | ForEach-Object { "[$($_.accessor):$(& $nsfRoleCode $_.role)]" }) -join ',') }
                        if (@($permissions.team_permissions).Count -gt 0) { $parts += 'teams:' + ((@($permissions.team_permissions) | ForEach-Object { "[$($_.accessor):$(& $nsfRoleCode $_.role)]" }) -join ',') }
                        if (@($permissions.application_permissions).Count -gt 0) { $parts += 'applications:' + ((@($permissions.application_permissions) | ForEach-Object { "[$($_.accessor):$(& $nsfRoleCode $_.role)]" }) -join ',') }
                        if ($parts.Count -gt 0) { $label += ' (' + ($parts -join '; ') + ')' }
                    }
                }
                else {
                    $sharedFolder = $null
                    if ($folder.FolderUid -and $vault.TryGetSharedFolder($folder.FolderUid, [ref]$sharedFolder)) { $label += ' [SHARED]' }
                }
            }
            if ($prefix) { & $writeTreeLine ($prefix + $(if ($last) { '└── ' } else { '├── ' }) + $label) }
            else { & $writeTreeLine $label }

            if ($entry.Kind -eq 'record') { continue }
            $children = New-Object 'System.Collections.Generic.List[object]'
            foreach ($uid in @($entry.Folder.Subfolders)) {
                $child = $null
                if ($vault.TryGetFolder($uid, [ref]$child) -or $vault.TryGetKeeperNSFFolder($uid, [ref]$child)) {
                    $childKey = if ($child.FolderUid) { $child.FolderUid } else { '__root__' }
                    if ($tableVisited.Add($childKey)) { [void]$children.Add([pscustomobject]@{ Kind = 'folder'; Folder = $child; Name = $child.Name }) }
                }
            }
            if ([string]::IsNullOrEmpty($entry.Folder.FolderUid)) {
                foreach ($child in @($vault.KeeperNSFFolderNodes | Where-Object { !$_.ParentUid -or !$nsfFolders.ContainsKey($_.ParentUid) })) {
                    if ($tableVisited.Add($child.FolderUid)) { [void]$children.Add([pscustomobject]@{ Kind = 'folder'; Folder = $child; Name = $child.Name }) }
                }
            }
            if ($Record) {
                foreach ($uid in @($entry.Folder.Records)) {
                    if ($nsfRecords.ContainsKey($uid)) {
                        $record = $nsfRecords[$uid]
                        $recordName = if ($record.Title) { $record.Title } else { $record.RecordUid }
                        $recordLabel = $recordName + ' [' + $record.Type + '] [Nested Record]'
                        if ($VerboseOutput) { $recordLabel += " ($($record.RecordUid))" }
                        [void]$children.Add([pscustomobject]@{ Kind = 'record'; Label = $recordLabel; Name = $record.Title })
                    }
                    else {
                        [KeeperSecurity.Vault.KeeperRecord]$record = $null
                        if ($vault.TryGetKeeperRecord($uid, [ref]$record) -and ($record.Version -eq 2 -or $record.Version -eq 3)) {
                            $recordName = if ($record.Title) { $record.Title } else { $record.Uid }
                            $recordLabel = $recordName + ' [' + [KeeperSecurity.Utils.RecordTypesUtils]::KeeperRecordType($record) + '] [Record]'
                            if ($VerboseOutput) { $recordLabel += " ($($record.Uid))" }
                            [void]$children.Add([pscustomobject]@{ Kind = 'record'; Label = $recordLabel; Name = $record.Title })
                        }
                    }
                }
            }
            $childPrefix = $prefix + $(if ($prefix -and $last) { '    ' } elseif ($prefix) { '│   ' } else { ' ' })
            $orderedChildren = @($children | Sort-Object Name)
            for ($i = $orderedChildren.Count - 1; $i -ge 0; $i--) {
                $childEntry = $orderedChildren[$i]
                $childEntry | Add-Member -NotePropertyName Prefix -NotePropertyValue $childPrefix
                $childEntry | Add-Member -NotePropertyName Last -NotePropertyValue ($i -eq ($orderedChildren.Count - 1))
                [void]$tablePending.Push($childEntry)
            }
        }
        }
        finally {
            if ($treeWriter) { $treeWriter.Dispose() }
        }
        if ($Output) { Write-Host "Output written to $Output" }
        return
    }

    $renderedFolders = New-Object 'System.Collections.Generic.HashSet[string]'
    $setTreeProperty = {
        Param($object, [string]$name, $value)
        if ($object.PSObject.Properties[$name]) { [void]($object.$name = $value) }
        else { Add-Member -InputObject $object -MemberType NoteProperty -Name $name -Value $value }
    }
    $buildPending = New-Object 'System.Collections.Generic.Stack[object]'
    $rootPath = if ($base.FolderUid) { '/' + $base.Name } else { '/' }
    [void]$renderedFolders.Add($(if ($base.FolderUid) { $base.FolderUid } else { '__root__' }))
    [void]$buildPending.Push([pscustomobject]@{ Folder = $base; Path = $rootPath })
    $rootItem = $null
    while ($buildPending.Count -gt 0) {
        $buildEntry = $buildPending.Pop()
        $folder = $buildEntry.Folder
        $nodePath = $buildEntry.Path
        $isNsf = $nsfFolders.ContainsKey($folder.FolderUid)
        $name = if ($folder.Name) { $folder.Name } else { 'My Vault' }
        $itemObject = $buildEntry.Node
        if (!$itemObject) { $itemObject = [pscustomobject][ordered]@{ name = $name; path = $nodePath; kind = $(if ($isNsf) { 'nested_share_folder' } else { 'folder' }) } }
        if (!$isNsf -and $folder.FolderUid) {
            $sharedFolder = $null
            if ($vault.TryGetSharedFolder($folder.FolderUid, [ref]$sharedFolder)) { & $setTreeProperty $itemObject 'shared' $true }
        }
        if ($VerboseOutput -and $folder.FolderUid) { & $setTreeProperty $itemObject 'uid' $folder.FolderUid }
        if ($isNsf -and $NsfShares) { & $setTreeProperty $itemObject 'share_permissions' (& $nsfPermission $folder.FolderUid $false) }
        elseif (!$isNsf -and $Shares) {
            $perm = & $classicFolderPermission $folder
            if ($perm) { & $setTreeProperty $itemObject 'share_permissions' $perm }
        }
        $children = if ($itemObject.children) { $itemObject.children } else { New-Object 'System.Collections.ArrayList' }
        foreach ($uid in @($folder.Subfolders)) {
            $child = $null
            if ($vault.TryGetFolder($uid, [ref]$child) -or $vault.TryGetKeeperNSFFolder($uid, [ref]$child)) {
                $childKey = if ($child.FolderUid) { $child.FolderUid } else { '__root__' }
                if (!$renderedFolders.Add($childKey)) { continue }
                $childItem = [ordered]@{ name = $(if ($child.Name) { $child.Name } else { 'My Vault' }); path = (($nodePath.TrimEnd('/') + '/' + $child.Name).Replace('//', '/')); kind = $(if ($nsfFolders.ContainsKey($child.FolderUid)) { 'nested_share_folder' } else { 'folder' }) }
                if (!$nsfFolders.ContainsKey($child.FolderUid) -and $child.FolderUid) { $childSf = $null; if ($vault.TryGetSharedFolder($child.FolderUid, [ref]$childSf)) { $childItem.shared = $true } }
                if ($VerboseOutput -and $child.FolderUid) { $childItem.uid = $child.FolderUid }
                $childObject = [pscustomobject]$childItem
                [void]$children.Add($childObject)
                [void]$buildPending.Push([pscustomobject]@{ Folder = $child; Node = $childObject; Path = $childItem.path })
            }
        }
        if ([string]::IsNullOrEmpty($folder.FolderUid)) {
            foreach ($child in @($vault.KeeperNSFFolderNodes | Where-Object { !$_.ParentUid -or !$nsfFolders.ContainsKey($_.ParentUid) })) {
                $childKey = if ($child.FolderUid) { $child.FolderUid } else { '__root__' }
                if (!$renderedFolders.Add($childKey)) { continue }
                $childItem = [ordered]@{ name = $child.Name; path = (($nodePath.TrimEnd('/') + '/' + $child.Name).Replace('//', '/')); kind = 'nested_share_folder' }
                if ($VerboseOutput -and $child.FolderUid) { $childItem.uid = $child.FolderUid }
                $childObject = [pscustomobject]$childItem
                [void]$children.Add($childObject)
                [void]$buildPending.Push([pscustomobject]@{ Folder = $child; Node = $childObject; Path = $childItem.path })
            }
        }
        if ($Record) {
            foreach ($uid in @($folder.Records)) {
                if ($nsfRecords.ContainsKey($uid)) {
                    $r = $nsfRecords[$uid]; $recordItem = [ordered]@{ name = $r.Title; path = $nodePath; kind = 'nested_record'; record_type = $r.Type }
                    if ($VerboseOutput) { $recordItem.uid = $r.RecordUid }
                    if ($NsfShares) { $recordItem.share_permissions = & $nsfPermission $r.RecordUid $true }
                    [void]$children.Add([pscustomobject]$recordItem)
                }
                else {
                    [KeeperSecurity.Vault.KeeperRecord]$r = $null
                    if ($vault.TryGetKeeperRecord($uid, [ref]$r) -and ($r.Version -eq 2 -or $r.Version -eq 3)) {
                        $recordItem = [ordered]@{ name = $r.Title; path = $nodePath; kind = 'record'; record_type = [KeeperSecurity.Utils.RecordTypesUtils]::KeeperRecordType($r) }
                        if ($VerboseOutput) { $recordItem.uid = $r.Uid }
                        if ($classicShares.ContainsKey($uid)) { $recordItem.share_permissions = & $classicRecordPermission $classicShares[$uid] }
                        [void]$children.Add([pscustomobject]$recordItem)
                    }
                }
            }
        }
        if ($children.Count -gt 0) { & $setTreeProperty $itemObject 'children' @($children | Sort-Object name) }
        if (!$buildEntry.Node) { $rootItem = $itemObject }
    }
    $tree = [ordered]@{ tree = $rootItem }
    if ($Title) { $tree.title = $Title }
    if (($Shares -or $NsfShares) -and !$HideSharesKey) {
        $key = [ordered]@{}
        if ($Shares) { $key.classic = [ordered]@{ RO = 'Read-Only'; MU = 'Can Manage Users'; MR = 'Can Manage Records'; CE = 'Can Edit'; CS = 'Can Share'; OW = 'Owner' } }
        if ($NsfShares) { $key.nsf = [ordered]@{ OW = 'NSF Owner'; VW = 'NSF Viewer'; SM = 'NSF Share Manager'; CM = 'NSF Content Manager'; CSM = 'NSF Content + Share Manager'; FM = 'NSF Full Manager' } }
        $tree.share_permissions_key = $key
    }
    $stripPending = New-Object 'System.Collections.Generic.Stack[object]'
    [void]$stripPending.Push($tree.tree)
    while ($stripPending.Count -gt 0) {
        $stripNode = $stripPending.Pop()
        if ($stripNode -and $stripNode.PSObject.Properties['shared']) { [void]$stripNode.PSObject.Properties.Remove('shared') }
        foreach ($child in @($stripNode.children)) { [void]$stripPending.Push($child) }
    }
    $json = $tree | ConvertTo-Json -Depth 100
    if ($Output) { Set-Content -Path $Output -Value $json -Encoding UTF8 } else { $json }
}
New-Alias -Name ktree -Value Get-KeeperTree


function Get-KeeperObject {
    <#
	.Synopsis
	Get Keeper object by Uid

	.Parameter Uid
	Keeper UID

	.Parameter ObjectType
	One of the following Record, SharedFolder, Folder, Team

	.Parameter PropertyName
	Return object property not the entire object
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)][string[]] $Uid,
        [string] [ValidateSet('Record' , 'SharedFolder', 'Folder', 'Team')] $ObjectType,
        [string] $PropertyName
    )

    Begin {
        [KeeperSecurity.Vault.VaultOnline]$vault = getVault

        $testRecord = if ($ObjectType) { $ObjectType -eq 'Record' } else { $true }
        $testSharedFolder = if ($ObjectType) { $ObjectType -eq 'SharedFolder' } else { $true }
        $testFolder = if ($ObjectType) { $ObjectType -eq 'Folder' } else { $true }
        $testTeam = if ($ObjectType) { $ObjectType -eq 'Team' } else { $true }
    }
    Process {
        ForEach ($oid in $Uid) {
            if ($testRecord) {
                [KeeperSecurity.Vault.KeeperRecord] $record = $null
                if ($vault.TryGetKeeperRecord($oid, [ref]$record)) {
                    if ($PropertyName) {
                        $mp = $record | Get-Member -MemberType Properties -Name $PropertyName
                        if ($mp) {
                            $record | Select-Object -ExpandProperty $PropertyName
                        }
                    }
                    else {
                        $record
                    }
                    continue
                }
            }
            if ($testSharedFolder) {
                [KeeperSecurity.Vault.SharedFolder] $sf = $null
                if ($vault.TryGetSharedFolder($oid, [ref]$sf)) {
                    if ($PropertyName) {
                        $mp = $sf | Get-Member -MemberType Properties -Name $PropertyName
                        if ($mp) {
                            $sf | Select-Object -ExpandProperty $PropertyName
                        }
                    }
                    else {
                        $sf
                    }
                    continue
                }
            }
            if ($testFolder) {
                [KeeperSecurity.Vault.FolderNode] $f = $null
                if ($vault.TryGetFolder($oid, [ref]$f)) {
                    if ($PropertyName) {
                        $mp = $f | Get-Member -MemberType Properties -Name $PropertyName
                        if ($mp) {
                            $f | Select-Object -ExpandProperty $PropertyName
                        }
                    }
                    else {
                        $f
                    }
                    continue
                }
            }
            if ($testTeam) {
                [KeeperSecurity.Vault.Team] $t = $null
                if ($vault.TryGetTeam($oid, [ref]$t)) {
                    if ($PropertyName) {
                        $mp = $t | Get-Member -MemberType Properties -Name $PropertyName
                        if ($mp) {
                            $t | Select-Object -ExpandProperty $PropertyName
                        }
                    }
                    else {
                        $t
                    }
                    continue
                }
                ensureAvalableLoaded
                [KeeperSecurity.Vault.TeamInfo] $teamInfo = $null
                $teamInfo = $Script:Context.AvailableTeams | Where-Object { $_.TeamUid -ceq $oid } | Select-Object -First 1
                if ($teamInfo) {
                    if ($PropertyName) {
                        $mp = $teamInfo | Get-Member -MemberType Properties -Name $PropertyName
                        if ($mp) {
                            $teamInfo | Select-Object -ExpandProperty $PropertyName
                        }
                    }
                    else {
                        $teamInfo
                    }
                    continue
                }
            }

            if ($testRecord) {
                $nsfRecord = resolveKeeperNSFRecord -Identifier $oid -Vault $vault
                if ($nsfRecord) {
                    if ($PropertyName) {
                        $mp = $nsfRecord | Get-Member -MemberType Properties -Name $PropertyName -ErrorAction SilentlyContinue
                        if ($mp) { $nsfRecord | Select-Object -ExpandProperty $PropertyName }
                    }
                    else { $nsfRecord }
                    continue
                }
            }
            if ($testFolder) {
                $nsfFolder = resolveKeeperNSFFolder -Identifier $oid -Vault $vault
                if ($nsfFolder) {
                    if ($PropertyName) {
                        $mp = $nsfFolder | Get-Member -MemberType Properties -Name $PropertyName -ErrorAction SilentlyContinue
                        if ($mp) { $nsfFolder | Select-Object -ExpandProperty $PropertyName }
                    }
                    else { $nsfFolder }
                    continue
                }
            }
        }
    }
}
New-Alias -Name ko -Value Get-KeeperObject

function parseKeeperPath {
    Param (
        [string[]]$components,
        [KeeperSecurity.Vault.VaultOnline]$vault,
        [KeeperSecurity.Vault.FolderNode]$folder
    )
    if ($components) {
        if (!$components[0]) {
            $folder = $vault.RootFolder
            $_, $components = $components
        }
        while ($components) {
            $resume = $false
            $component, $rest = $components
            if ($component -eq '..') {
                if ($folder.ParentUid) {
                    $resume = $vault.TryGetFolder($folder.ParentUid, [ref]$folder)
                }
                else {
                    $folder = $vault.RootFolder
                    $resume = $true
                }
            }
            elseif (!$component -or $component -eq '.') {
                $resume = $true
            }
            else {
                foreach ($x in $folder.Subfolders) {
                    [KeeperSecurity.Vault.FolderNode] $subfolder = $null
                    if ($vault.TryGetFolder($x, [ref]$subfolder)) {
                        if ($subfolder.Name -eq $component) {
                            $resume = $true
                            $folder = $subfolder
                            break
                        }
                    }
                }
            }

            if ($resume) {
                $components = $rest
            }
            else {
                break
            }
        }
        $folder
        $components -join $Script:PathDelimiter
    }
    else {
        $folder
        $path
    }
}

function splitKeeperPath {
    Param ([string] $path)

    [bool]$isDelimiter = $false
    [string]$component = ''
    foreach ($x in $path.ToCharArray()) {
        if ($x -eq $Script:PathDelimiter) {
            if ($isDelimiter) {
                $component += $x
                $isDelimiter = $false
            }
            else {
                $isDelimiter = $true
            }
        }
        else {
            if ($isDelimiter) {
                $component
                $component = ''
                $isDelimiter = $false
            }
            $component += $x
        }
    }
    $component
    if ($isDelimiter) {
        ''
    }
}

function exportKeeperNode {
    Param ([KeeperSecurity.Vault.FolderNode] $folder)
    [PSCustomObject]@{
        PSTypeName = 'KeeperSecurity.Commander.FolderInfo'
        FolderUid  = $folder.FolderUid
        Path       = getVaultFolderPath $vault $folder.FolderUid
        Name       = $folder.Name
        ParentUid  = $folder.ParentUid
        FolderType = $folder.FolderType
    }
}

function escapePathComponent {
    Param ([string] $component)

    $component = $component -replace '\\', '\\'
    $component = $component -replace '''', ''''''
    if ($component -match '[\s'']') {
        "'${component}'"
    }
    else {
        $component
    }
}

function getVaultFolderPath {
    Param (
        [KeeperSecurity.Vault.VaultOnline]$vault,
        [string] $folderUid
    )

    $comps = @()
    traverseFolderToRoot $vault $folderUid ([ref]$comps)
    $path = ''
    if ($comps) {
        [Array]::Reverse($comps)
        $comps += ''
        $path = ($comps | ForEach-Object { $_ -replace [Regex]::Escape($Script:PathDelimiter), "${Script:PathDelimiter}${Script:PathDelimiter}" }) -join $Script:PathDelimiter
    }
    "${Script:PathDelimiter}${path}"
}

function traverseFolderToRoot ([KeeperSecurity.Vault.VaultOnline]$vault, [string] $folderUid, [ref] $components) {
    if ($folderUid) {
        [KeeperSecurity.Vault.FolderNode]$folder = $null
        if ($vault.TryGetFolder($folderUid, [ref]$folder)) {
            $components.Value += $folder.Name
            traverseFolderToRoot $vault $folder.ParentUid $components
        }
    }
}


function Export-KeeperVault {
    <#
	.Synopsis
	Export vault data to a JSON file

	.Parameter FileName
	JSON export filename (will automatically add .json extension if not present)

	.Parameter Force
	Overwrite existing file without prompting

	.Parameter ExcludeSharedFolders
	Exclude shared folders from export

	.Description
	Exports all vault records and optionally shared folders to a JSON file.
	The JSON format is compatible with Keeper's import functionality.

	.Example
	Export-KeeperVault -FileName "vault_backup"
	Exports vault to "vault_backup.json" and prompts if file exists

	.Example
	Export-KeeperVault -FileName "vault.json" -Force
	Exports vault and overwrites existing file without prompting

	.Example
	Export-KeeperVault -FileName "records_only.json" -ExcludeSharedFolders
	Exports only records, excluding shared folders
#>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $FileName,

        [Parameter(Mandatory = $false)]
        [switch] $Force,

        [Parameter(Mandatory = $false)]
        [switch] $ExcludeSharedFolders
    )

    [KeeperSecurity.Vault.VaultOnline]$vault = getVault

    if (-not $FileName.EndsWith(".json", [StringComparison]::OrdinalIgnoreCase)) {
        $FileName += ".json"
    }

    if ((Test-Path $FileName) -and -not $Force) {
        $response = Read-Host "File `"$FileName`" already exists. Overwrite? (y/n)"
        if ($response -notmatch '^y(es)?$') {
            Write-Host "Export cancelled."
            return
        }
    }

    Write-Host "Exporting vault data..."

    $includeSharedFolders = -not $ExcludeSharedFolders.IsPresent
    $jsonContent = [KeeperSecurity.Vault.KeeperExport]::ExportVaultToJson(
        $vault,
        $null,
        $includeSharedFolders
    )

    $fullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($FileName)
    
    $directory = [System.IO.Path]::GetDirectoryName($fullPath)
    if (-not [string]::IsNullOrEmpty($directory) -and -not (Test-Path $directory)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }
    
    [System.IO.File]::WriteAllText($fullPath, $jsonContent)
    
    Write-Debug "Exported to $fullPath"

    $fileInfo = Get-Item $fullPath

    $recordCount = ($vault.KeeperRecords | Where-Object { $_.Version -eq 2 -or $_.Version -eq 3 }).Count
    $sharedFolderCount = if ($ExcludeSharedFolders) { 0 } else { $vault.SharedFolders.Count }

    Write-Host ""
    Write-Host "Export Summary:"
    Write-Host "    Records Exported: $recordCount"
    if (-not $ExcludeSharedFolders) {
        Write-Host "    Shared Folders: $sharedFolderCount"
    }
    Write-Host "    File Size: $($fileInfo.Length.ToString('N0')) bytes"
    Write-Host "    Output File: $fullPath"
    Write-Host ""
    Write-Host "Export completed successfully." -ForegroundColor Green
}
New-Alias -Name kexport -Value Export-KeeperVault

function Script:ConvertTo-ImportJsonValue {
    <#
    .SYNOPSIS
    Converts PowerShell/ConvertFrom-Json output into KeeperSecurity.Commands.ImportJsonValue
    for KeeperImport.LoadJsonDictionary. (Not for NSF record Fields bags — use ConvertTo-NSFJsonValue.)
    #>
    Param([Parameter(Mandatory = $true)][AllowNull()] $InputObject)

    if ($null -eq $InputObject) {
        return [KeeperSecurity.Commands.ImportJsonValue]::Null
    }

    $base = $InputObject
    if ($InputObject -is [System.Management.Automation.PSObject] -and $null -ne $InputObject.PSObject) {
        $bo = $InputObject.PSObject.BaseObject
        if ($null -ne $bo) { $base = $bo }
    }

    if ($base -is [string]) {
        return [KeeperSecurity.Commands.ImportJsonValue]::FromString([string]$base)
    }

    if ($base -is [bool]) {
        return [KeeperSecurity.Commands.ImportJsonValue]::FromBoolean([bool]$base)
    }

    if ($base -is [byte] -or $base -is [sbyte] -or $base -is [int16] -or $base -is [uint16] -or
        $base -is [int] -or $base -is [uint32] -or $base -is [int64] -or $base -is [uint64] -or
        $base -is [single] -or $base -is [double] -or $base -is [decimal]) {
        # Store as string to avoid double precision loss (e.g. large numeric uids).
        return [KeeperSecurity.Commands.ImportJsonValue]::FromString([string]$base)
    }

    if ($base -is [KeeperSecurity.Commands.ImportJsonValue]) {
        return $base
    }

    if ($base -is [System.Collections.IDictionary]) {
        $ht = New-Object 'System.Collections.Generic.Dictionary[string,KeeperSecurity.Commands.ImportJsonValue]'
        foreach ($key in $base.Keys) {
            $ht[[string]$key] = ConvertTo-ImportJsonValue -InputObject $base[$key]
        }
        return [KeeperSecurity.Commands.ImportJsonValue]::FromObject($ht)
    }

    if ($base -is [System.Collections.IEnumerable]) {
        $list = New-Object 'System.Collections.Generic.List[KeeperSecurity.Commands.ImportJsonValue]'
        foreach ($item in $base) {
            $list.Add((ConvertTo-ImportJsonValue -InputObject $item)) | Out-Null
        }
        return [KeeperSecurity.Commands.ImportJsonValue]::FromArray($list)
    }

    if ($null -ne $InputObject.PSObject -and $InputObject.PSObject.Properties.Count -gt 0) {
        $ht = New-Object 'System.Collections.Generic.Dictionary[string,KeeperSecurity.Commands.ImportJsonValue]'
        foreach ($prop in $InputObject.PSObject.Properties) {
            $ht[$prop.Name] = ConvertTo-ImportJsonValue -InputObject $prop.Value
        }
        return [KeeperSecurity.Commands.ImportJsonValue]::FromObject($ht)
    }

    return [KeeperSecurity.Commands.ImportJsonValue]::FromString([string]$base)
}

function Script:Repair-ImportJsonSingleElementArrays {
    <#
    .SYNOPSIS
    PowerShell unwraps single-element arrays to the element; restore records/shared_folders as arrays.
    #>
    Param(
        [Parameter(Mandatory = $true)]
        [KeeperSecurity.Commands.ImportJsonValue] $JsonValue
    )

    if ($null -eq $JsonValue -or $JsonValue.Kind -ne [KeeperSecurity.Commands.ImportJsonValue+JsonKind]::Object) {
        return $JsonValue
    }

    $changed = $false
    $map = New-Object 'System.Collections.Generic.Dictionary[string,KeeperSecurity.Commands.ImportJsonValue]'
    foreach ($key in $JsonValue.ObjectValue.Keys) {
        $existing = $JsonValue.ObjectValue[$key]
        if (($key -eq 'records' -or $key -eq 'shared_folders') -and
            $null -ne $existing -and
            $existing.Kind -eq [KeeperSecurity.Commands.ImportJsonValue+JsonKind]::Object) {
            $single = New-Object 'System.Collections.Generic.List[KeeperSecurity.Commands.ImportJsonValue]'
            $single.Add($existing) | Out-Null
            $map[$key] = [KeeperSecurity.Commands.ImportJsonValue]::FromArray($single)
            $changed = $true
        }
        else {
            $map[$key] = $existing
        }
    }

    if (-not $changed) {
        return $JsonValue
    }

    return [KeeperSecurity.Commands.ImportJsonValue]::FromObject($map)
}

function Script:Read-KeeperImportFile {
    Param(
        [Parameter(Mandatory = $true)]
        [string] $JsonText
    )

    if ([string]::IsNullOrWhiteSpace($JsonText)) {
        throw "JSON text cannot be empty."
    }

    # ConvertFrom-Json + ImportJsonValue preserves nested custom_fields.
    # JsonUtils.ParseJson / DataContractJsonSerializer turns those into empty System.Object.
    $parsed = $JsonText | ConvertFrom-Json -ErrorAction Stop
    $jsonValue = ConvertTo-ImportJsonValue -InputObject $parsed
    if ($null -eq $jsonValue -or $jsonValue.Kind -ne [KeeperSecurity.Commands.ImportJsonValue+JsonKind]::Object) {
        throw "Import JSON root must be an object."
    }

    $jsonValue = Repair-ImportJsonSingleElementArrays -JsonValue $jsonValue
    return [KeeperSecurity.Vault.KeeperImport]::LoadJsonDictionary($jsonValue)
}

function Import-KeeperVault {
    <#
	.Synopsis
	Import vault data from a JSON file

	.Parameter FileName
	JSON import filename (from Export-KeeperVault or compatible format).
	When used with -DownloadSampleRecords, this is the output path (default: keeper-import-sample.json).

	.Parameter DownloadSampleRecords
	Writes a sample import JSON file to disk and exits without importing.
	The sample uses the same records and shared_folders structure as Export-KeeperVault / kimport.
	Edit the file with your own data, then import with Import-KeeperVault -FileName.

	.Parameter Force
	Proceed without confirming when file is large

	.Description
	Imports records and shared folders from a JSON file into the vault.
	Use a file produced by Export-KeeperVault or the same JSON structure (records, shared_folders).
	Nested custom_fields objects (e.g. $host, $paymentCard) are preserved; the same record JSON
	shape is used by NSF batch create/update (Add-KeeperNSFRecords / Edit-KeeperNSFRecords).

	.Example
	Import-KeeperVault -FileName "vault_backup.json"
	Imports vault data from vault_backup.json

	.Example
	Import-KeeperVault -DownloadSampleRecords
	Writes keeper-import-sample.json in the current directory

	.Example
	Import-KeeperVault -DownloadSampleRecords -FileName "my-import-template.json"
	Writes a sample import file to my-import-template.json

	.Example
	Import-KeeperVault -FileName "restore.json" -Force
	Imports without size confirmation
#>

    [CmdletBinding(DefaultParameterSetName = 'Import')]
    Param (
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'Import')]
        [Parameter(Mandatory = $false, Position = 0, ParameterSetName = 'DownloadSample')]
        [string] $FileName,

        [Parameter(Mandatory = $false, ParameterSetName = 'DownloadSample')]
        [switch] $DownloadSampleRecords,

        [Parameter(Mandatory = $false)]
        [switch] $Force
    )

    if ($DownloadSampleRecords) {
        if (-not $FileName) {
            $FileName = 'keeper-import-sample.json'
        }

        $fullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($FileName)
        $parentDir = Split-Path -Parent $fullPath
        if ($parentDir -and -not (Test-Path -LiteralPath $parentDir)) {
            New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
        }

        $sampleJson = Get-KeeperImportSampleJson
        $utf8NoBom = New-Object System.Text.UTF8Encoding $false
        [System.IO.File]::WriteAllText($fullPath, $sampleJson, $utf8NoBom)

        Write-Host "Sample import file written to: $fullPath" -ForegroundColor Green
        Write-Host "Edit the file with your records and shared folders, then run:"
        Write-Host "    Import-KeeperVault -FileName `"$FileName`""
        return
    }

    if (-not $FileName) {
        Write-Error "FileName is required when -DownloadSampleRecords is not specified."
        return
    }

    [KeeperSecurity.Vault.VaultOnline]$vault = getVault
    if (-not $vault) {
        Write-Error "Not connected to Keeper. Please login first."
        return
    }

    $MaxFileSizeBytes = 50 * 1024 * 1024  # 50 MB

    $fullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($FileName)
    if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
        Write-Error "File `"$fullPath`" not found"
        return
    }

    $fileInfo = Get-Item -LiteralPath $fullPath
    if ($fileInfo.Length -gt $MaxFileSizeBytes -and -not $Force) {
        $maxMB = [math]::Round($MaxFileSizeBytes / (1024 * 1024), 2)
        $sizeMB = [math]::Round($fileInfo.Length / (1024 * 1024), 2)
        $response = Read-Host "File size ($sizeMB MB) exceeds $maxMB MB. Continue? (y/n)"
        if ($response -notmatch '^y(es)?$') {
            Write-Host "Import cancelled."
            return
        }
    }

    try {
        $jsonText = [System.IO.File]::ReadAllText($fullPath, [System.Text.Encoding]::UTF8)
        $importFile = Read-KeeperImportFile -JsonText $jsonText
    }
    catch {
        Write-Error "Error reading or parsing JSON file: $_"
        return
    }

    $recordCount = if ($importFile.Records) { $importFile.Records.Length } else { 0 }
    $sharedFolderCount = if ($importFile.SharedFolders) { $importFile.SharedFolders.Length } else { 0 }

    if ($recordCount -eq 0 -and $sharedFolderCount -eq 0) {
        Write-Error "The import file contains no valid records or shared folders."
        return
    }

    Write-Host "Importing $recordCount record(s), $sharedFolderCount shared folder(s)..."

    try {
        $result = [KeeperSecurity.Vault.KeeperImport]::ImportJson($vault, $importFile).GetAwaiter().GetResult()
        Write-Host ""
        Write-Host "Import Summary:"
        if ($result.SharedFolderCount -gt 0) { Write-Host "    Shared Folders: $($result.SharedFolderCount)" }
        if ($result.FolderCount -gt 0) { Write-Host "    Folders: $($result.FolderCount)" }
        if ($result.LegacyRecordCount -gt 0) { Write-Host "    Legacy Records: $($result.LegacyRecordCount)" }
        if ($result.TypedRecordCount -gt 0) { Write-Host "    Typed Records: $($result.TypedRecordCount)" }
        if ($result.UpdatedRecordCount -gt 0) { Write-Host "    Records Updated: $($result.UpdatedRecordCount)" }
        if ($result.UpdatedFolderCount -gt 0) { Write-Host "    Folders Updated: $($result.UpdatedFolderCount)" }
        if ($result.FolderFailure.Count -gt 0) { Write-Host "    Folder Failures: $($result.FolderFailure.Count)" -ForegroundColor Yellow }
        if ($result.RecordFailure.Count -gt 0) { Write-Host "    Record Failures: $($result.RecordFailure.Count)" -ForegroundColor Yellow }
        if ($result.MembershipFailure.Count -gt 0) { Write-Host "    Membership Failures: $($result.MembershipFailure.Count)" -ForegroundColor Yellow }
        Write-Host ""
        Write-Host "Import completed successfully." -ForegroundColor Green
    }
    catch {
        Write-Error "Import failed: $_"
    }
}
New-Alias -Name kimport -Value Import-KeeperVault
