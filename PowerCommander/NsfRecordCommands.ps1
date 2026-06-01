#requires -Version 5.1

function Add-KeeperNSFRecord {
    <#
	.Synopsis
	Creates a new Keeper NSF record.

	.Description
	Creates a new record in Keeper NSF using the v3 API.
	Supports setting title, type, notes, folder, and field values.

	.Parameter Title
	Title for the new record.

	.Parameter RecordType
	Record type (e.g. login, general). Defaults to 'general'.

	.Parameter FolderUid
	Optional folder UID to place the record in.
 
	.Parameter Notes
	Optional notes for the record.

	.Parameter Fields
	Optional field values as key=value pairs (e.g. login=admin password=secret url=https://example.com).
#>
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $true)]
        [string] $Title,

        [Parameter()]
        [string] $RecordType = 'general',

        [Parameter()]
        [string] $FolderUid,

        [Parameter()]
        [string] $Notes,

        [Parameter(ValueFromRemainingArguments = $true)]
        [string[]] $Fields
    )

    try {
        [KeeperSecurity.Vault.VaultOnline]$vault = getVault
    } catch {
        Write-Host "Error getting vault: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    $fieldDict = $null
    if ($Fields -and $Fields.Count -gt 0) {
        $fieldDict = New-Object 'System.Collections.Generic.Dictionary[string,string]'
        foreach ($f in $Fields) {
            $eqIdx = $f.IndexOf('=')
            if ($eqIdx -gt 0) {
                $key = $f.Substring(0, $eqIdx).Trim()
                $val = $f.Substring($eqIdx + 1).Trim()
                $fieldDict[$key] = $val
            } else {
                Write-Host "Warning: Skipping invalid field '$f'. Expected format: key=value" -ForegroundColor Yellow
            }
        }
    }

    try {
        $recordUid = $vault.CreateKeeperNSFRecord($Title, $RecordType, $FolderUid, $Notes, $fieldDict).GetAwaiter().GetResult()
        Write-Host "Record '$Title' created successfully (UID: $recordUid)." -ForegroundColor Green
        return $recordUid
    }
    catch {
        Write-Host "Error creating record: $($_.Exception.Message)" -ForegroundColor Red
    }
}

New-Alias -Name nsf-record-add -Value Add-KeeperNSFRecord

function Edit-KeeperNSFRecord {
    <#
	.Synopsis
	Updates an existing Keeper NSF record.

	.Description
	Updates the title, type, notes, and/or fields of a Keeper NSF record using the v3 API.
	Only specified parameters are changed; others are preserved.

	.Parameter RecordUid
	UID of the record to update.

	.Parameter Title
	New title for the record.

	.Parameter RecordType
	New record type.

	.Parameter Notes
	New notes for the record.

	.Parameter Fields
	Field values to add or update as key=value pairs (e.g. login=newuser password=newpass).
#>
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $true)]
        [string] $RecordUid,

        [Parameter()]
        [string] $Title,

        [Parameter()]
        [string] $RecordType,

        [Parameter()]
        [string] $Notes,

        [Parameter(ValueFromRemainingArguments = $true)]
        [string[]] $Fields
    )

    $hasTitle = $PSBoundParameters.ContainsKey('Title')
    $hasType  = $PSBoundParameters.ContainsKey('RecordType')
    $hasNotes = $PSBoundParameters.ContainsKey('Notes')
    $hasFields = $Fields -and $Fields.Count -gt 0

    if (-not $hasTitle -and -not $hasType -and -not $hasNotes -and -not $hasFields) {
        Write-Host "Error: At least one of -Title, -RecordType, -Notes, or field values must be specified." -ForegroundColor Red
        return
    }

    try {
        [KeeperSecurity.Vault.VaultOnline]$vault = getVault
    } catch {
        Write-Host "Error getting vault: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    $titleParam = if ($hasTitle) { $Title }      else { [NullString]::Value }
    $typeParam  = if ($hasType)  { $RecordType } else { [NullString]::Value }
    $notesParam = if ($hasNotes) { $Notes }      else { [NullString]::Value }

    $fieldDict = $null
    if ($hasFields) {
        $fieldDict = New-Object 'System.Collections.Generic.Dictionary[string,string]'
        foreach ($f in $Fields) {
            $eqIdx = $f.IndexOf('=')
            if ($eqIdx -gt 0) {
                $key = $f.Substring(0, $eqIdx).Trim()
                $val = $f.Substring($eqIdx + 1).Trim()
                $fieldDict[$key] = $val
            } else {
                Write-Host "Warning: Skipping invalid field '$f'. Expected format: key=value" -ForegroundColor Yellow
            }
        }
    }

    try {
        [void]$vault.UpdateKeeperNSFRecord($RecordUid, $titleParam, $typeParam, $notesParam, $fieldDict).GetAwaiter().GetResult()
        Write-Host "Record '$RecordUid' updated successfully." -ForegroundColor Green
    }
    catch {
        Write-Host "Error updating record: $($_.Exception.Message)" -ForegroundColor Red
    }
}

New-Alias -Name nsf-record-update -Value Edit-KeeperNSFRecord

function Set-KeeperNSFRecordAccess {
    <#
	.Synopsis
	Grant or revoke user access to a Keeper NSF record.

	.Description
	Shares or unshares a Keeper NSF record with a user using the v3 API.
	When granting, encrypts and sends the record key to the recipient.

	.Parameter RecordUid
	UID of the record to share/unshare.

	.Parameter Action
	Action to perform: 'grant' (default) or 'revoke'.

	.Parameter Email
	One or more user email addresses to grant/revoke access.

	.Parameter Role
	Access role for grant action: viewer (default), shared-manager, content-manager,
	content-share-manager, full-manager.
#>
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseShouldProcessForStateChangingFunctions", "")]
    Param (
        [Parameter(Position = 0, Mandatory = $true)]
        [string] $RecordUid,

        [Parameter()]
        [ValidateSet('grant', 'revoke')]
        [string] $Action = 'grant',

        [Parameter(Mandatory = $true)]
        [string[]] $Email,

        [Parameter()]
        [ValidateSet('viewer', 'shared-manager', 'content-manager', 'content-share-manager', 'full-manager')]
        [string] $Role = 'viewer'
    )

    try {
        [KeeperSecurity.Vault.VaultOnline]$vault = getVault
    } catch {
        Write-Host "Error getting vault: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    [KeeperSecurity.Vault.KeeperNSFRecord]$tmpRecord = $null
    if (-not $vault.TryGetKeeperNSFRecord($RecordUid, [ref]$tmpRecord)) {
        Write-Host "Error: NSF record '$RecordUid' not found." -ForegroundColor Red
        return
    }

    foreach ($user in $Email) {
        try {
            if ($Action -eq 'grant') {
                [void]$vault.ShareKeeperNSFRecord($RecordUid, $user, $Role).GetAwaiter().GetResult()
                Write-Host "Granted '$Role' access to '$user' on record '$RecordUid'." -ForegroundColor Green
            }
            else {
                [void]$vault.UnshareKeeperNSFRecord($RecordUid, $user).GetAwaiter().GetResult()
                Write-Host "Revoked access for '$user' from record '$RecordUid'." -ForegroundColor Green
            }
        }
        catch {
            Write-Host "Error ${Action}ing access for '$user': $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

New-Alias -Name nsf-share-record -Value Set-KeeperNSFRecordAccess

function Set-KeeperNSFRecordPermission {
    <#
	.Synopsis
	Bulk grant or revoke record-level sharing permissions for records in a Keeper NSF folder.

	.Description
	Modifies sharing permissions on all records within a Keeper NSF folder using the v3 API.
	Fetches current access permissions, computes required changes, displays a plan, and
	executes the changes after confirmation.

	.Parameter FolderUid
	Folder UID or name containing the records. If omitted, operates on root-level records.

	.Parameter Action
	Action to perform: 'grant' or 'revoke'.

	.Parameter Role
	Access role: viewer, shared-manager, content-manager, content-share-manager, full-manager.
	Required for grant action. For revoke, if specified, only revokes users with that role.

	.Parameter Recursive
	If specified, includes records in subfolders.

	.Parameter Force
	Skip confirmation prompt.

	.Parameter DryRun
	Show what would change without making modifications.
#>
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseShouldProcessForStateChangingFunctions", "")]
    Param (
        [Parameter(Position = 0)]
        [string] $FolderUid,

        [Parameter(Mandatory = $true)]
        [ValidateSet('grant', 'revoke')]
        [string] $Action,

        [Parameter()]
        [ValidateSet('viewer', 'shared-manager', 'content-manager', 'content-share-manager', 'full-manager')]
        [string] $Role,

        [Parameter()]
        [switch] $Recursive,

        [Parameter()]
        [switch] $Force,

        [Parameter()]
        [switch] $DryRun
    )

    if ($Action -eq 'grant' -and -not $Role) {
        Write-Host "Error: -Role is required for grant action." -ForegroundColor Red
        return
    }

    try {
        [KeeperSecurity.Vault.VaultOnline]$vault = getVault
    } catch {
        Write-Host "Error getting vault: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    if ($FolderUid) {
        [KeeperSecurity.Vault.FolderNode]$tmpFolder = $null
        if (-not $vault.TryGetKeeperNSFFolder($FolderUid, [ref]$tmpFolder)) {
            foreach ($f in $vault.KeeperNSFFolderNodes) {
                if ($f.Name -and $f.Name -ieq $FolderUid) { $FolderUid = $f.FolderUid; break }
            }
        }
    }

    $folderDisplay = if ($FolderUid) { $FolderUid } else { 'root' }
    $roleLabel = if ($Role) { "'$Role'" } else { 'all' }
    $scopeLabel = if ($Recursive.IsPresent) { 'recursively' } else { 'only' }
    Write-Host ""
    Write-Host "Request to $($Action.ToUpper()) $roleLabel permission(s) in '$folderDisplay' folder $scopeLabel" -ForegroundColor Cyan

    try {
        $permResult = $vault.UpdateKeeperNSFRecordPermissions($FolderUid, $Action, $Role, $Recursive.IsPresent, $true).GetAwaiter().GetResult()
    }
    catch {
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    $hasChanges = ($permResult.Grants.Count -gt 0) -or ($permResult.Revokes.Count -gt 0)

    if ($permResult.Skipped.Count -gt 0) {
        Write-Host ""
        Write-Host "  SKIPPED ($($permResult.Skipped.Count)):" -ForegroundColor Yellow
        foreach ($s in $permResult.Skipped) {
            $email = if ($s.Email) { $s.Email } else { '-' }
            $curRole = if ($s.CurrentRole) { $s.CurrentRole } else { '-' }
            Write-Host "    $($s.RecordUid)  $email  [$curRole]  $($s.Message)"
        }
    }

    if ($permResult.Grants.Count -gt 0) {
        Write-Host ""
        Write-Host "  PLANNED GRANTS ($($permResult.Grants.Count)):" -ForegroundColor Green
        foreach ($g in $permResult.Grants) {
            $inherited = if ($g.ChangeType -eq 'create') { ' (inherited override)' } else { '' }
            Write-Host "    $($g.RecordUid)  $($g.Email)  $($g.CurrentRole) -> $($g.NewRole)$inherited"
        }
    }

    if ($permResult.Revokes.Count -gt 0) {
        Write-Host ""
        Write-Host "  PLANNED REVOKES ($($permResult.Revokes.Count)):" -ForegroundColor Red
        foreach ($r in $permResult.Revokes) {
            Write-Host "    $($r.RecordUid)  $($r.Email)  [$($r.CurrentRole)]"
        }
    }

    if (-not $hasChanges -and $permResult.Skipped.Count -eq 0) {
        Write-Host "No permission changes are needed." -ForegroundColor DarkYellow
        return
    }

    if ($DryRun.IsPresent) {
        Write-Host ""
        Write-Host "[Dry-run mode - no changes were made]" -ForegroundColor Yellow
        $planTotal = $permResult.Grants.Count + $permResult.Revokes.Count
        Write-Host "Summary: $planTotal planned, $($permResult.Skipped.Count) skipped" -ForegroundColor Cyan
        return
    }

    if (-not $hasChanges) {
        Write-Host ""
        Write-Host "Summary: 0 changes, $($permResult.Skipped.Count) skipped" -ForegroundColor Cyan
        return
    }

    if (-not $Force) {
        $confirmation = Read-Host "Are you sure you want to apply the above changes? (yes/No)"
        if ($confirmation -notmatch '^(y|yes)$') {
            Write-Host "Update operation cancelled"
            return
        }
    }

    try {
        $permResult = $vault.UpdateKeeperNSFRecordPermissions($FolderUid, $Action, $Role, $Recursive.IsPresent, $false).GetAwaiter().GetResult()
    }
    catch {
        Write-Host "Error executing changes: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    if ($permResult.Grants.Count -gt 0) {
        Write-Host ""
        Write-Host "  GRANT ($($permResult.Grants.Count)):" -ForegroundColor Green
        foreach ($g in $permResult.Grants) {
            $statusIcon = if ($g.Success) { '[OK]' } else { '[FAIL]' }
            $statusColor = if ($g.Success) { 'Green' } else { 'Red' }
            $inherited = if ($g.ChangeType -eq 'create') { ' (inherited override)' } else { '' }
            Write-Host "    $statusIcon $($g.RecordUid)  $($g.Email)  $($g.CurrentRole) -> $($g.NewRole)$inherited" -ForegroundColor $statusColor
            if (-not $g.Success -and $g.Message) {
                Write-Host "         Error: $($g.Message)" -ForegroundColor Red
            }
        }
    }

    if ($permResult.Revokes.Count -gt 0) {
        Write-Host ""
        Write-Host "  REVOKE ($($permResult.Revokes.Count)):" -ForegroundColor Red
        foreach ($r in $permResult.Revokes) {
            $statusIcon = if ($r.Success) { '[OK]' } else { '[FAIL]' }
            $statusColor = if ($r.Success) { 'Green' } else { 'Red' }
            Write-Host "    $statusIcon $($r.RecordUid)  $($r.Email)  [$($r.CurrentRole)]" -ForegroundColor $statusColor
            if (-not $r.Success -and $r.Message) {
                Write-Host "         Error: $($r.Message)" -ForegroundColor Red
            }
        }
    }

    $successCount = ($permResult.Grants | Where-Object { $_.Success }).Count + ($permResult.Revokes | Where-Object { $_.Success }).Count
    $failCount = ($permResult.Grants | Where-Object { -not $_.Success }).Count + ($permResult.Revokes | Where-Object { -not $_.Success }).Count
    Write-Host ""
    Write-Host "Summary: $successCount succeeded, $failCount failed, $($permResult.Skipped.Count) skipped" -ForegroundColor Cyan
}

New-Alias -Name nsf-record-permission -Value Set-KeeperNSFRecordPermission

function Get-KeeperNSFShortcut {
    <#
	.Synopsis
	Lists Keeper NSF records that appear in more than one folder (shortcuts).

	.Description
	Scans all Keeper NSF folder-record links and reports records that exist
	in two or more folders. Optionally filters by a specific record UID/title
	or folder UID/name.

	.Parameter Target
	Optional record UID, record title, folder UID, or folder name to filter results.

	.Parameter Format
	Output format: table (default), csv, or json.

	.Parameter Output
	Path to output file. Ignored for table format.
#>
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0)]
        [string] $Target,

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

    $recordUid = $null
    $folderUid = $null

    if ($Target) {
        [KeeperSecurity.Vault.KeeperNSFRecord]$tmpRecord = $null
        if ($vault.TryGetKeeperNSFRecord($Target, [ref]$tmpRecord)) {
            $recordUid = $Target
        } else {
            [KeeperSecurity.Vault.FolderNode]$tmpFolder = $null
            if ($vault.TryGetKeeperNSFFolder($Target, [ref]$tmpFolder)) {
                $folderUid = $Target
            } else {
                $foundByTitle = $false
                foreach ($r in $vault.KeeperNSFRecordEntries) {
                    if ($r.Title -and $r.Title -ieq $Target) {
                        $recordUid = $r.RecordUid
                        $foundByTitle = $true
                        break
                    }
                }
                if (-not $foundByTitle) {
                    foreach ($f in $vault.KeeperNSFFolderNodes) {
                        if ($f.Name -and $f.Name -ieq $Target) {
                            $folderUid = $f.FolderUid
                            $foundByTitle = $true
                            break
                        }
                    }
                }
                if (-not $foundByTitle) {
                    Write-Host "Error: Target '$Target' not found as record UID, title, folder UID, or folder name." -ForegroundColor Red
                    return
                }
            }
        }
    }

    try {
        $entries = $vault.GetKeeperNSFShortcuts($recordUid, $folderUid)
    } catch {
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    if ($entries.Count -eq 0) {
        Write-Host "No shortcut records found." -ForegroundColor DarkYellow
        return
    }

    if ($Format -eq 'json') {
        $jsonItems = @()
        foreach ($e in $entries) {
            $folders = @()
            foreach ($f in $e.Folders) {
                $folders += [ordered]@{ folder_uid = $f.FolderUid; name = $f.Name }
            }
            $jsonItems += [ordered]@{
                record_uid   = $e.RecordUid
                record_title = $e.Title
                folders      = $folders
            }
        }
        $jsonText = $jsonItems | ConvertTo-Json -Depth 4
        if ($Output) {
            $jsonText | Out-File -FilePath $Output -Encoding utf8
            Write-Host "JSON output written to '$Output' ($($entries.Count) shortcuts)." -ForegroundColor Green
        } else {
            $jsonText
        }
        return
    }

    if ($Format -eq 'csv') {
        $csvData = @()
        foreach ($e in $entries) {
            $folderNames = ($e.Folders | ForEach-Object { $_.Name }) -join '; '
            $folderUids  = ($e.Folders | ForEach-Object { $_.FolderUid }) -join '; '
            $csvData += [PSCustomObject]@{
                RecordUid   = $e.RecordUid
                Title       = $e.Title
                FolderCount = $e.Folders.Count
                FolderUids  = $folderUids
                FolderNames = $folderNames
            }
        }
        if ($Output) {
            $csvData | Export-Csv -Path $Output -NoTypeInformation -Encoding utf8
            Write-Host "CSV output written to '$Output' ($($entries.Count) shortcuts)." -ForegroundColor Green
        } else {
            $csvData | ConvertTo-Csv -NoTypeInformation
        }
        return
    }

    Write-Host ""
    Write-Host "  Shortcut Records ($($entries.Count)):" -ForegroundColor Cyan
    Write-Host ""
    foreach ($e in $entries) {
        Write-Host "  $($e.RecordUid)  $($e.Title)  [$($e.Folders.Count) folders]" -ForegroundColor White
        foreach ($f in $e.Folders) {
            Write-Host "    - $($f.Name) ($($f.FolderUid))"
        }
    }
    Write-Host ""
}

New-Alias -Name nsf-shortcut-list -Value Get-KeeperNSFShortcut

function Set-KeeperNSFShortcutKeep {
    <#
	.Synopsis
	Keep a Keeper NSF record in one folder and remove it from all others.

	.Description
	For a record that appears in multiple Keeper NSF folders (a shortcut),
	keeps it in the specified folder and unlinks it from all other folders.

	.Parameter RecordUid
	Record UID or title of the record.

	.Parameter FolderUid
	Folder UID or folder name to keep the record in.

	.Parameter Force
	Skip confirmation prompt.
#>
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseShouldProcessForStateChangingFunctions", "")]
    Param (
        [Parameter(Position = 0, Mandatory = $true)]
        [string] $RecordUid,

        [Parameter(Position = 1, Mandatory = $true)]
        [string] $FolderUid,

        [Parameter()]
        [switch] $Force
    )

    try {
        [KeeperSecurity.Vault.VaultOnline]$vault = getVault
    } catch {
        Write-Host "Error getting vault: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    [KeeperSecurity.Vault.KeeperNSFRecord]$tmpRecord = $null
    if (-not $vault.TryGetKeeperNSFRecord($RecordUid, [ref]$tmpRecord)) {
        $found = $false
        foreach ($r in $vault.KeeperNSFRecordEntries) {
            if ($r.Title -and $r.Title -ieq $RecordUid) {
                $RecordUid = $r.RecordUid
                $found = $true
                break
            }
        }
        if (-not $found) {
            Write-Host "Error: Record '$RecordUid' not found." -ForegroundColor Red
            return
        }
    }

    [KeeperSecurity.Vault.FolderNode]$tmpFolder = $null
    if (-not $vault.TryGetKeeperNSFFolder($FolderUid, [ref]$tmpFolder)) {
        $found = $false
        foreach ($f in $vault.KeeperNSFFolderNodes) {
            if ($f.Name -and $f.Name -ieq $FolderUid) {
                $FolderUid = $f.FolderUid
                $found = $true
                break
            }
        }
        if (-not $found) {
            Write-Host "Error: Folder '$FolderUid' not found." -ForegroundColor Red
            return
        }
    }

    $shortcuts = $vault.GetKeeperNSFShortcuts($RecordUid, $null)
    if ($shortcuts.Count -eq 0) {
        Write-Host "Record '$RecordUid' does not appear in multiple folders." -ForegroundColor DarkYellow
        return
    }

    $entry = $shortcuts[0]
    $keepFolder = $entry.Folders | Where-Object { $_.FolderUid -eq $FolderUid }
    if (-not $keepFolder) {
        Write-Host "Error: Record '$RecordUid' is not in folder '$FolderUid'." -ForegroundColor Red
        return
    }

    $removeFolders = $entry.Folders | Where-Object { $_.FolderUid -ne $FolderUid }

    if (-not $Force) {
        Write-Host ""
        Write-Host "  Will remove record '$($entry.Title)' ($RecordUid) from:" -ForegroundColor Yellow
        foreach ($rf in $removeFolders) {
            Write-Host "    - $($rf.Name) ($($rf.FolderUid))"
        }
        Write-Host "  Keeping in: $($keepFolder.Name) ($($keepFolder.FolderUid))" -ForegroundColor Green
        Write-Host ""
        $confirmation = Read-Host "Are you sure you want to keep the record only in '$($keepFolder.Name)' and remove it from the other folder(s) above? (yes/No)"
        if ($confirmation -notmatch '^(y|yes)$') {
            Write-Host "Shortcut-keep operation cancelled"
            return
        }
    }

    try {
        $result = $vault.KeepKeeperNSFRecordInFolder($RecordUid, $FolderUid).GetAwaiter().GetResult()
    } catch {
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    $successCount = ($result.Removals | Where-Object { $_.Success }).Count
    $failCount = ($result.Removals | Where-Object { -not $_.Success }).Count

    foreach ($removal in $result.Removals) {
        if ($removal.Success) {
            Write-Host "  [OK] Removed from '$($removal.FolderName)' ($($removal.FolderUid))" -ForegroundColor Green
        } else {
            Write-Host "  [FAIL] '$($removal.FolderName)' ($($removal.FolderUid)): $($removal.Message)" -ForegroundColor Red
        }
    }

    Write-Host ""
    Write-Host "Record kept in '$($result.KeptFolderName)'. $successCount removed, $failCount failed." -ForegroundColor Cyan
}

New-Alias -Name nsf-shortcut-keep -Value Set-KeeperNSFShortcutKeep

# --- NSF record mutations (sdk-396) ---
function Remove-KeeperNSFRecord {
    <#
	.Synopsis
	Removes one or more Keeper NSF records (Keeper NSF v3 API).

	.Parameter Record
	One or more record UIDs or titles.

	.Parameter Folder
	Folder UID or name that provides context (required for unlink).

	.Parameter Operation
	Removal operation: owner-trash, folder-trash, or unlink.

	.Parameter Force
	Skip confirmation after preview.

	.Parameter DryRun
	Preview only; do not remove records.
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseShouldProcessForStateChangingFunctions", "")]
    [CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Default')]
    Param(
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true)]
        [string[]] $Record,

        [string] $Folder,

        [Alias('o')]
        [ValidateSet('owner-trash', 'folder-trash', 'unlink')]
        [string] $Operation = 'owner-trash',

        [Alias('f')]
        [switch] $Force,

        [switch] $DryRun
    )

    begin {
        [KeeperSecurity.Vault.VaultOnline]$vault = getVault
        $removals = New-Object 'System.Collections.Generic.List[KeeperSecurity.Vault.KeeperNSFRecordRemoval]'
        $resolvedFolderUid = $null

        if ($Folder) {
            [KeeperSecurity.Vault.FolderNode]$folderNode = $null
            if (-not $vault.TryResolveKeeperNSFFolder($Folder, [ref]$folderNode)) {
                Write-Error -Message "Keeper NSF folder `"$Folder`" was not found. Run Sync-Keeper or nsf-list first."
                return
            }
            $resolvedFolderUid = $folderNode.FolderUid
        }
        elseif ($Script:Context.CurrentFolder) {
            [KeeperSecurity.Vault.FolderNode]$currentFolder = $null
            if ($vault.TryResolveKeeperNSFFolder($Script:Context.CurrentFolder, [ref]$currentFolder)) {
                $resolvedFolderUid = $currentFolder.FolderUid
            }
        }

        $op = switch ($Operation) {
            'owner-trash' { [KeeperSecurity.Vault.KeeperNSFRecordRemoveOperation]::OwnerTrash }
            'folder-trash' { [KeeperSecurity.Vault.KeeperNSFRecordRemoveOperation]::FolderTrash }
            'unlink' { [KeeperSecurity.Vault.KeeperNSFRecordRemoveOperation]::Unlink }
        }

        if ($op -eq [KeeperSecurity.Vault.KeeperNSFRecordRemoveOperation]::Unlink -and -not $resolvedFolderUid) {
            Write-Error -Message "Folder context is required for unlink. Use -Folder or cd into a Keeper NSF folder."
            return
        }
    }

    process {
        foreach ($name in $Record) {
            [KeeperSecurity.Vault.KeeperNSFRecord]$kdRecord = $null
            if (-not $vault.TryResolveKeeperNSFRecord($name, [ref]$kdRecord)) {
                Write-Error -Message "Keeper NSF record `"$name`" was not found. Run Sync-Keeper or nsf-list first."
                continue
            }

            $folderUid = $resolvedFolderUid
            if (-not $folderUid -and $op -ne [KeeperSecurity.Vault.KeeperNSFRecordRemoveOperation]::OwnerTrash) {
                $folderUids = @($vault.GetKeeperNSFFoldersForRecord($kdRecord.RecordUid))
                if ($folderUids.Count -eq 0) {
                    Write-Error -Message "No folder context for record `"$name`". Use -Folder or -Operation owner-trash."
                    continue
                }
                $folderUid = $folderUids[0]
            }

            $removal = New-Object KeeperSecurity.Vault.KeeperNSFRecordRemoval
            $removal.RecordUid = $kdRecord.RecordUid
            $removal.FolderUid = $folderUid
            $removal.Operation = $op
            $removals.Add($removal)
        }
    }

    end {
        if ($removals.Count -eq 0) {
            return
        }

        Write-Host ""
        Write-Host "=== Keeper NSF Remove Preview ===" -ForegroundColor Cyan
        $previewResult = $vault.RemoveKeeperNSFRecords($removals, $true).GetAwaiter().GetResult()
        Write-KeeperNSFRemoveImpact -Response $previewResult.PreviewResponse

        try {
            [KeeperSecurity.Vault.VaultOnline]::ValidateRemoveResponse($previewResult.PreviewResponse, $false)
        }
        catch {
            Write-Error -Message $_.Exception.Message
            return
        }

        if ($DryRun) {
            Write-Host ""
            Write-Host "Dry run: no records were removed." -ForegroundColor DarkYellow
            return
        }

        if (-not $Force) {
            $prompt = if ($Operation -eq 'owner-trash') {
                "Are you sure you want to move the record(s) above to your trash? (yes/No)"
            } elseif ($Operation -eq 'folder-trash') {
                "Are you sure you want to move the record(s) above to folder trash? (yes/No)"
            } else {
                "Are you sure you want to unlink the record(s) above from the folder? (yes/No)"
            }
            $confirmation = Read-Host $prompt
            if ($confirmation -notmatch '^(y|yes)$') {
                Write-Host "Remove operation cancelled"
                return
            }
        }

        if ($previewResult.PreviewResponse.ConfirmationToken.IsEmpty) {
            Write-Error -Message "Preview did not return a confirmation token."
            return
        }

        Write-Host ""
        Write-Host "Removing records..." -ForegroundColor Cyan
        $confirmResult = $vault.RemoveKeeperNSFRecords($removals, $false).GetAwaiter().GetResult()
        if (-not $confirmResult.Confirmed) {
            Write-Error -Message "Record removal was not confirmed by the server."
            return
        }

        $vault.SyncDown($false).GetAwaiter().GetResult() | Out-Null
        Write-Host ""
        Write-Host "Keeper NSF record removal completed." -ForegroundColor Green
    }
}
New-Alias -Name nsf-rm -Value Remove-KeeperNSFRecord
function Link-KeeperNSFRecord {
    <#
	.Synopsis
	Links a Keeper NSF record into a Keeper NSF folder (Keeper NSF v3 API).

	.Parameter Record
	Record UID or title.

	.Parameter Folder
	Destination folder UID, name, or "/" for Keeper NSF root.
#>
    [CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Default')]
    Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [string] $Record,

        [Parameter(Position = 1, Mandatory = $true)]
        [string] $Folder
    )

    [KeeperSecurity.Vault.VaultOnline]$vault = getVault

    [KeeperSecurity.Vault.KeeperNSFRecord]$kdRecord = $null
    if (-not $vault.TryResolveKeeperNSFRecord($Record, [ref]$kdRecord)) {
        Write-Error -Message "Keeper NSF record `"$Record`" was not found. Run Sync-Keeper or nsf-list first."
        return
    }

    [KeeperSecurity.Vault.FolderNode]$folderNode = $null
    if (-not $vault.TryResolveKeeperNSFFolder($Folder, [ref]$folderNode)) {
        Write-Error -Message "Keeper NSF folder `"$Folder`" was not found. Run Sync-Keeper or nsf-list first."
        return
    }

    $folderLabel = if ([string]::IsNullOrEmpty($folderNode.FolderUid)) { 'root' } else { "$($folderNode.Name) ($($folderNode.FolderUid))" }
    $target = "$($kdRecord.RecordUid) -> $folderLabel"
    if (-not $PSCmdlet.ShouldProcess($target, "Link Keeper NSF record into folder")) {
        return
    }

    try {
        $result = $vault.LinkKeeperNSFRecordToFolder($Record, $Folder).GetAwaiter().GetResult()
        [KeeperSecurity.Vault.VaultOnline]::ValidateFolderRecordUpdateResult($result)
    }
    catch {
        Write-Error -Message $_.Exception.Message
        return
    }

    $vault.SyncDown($false).GetAwaiter().GetResult() | Out-Null
    Write-Host "Keeper NSF record linked into folder." -ForegroundColor Green
}
New-Alias -Name nsf-ln -Value Link-KeeperNSFRecord

function Transfer-KeeperNSFRecordOwnership {
    <#
	.Synopsis
	Transfers ownership of one or more Keeper NSF records to another user (Keeper NSF v3 API).

	.Description
	Positional arguments: one or more record UIDs or titles, then the new owner's email address.
	After a successful transfer you will no longer have access to the record(s).

	.Example
	nsf-transfer-record rvwIBG_ban2VTH64OsnzLn alice@example.com

	.Example
	nsf-transfer-record rec1 rec2 rec3 alice@example.com
#>
    [CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Default')]
    Param(
        [Parameter(ValueFromRemainingArguments = $true, Mandatory = $true)]
        [string[]] $ArgumentList,

        [Alias('f')]
        [switch] $Force
    )

    if ($ArgumentList.Count -lt 2) {
        Write-Error -Message "Usage: nsf-transfer-record RECORD [RECORD...] NEW_OWNER_EMAIL"
        return
    }

    $newOwnerEmail = $ArgumentList[-1]
    $recordArgs = @($ArgumentList[0..($ArgumentList.Count - 2)])

    if ($recordArgs.Count -eq 0 -or [string]::IsNullOrWhiteSpace($newOwnerEmail)) {
        Write-Error -Message "Record UID(s) and new owner email are required."
        return
    }

    if ($newOwnerEmail -notmatch '@') {
        Write-Error -Message "New owner must be an email address: `"$newOwnerEmail`""
        return
    }

    [KeeperSecurity.Vault.VaultOnline]$vault = getVault
    $resolvedRecords = New-Object 'System.Collections.Generic.List[string]'

    foreach ($name in $recordArgs) {
        [KeeperSecurity.Vault.KeeperNSFRecord]$kdRecord = $null
        if (-not $vault.TryResolveKeeperNSFRecord($name, [ref]$kdRecord)) {
            Write-Error -Message "Keeper NSF record `"$name`" was not found. Run Sync-Keeper or nsf-list first."
            return
        }
        $resolvedRecords.Add($kdRecord.RecordUid)
    }

    if (-not $Force) {
        Write-Host ""
        Write-Host "*** WARNING ***" -ForegroundColor Yellow
        Write-Host "After ownership is transferred you will lose owner rights on the record(s)."
        Write-Host "You may still see the record(s) if you retain access via a shared folder or admin role; otherwise they will disappear after sync."
        Write-Host "Make sure the new owner is correct before continuing."
        Write-Host ""
        $confirmation = Read-Host "Are you sure you want to transfer ownership to '$newOwnerEmail'? This action cannot be undone. (yes/No)"
        if ($confirmation -notmatch '^(y|yes)$') {
            Write-Host "Transfer operation cancelled"
            return
        }
    }

    try {
        $results = $vault.TransferKeeperNSFRecordOwnership($resolvedRecords, $newOwnerEmail).GetAwaiter().GetResult()
        [KeeperSecurity.Vault.VaultOnline]::ValidateKeeperNSFTransferResults($results)

        foreach ($result in $results) {
            Write-Host "Record '$($result.RecordUid)' ownership transferred to $($result.Username)." -ForegroundColor Green
            Write-Host "You no longer own this record. Run Sync-Keeper to refresh; it will remain visible only if you retain access via a shared folder or admin role." -ForegroundColor Yellow
        }
    }
    catch {
        Write-Error -Message $_.Exception.Message
        return
    }

    $vault.SyncDown($false).GetAwaiter().GetResult() | Out-Null
}
New-Alias -Name nsf-transfer-record -Value Transfer-KeeperNSFRecordOwnership
