#requires -Version 5.1

function New-KeeperNSFFolder {
    <#
	.Synopsis
	Creates a new Keeper NSF folder.

	.Description
	Creates a new folder in Keeper NSF using the v3 API.

	.Parameter Name
	Name of the folder to create.

	.Parameter ParentFolderUid
	UID of the parent folder. If omitted, the folder is created at root level.

	.Parameter Color
	Optional color for the folder.

	.Parameter NoInheritPermissions
	If specified, the folder will not inherit permissions from its parent.
#>
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $true)]
        [string] $Name,

        [Parameter()]
        [string] $ParentFolderUid,

        [Parameter()]
        [string] $Color,

        [Parameter()]
        [switch] $NoInheritPermissions
    )

    try{
        [KeeperSecurity.Vault.VaultOnline]$vault = getVault
    } catch {
        Write-Host "Error getting vault: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    $inheritPermissions = -not $NoInheritPermissions.IsPresent

    try {
        $folderUid = $vault.CreateKeeperNSFFolder($Name, $ParentFolderUid, $Color, $inheritPermissions).GetAwaiter().GetResult()
        Write-Host "Folder '$Name' created successfully (UID: $folderUid)." -ForegroundColor Green
        return $folderUid
    }
    catch {
        Write-Host "Error creating folder: $($_.Exception.Message)" -ForegroundColor Red
    }
}

New-Alias -Name nsf-mkdir -Value New-KeeperNSFFolder

function Set-KeeperNSFFolderAccess {
    <#
	.Synopsis
	Grant or revoke user or team access to a Keeper NSF folder.

	.Description
	Changes the sharing permissions of a Keeper NSF folder using the v3 API.
	Supports granting access with a specified role, or revoking access entirely.
	Recipients may be user emails, team names, or team UIDs.

	.Parameter FolderUid
	UID of the folder to share. 

	.Parameter Action
	Action to perform: 'grant' (default) or 'remove'.

	.Parameter Email
	One or more user email addresses, team names, or team UIDs to grant/revoke access.

	.Parameter Role
	Access role for grant action: viewer (default), share-manager, content-manager,
	content-share-manager, full-manager.

	.Parameter ExpireIn
	Optional. Share expiration period from now (e.g. 30d, 6mo, 1y, 24h, 30mi), integer minutes,
	or a TimeSpan. Same as Grant-KeeperRecordAccess.

	.Parameter ExpireAt
	Optional. Absolute share expiration as ISO datetime (e.g. 2027-01-01T00:00:00Z).
#>
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseShouldProcessForStateChangingFunctions", "")]
    Param (
        [Parameter(Position = 0, Mandatory = $true)]
        [string] $FolderUid,

        [Parameter()]
        [ValidateSet('grant', 'remove')]
        [string] $Action = 'grant',

        [Parameter(Mandatory = $true)]
        [string[]] $Email,

        [Parameter()]
        [ValidateSet('viewer', 'share-manager', 'content-manager', 'content-share-manager', 'full-manager')]
        [string] $Role = 'viewer',

        [Alias('expire-in')]
        [Parameter()]
        [System.Object] $ExpireIn,

        [Alias('expire-at')]
        [Parameter()]
        [string] $ExpireAt
    )

    try {
        [KeeperSecurity.Vault.VaultOnline]$vault = getVault
    } catch {
        Write-Host "Error getting vault: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    [KeeperSecurity.Vault.FolderNode]$tmpFolder = $null
    if (-not $vault.TryGetKeeperNSFFolder($FolderUid, [ref]$tmpFolder)) {
        Write-Host "Error: NSF folder '$FolderUid' not found." -ForegroundColor Red
        return
    }

    $shareOptions = $null
    if ($Action -eq 'grant' -and ($ExpireIn -or $ExpireAt)) {
        try {
            $expirationDto = Get-ExpirationDate -ExpireIn $ExpireIn -ExpireAt $ExpireAt
        }
        catch {
            Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
            return
        }
        $shareOptions = New-Object KeeperSecurity.Vault.SharedFolderUserOptions
        $shareOptions.Expiration = $expirationDto
    }

    foreach ($user in $Email) {
        try {
            if ($Action -eq 'grant') {
                [void]$vault.GrantKeeperNSFFolderAccess($FolderUid, $user, $Role, $shareOptions).GetAwaiter().GetResult()
                $expireMsg = if ($shareOptions -and $shareOptions.Expiration) {
                    " (expires $($shareOptions.Expiration.LocalDateTime.ToString('g')))"
                } else { '' }
                Write-Host "Granted '$Role' access to '$user' on folder '$FolderUid'$expireMsg." -ForegroundColor Green
            }
            else {
                [void]$vault.RevokeKeeperNSFFolderAccess($FolderUid, $user).GetAwaiter().GetResult()
                Write-Host "Revoked access for '$user' from folder '$FolderUid'." -ForegroundColor Green
            }
        }
        catch {
            Write-Host "Error ${Action}ing access for '$user': $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

New-Alias -Name nsf-share-folder -Value Set-KeeperNSFFolderAccess

function Write-KeeperNSFRemoveImpact {
    param(
        [Folder.V3.Remove.RemoveResponse]$Response,
        [string] $ItemLabel = 'Record'
    )

    if ($Response.ErrorMessage) {
        Write-Host "Error: $($Response.ErrorMessage)" -ForegroundColor Red
    }

    foreach ($result in $Response.Results) {
        $recordUid = if ($result.ItemUid.Length -gt 0) {
            [KeeperSecurity.Utils.CryptoUtils]::Base64UrlEncode($result.ItemUid.ToByteArray())
        } else { '(unknown)' }

        $folderUid = if ($result.FolderUid.Length -gt 0) {
            [KeeperSecurity.Utils.CryptoUtils]::Base64UrlEncode($result.FolderUid.ToByteArray())
        } else { '' }

        Write-Host ""
        Write-Host "${ItemLabel}: $recordUid" -ForegroundColor Cyan
        if ($folderUid) {
            Write-Host "  Folder context: $folderUid"
        }
        Write-Host "  Status: $($result.Status)"

        if ($result.Error -and $result.Error.Message) {
            Write-Host "  Error: $($result.Error.Message)" -ForegroundColor Red
        }

        if ($result.Impact) {
            $impact = $result.Impact
            Write-Host "  Impact:"
            Write-Host "    Folders:          $($impact.FoldersCount)"
            Write-Host "    Records:          $($impact.RecordsCount)"
            Write-Host "    Affected users:   $($impact.AffectedUsersCount)"
            Write-Host "    Affected teams:   $($impact.AffectedTeamsCount)"
            if ($impact.RecordInfo) {
                Write-Host "    Other locations:  $($impact.RecordInfo.LocationsCount)"
            }
            foreach ($warning in $impact.Warnings) {
                Write-Host "    Warning: $warning" -ForegroundColor Yellow
            }
        }
    }
}
function Set-KeeperNSFFolder {
    <#
	.Synopsis
	Renames or recolors a Keeper NSF folder (Keeper NSF v3 API).

	.Parameter Folder
	Folder UID or name.

	.Parameter Name
	New folder name.

	.Parameter Color
	Optional folder color, or "none" to clear.
#>
    [CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Default')]
    Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [string] $Folder,

        [Alias('n')]
        [Parameter(ParameterSetName = 'Default')]
        [string] $Name,

        [ValidateSet('none', 'red', 'orange', 'yellow', 'green', 'blue', 'gray', 'grey')]
        [string] $Color
    )

    if (-not $Name -and -not $PSBoundParameters.ContainsKey('Color')) {
        Write-Error -Message "Specify -Name and/or -Color to update the folder."
        return
    }
    
    try {
        [KeeperSecurity.Vault.VaultOnline]$vault = getVault
    } catch {
        Write-Error -Message "Error getting vault: $($_.Exception.Message)"
        return
    }

    [KeeperSecurity.Vault.FolderNode]$folderNode = $null
    if (-not $vault.TryResolveKeeperNSFFolder($Folder, [ref]$folderNode)) {
        Write-Error -Message "Keeper NSF folder `"$Folder`" was not found. Run Sync-Keeper or nsf-list first."
        return
    }

    $target = "$($folderNode.Name) ($($folderNode.FolderUid))"
    if (-not $PSCmdlet.ShouldProcess($target, "Update Keeper NSF folder")) {
        return
    }

    $nameArg = if ($PSBoundParameters.ContainsKey('Name')) { $Name } else { [NullString]::Value }
    $colorArg = if ($PSBoundParameters.ContainsKey('Color')) { $Color } else { [NullString]::Value }

    try {
        $result = $vault.UpdateKeeperNSFFolder($folderNode.FolderUid, $nameArg, $colorArg).GetAwaiter().GetResult()
        [KeeperSecurity.Vault.VaultOnline]::ValidateFolderModifyResult($result)
    }
    catch {
        Write-Error -Message $_.Exception.Message
        return
    }

    $vault.SyncDown($false).GetAwaiter().GetResult() | Out-Null
    Write-Host "Keeper NSF folder updated." -ForegroundColor Green
}
New-Alias -Name nsf-rndir -Value Set-KeeperNSFFolder

function Remove-KeeperNSFFolder {
    <#
	.Synopsis
	Removes one or more Keeper NSF folders (Keeper NSF v3 API).

	.Parameter Folder
	One or more folder UIDs or names.

	.Parameter Operation
	folder-trash (default, recoverable) or delete-permanent (irreversible).

	.Parameter Force
	Skip confirmation after preview.

	.Parameter DryRun
	Preview only; do not remove folders.
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseShouldProcessForStateChangingFunctions", "")]
    [CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Default')]
    Param(
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true)]
        [string[]] $Folder,

        [Alias('o')]
        [ValidateSet('folder-trash', 'delete-permanent')]
        [string] $Operation = 'folder-trash',

        [Alias('f')]
        [switch] $Force,

        [switch] $DryRun
    )

    begin {
        [KeeperSecurity.Vault.VaultOnline]$vault = getVault
        $removals = New-Object 'System.Collections.Generic.List[KeeperSecurity.Vault.KeeperNSFFolderRemoval]'

        $op = switch ($Operation) {
            'folder-trash' { [KeeperSecurity.Vault.KeeperNSFFolderRemoveOperation]::FolderTrash }
            'delete-permanent' { [KeeperSecurity.Vault.KeeperNSFFolderRemoveOperation]::DeletePermanent }
        }
    }

    process {
        foreach ($name in $Folder) {
            [KeeperSecurity.Vault.FolderNode]$folderNode = $null
            if (-not $vault.TryResolveKeeperNSFFolder($name, [ref]$folderNode)) {
                Write-Error -Message "Keeper NSF folder `"$name`" was not found. Run Sync-Keeper or nsf-list first."
                continue
            }

            $removal = New-Object KeeperSecurity.Vault.KeeperNSFFolderRemoval
            $removal.FolderUid = $folderNode.FolderUid
            $removal.Operation = $op
            $removals.Add($removal)
        }
    }

    end {
        if ($removals.Count -eq 0) {
            return
        }

        if ($Operation -eq 'delete-permanent' -and -not $Force -and -not $DryRun) {
            Write-Host ""
            Write-Host "*** WARNING ***" -ForegroundColor Red
            Write-Host "  delete-permanent is IRREVERSIBLE."
            Write-Host "  All sub-folders and records inside will be permanently destroyed."
        }

        Write-Host ""
        Write-Host "=== Keeper NSF Folder Remove Preview ===" -ForegroundColor Cyan
        $previewResult = $vault.RemoveKeeperNSFFolders($removals, $true).GetAwaiter().GetResult()
        Write-KeeperNSFRemoveImpact -Response $previewResult.PreviewResponse -ItemLabel 'Folder'

        try {
            [KeeperSecurity.Vault.VaultOnline]::ValidateRemoveResponse($previewResult.PreviewResponse, $false)
        }
        catch {
            Write-Error -Message $_.Exception.Message
            return
        }

        if ($DryRun) {
            Write-Host ""
            Write-Host "Dry run: no folders were removed." -ForegroundColor DarkYellow
            return
        }

        if (-not $Force) {
            $prompt = if ($Operation -eq 'delete-permanent') {
                "Are you sure you want to permanently delete the folder(s) above? This action cannot be undone. (yes/No)"
            } else {
                "Are you sure you want to remove the folder(s) above? (yes/No)"
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
        Write-Host "Removing folders..." -ForegroundColor Cyan
        $confirmResult = $vault.RemoveKeeperNSFFolders($removals, $false).GetAwaiter().GetResult()
        if (-not $confirmResult.Confirmed) {
            Write-Error -Message "Folder removal was not confirmed by the server."
            return
        }

        $vault.SyncDown($false).GetAwaiter().GetResult() | Out-Null
        Write-Host ""
        Write-Host "Keeper NSF folder removal completed." -ForegroundColor Green
    }
}
New-Alias -Name nsf-rmdir -Value Remove-KeeperNSFFolder
