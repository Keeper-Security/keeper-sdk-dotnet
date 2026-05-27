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
	Grant or revoke user access to a Keeper NSF folder.

	.Description
	Changes the sharing permissions of a Keeper NSF folder using the v3 API.
	Supports granting access with a specified role, or revoking access entirely.

	.Parameter FolderUid
	UID of the folder to share. 

	.Parameter Action
	Action to perform: 'grant' (default) or 'remove'.

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
        [string] $FolderUid,

        [Parameter()]
        [ValidateSet('grant', 'remove')]
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

    [KeeperSecurity.Vault.FolderNode]$tmpFolder = $null
    if (-not $vault.TryGetKeeperNSFFolder($FolderUid, [ref]$tmpFolder)) {
        Write-Host "Error: NSF folder '$FolderUid' not found." -ForegroundColor Red
        return
    }

    foreach ($user in $Email) {
        try {
            if ($Action -eq 'grant') {
                [void]$vault.GrantKeeperNSFFolderAccess($FolderUid, $user, $Role).GetAwaiter().GetResult()
                Write-Host "Granted '$Role' access to '$user' on folder '$FolderUid'." -ForegroundColor Green
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
