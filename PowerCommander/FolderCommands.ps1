#requires -Version 5.1

function Add-KeeperFolder {
    <#
	.Synopsis
	Creates a Keeper folder.

	.Parameter Name
	Folder name

	.Parameter ParentFolderUid
	Parent Folder UID. Use current folder if omitted

	.Parameter Shared
	Create a shared folder

	.Parameter CanEdit
	Anyone can edit records by default

	.Parameter CanShare
	Anyone can share records by default

	.Parameter ManageUsers
	Anyone can manage users by default

	.Parameter ManageRecords
	Anyone can manage records by default

#>

    [CmdletBinding(DefaultParameterSetName = 'Default')]
    Param (
        [Parameter(Position = 0, Mandatory = $true)][string] $Name,
        [Parameter()][string] $ParentFolderUid,
        [Parameter()][switch] $Shared,
        [Parameter()][switch] $CanEdit,
        [Parameter()][switch] $CanShare,
        [Parameter()][switch] $ManageUsers,
        [Parameter()][switch] $ManageRecords
    )

    [KeeperSecurity.Vault.VaultOnline]$vault = getVault

    $objs = Get-KeeperChildItem -ObjectType Folder | Where-Object Name -eq $Name
    if ($objs.Length -gt 0 ) {
        Write-Error -Message "Folder `"$Name`" already exists" -ErrorAction Stop
    }

    $parentUid = $Script:Context.CurrentFolder
    if ($ParentFolderUid) {
        [KeeperSecurity.Vault.FolderNode]$folder = $null
        if (-not $vault.TryGetFolder($ParentFolderUid, [ref]$folder)) {
            Write-Error -Message "Folder UID `"$ParentFolderUid`" does not exist" -ErrorAction Stop
        }
        $parentUid = $ParentFolderUid
    }

    $options = $null
    if ($Shared.IsPresent) {
        $options = New-Object KeeperSecurity.Vault.SharedFolderOptions
        if ($CanEdit.IsPresent) {
            $options.CanEdit = $true
        }
        if ($CanShare.IsPresent) {
            $options.CanShare = $true
        }
        if ($ManageUsers.IsPresent) {
            $options.ManageUsers = $true
        }
        if ($ManageRecords.IsPresent) {
            $options.ManageRecords = $true
        }

    }
    $vault.CreateFolder($Name, $parentUid, $options).GetAwaiter().GetResult()
}
New-Alias -Name kmkdir -Value Add-KeeperFolder

function Remove-KeeperFolder {
    <#
	.Synopsis
	Delete Keeper folder.

	.Parameter Name
	Folder name or Folder UID
#>

    [CmdletBinding(DefaultParameterSetName = 'Default')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseShouldProcessForStateChangingFunctions", "")]
    Param (
        [Parameter(Position = 0, Mandatory = $true)][string] $Name
    )

    [KeeperSecurity.Vault.VaultOnline]$vault = getVault

    $folderUid = $null
    $folder = $null
    if ($vault.TryGetFolder($Name, [ref]$folder)) {
        $folderUid = $folder.FolderUid
    }
    if (-not $folderUid) {
        $objs = Get-KeeperChildItem -ObjectType Folder | Where-Object Name -eq $Name
        if (-not $objs) {
            Write-Error -Message "Folder `"$Name`" does not exist" -ErrorAction Stop
        }
        if ($objs.Length -gt 1) {
            Write-Error -Message "There are more than one folders with name `"$Name`". Use Folder UID do delete the correct one." -ErrorAction Stop
        }
        $folderUid = $objs[0].Uid
    }

    $vault.DeleteFolder($folderUid).GetAwaiter().GetResult() | Out-Null
}
New-Alias -Name krmdir -Value Remove-KeeperFolder

function Edit-KeeperFolder {
    <#
	.Synopsis
	Edits a Keeper folder.

	.Parameter Uid
	Folder UID or Name
    
    .Parameter Name
	Folder new name 

	.Parameter CanEdit
	Anyone can edit records by default (Shared Folder only)

	.Parameter CanShare
	Anyone can share records by default (Shared Folder only)

	.Parameter ManageUsers
	Anyone can manage users by default (Shared Folder only)

	.Parameter ManageRecords
	Anyone can manage records by default (Shared Folder only)
 
#>

    [CmdletBinding(DefaultParameterSetName = 'Default')]
    Param (
        [Parameter(Position=0, Mandatory = $true)] [string] $Uid,
        [Parameter()][string] $Name,
        [Parameter()][switch] $CanEdit,
        [Parameter()][switch] $CanShare,
        [Parameter()][switch] $ManageUsers,
        [Parameter()][switch] $ManageRecords
    )

    [KeeperSecurity.Vault.VaultOnline]$vault = getVault

    $folderUid = $null
    $folder = $null
    if ($vault.TryGetFolder($Uid, [ref]$folder)) {
        $folderUid = $folder.FolderUid
    }
    if (-not $folderUid) {
        $objs = Get-KeeperChildItem -ObjectType Folder | Where-Object Name -eq $Uid
        if (-not $objs) {
            Write-Error -Message "Folder `"$Uid`" does not exist" -ErrorAction Stop
        }
        if ($objs.Length -gt 1) {
            Write-Error -Message "There are more than one folders with name `"$Uid`". Use Folder UID do delete the correct one." -ErrorAction Stop
        }
        $folderUid = $objs[0].Uid
    }    

    $options = $null
    if ($CanEdit.IsPresent -or $CanShare.IsPresent -or $ManageUsers.IsPresent -or $ManageRecords.IsPresent) {
        $options = New-Object KeeperSecurity.Vault.SharedFolderOptions
        if ($CanEdit.IsPresent) {
            $options.CanEdit = $true
        }
        if ($CanShare.IsPresent) {
            $options.CanShare = $true
        }
        if ($ManageUsers.IsPresent) {
            $options.ManageUsers = $true
        }
        if ($ManageRecords.IsPresent) {
            $options.ManageRecords = $true
        }

    }
    $vault.UpdateFolder($folderUid, $Name, $options).GetAwaiter().GetResult()
}
