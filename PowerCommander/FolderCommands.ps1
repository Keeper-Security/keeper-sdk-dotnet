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
        $folder = resolveKeeperFolder -Identifier $ParentFolderUid -Vault $vault -SupportPaths
        $parentUid = $folder.FolderUid
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
    
    $folder = resolveKeeperFolder -Identifier $Name -Vault $vault
    
    $vault.DeleteFolder($folder.FolderUid).GetAwaiter().GetResult() | Out-Null
}
New-Alias -Name krmdir -Value Remove-KeeperFolder

function resolveKeeperFolder {
    <#
    .Synopsis
    Internal helper function to resolve a folder by UID, name, or path

    .Parameter Identifier
    Folder UID, Name, or Path

    .Parameter Vault
    VaultOnline instance

    .Parameter SupportPaths
    Whether to support path resolution (e.g., /Shared Folder/SubFolder)
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)][string] $Identifier,
        [Parameter(Mandatory = $true)][KeeperSecurity.Vault.VaultOnline] $Vault,
        [Parameter()][switch] $SupportPaths
    )

    $folder = $null
    
    if ($Vault.TryGetFolder($Identifier, [ref]$folder)) {
        return $folder
    }
    
    if ($SupportPaths.IsPresent) {
        [KeeperSecurity.Vault.FolderNode]$currentDir = $null
        if (-not $Vault.TryGetFolder($Script:Context.CurrentFolder, [ref]$currentDir)) {
            $currentDir = $Vault.RootFolder
        }
        
        $components = splitKeeperPath $Identifier
        $rs = parseKeeperPath $components $Vault $currentDir
        if ($rs -is [array] -and -not $rs[1]) {
            return $rs[0]
        }
    }
    
    $objs = Get-KeeperChildItem -ObjectType Folder -Recursive | Where-Object Name -eq $Identifier
    if (-not $objs) {
        Write-Error -Message "Folder `"$Identifier`" does not exist" -ErrorAction Stop
    }
    if ($objs -is [array] -and $objs.Length -gt 1) {
        Write-Error -Message "There are more than one folders with name `"$Identifier`". Use Folder UID$(if ($SupportPaths.IsPresent) {' or full path'}) to specify the correct one using UID" -ErrorAction Stop
    }
    
    $folderUid = if ($objs -is [array]) { $objs[0].Uid } else { $objs.Uid }
    if ($Vault.TryGetFolder($folderUid, [ref]$folder)) {
        return $folder
    }
    
    Write-Error -Message "Folder `"$Identifier`" not found or not accessible" -ErrorAction Stop
}

function Get-KeeperFolder {
    <#
	.Synopsis
	Get detailed information about a Keeper folder.

	.Parameter Uid
	Folder UID, Name, or Path

	.Parameter AsObject
	Return the folder object instead of displaying formatted information
#>

    [CmdletBinding(DefaultParameterSetName = 'Default')]
    Param (
        [Parameter(Position = 0, Mandatory = $true)][string] $Uid,
        [Parameter()][switch] $AsObject
    )

    [KeeperSecurity.Vault.VaultOnline]$vault = getVault
    
    $folder = resolveKeeperFolder -Identifier $Uid -Vault $vault -SupportPaths

    if ($AsObject.IsPresent) {
        return $folder
    }

    Write-Host ""
    Write-Host ("    {0,-20}: {1}" -f "Folder UID", $folder.FolderUid)
    
    if ($folder.ParentUid) {
        Write-Host ("    {0,-20}: {1}" -f "Parent Folder UID", $folder.ParentUid)
    }
    
    Write-Host ("    {0,-20}: {1}" -f "Folder Type", $folder.FolderType)
    Write-Host ("    {0,-20}: {1}" -f "Name", $folder.Name)
    
    if ($folder.SharedFolderUid) {
        Write-Host ("    {0,-20}: {1}" -f "Shared Folder UID", $folder.SharedFolderUid)
    }
    
    $path = getVaultFolderPath $vault $folder.FolderUid
    Write-Host ("    {0,-20}: {1}" -f "Full Path", $path)
    
    $subfolderCount = $folder.Subfolders.Count
    $recordCount = $folder.Records.Count
    
    Write-Host ("    {0,-20}: {1}" -f "Subfolders", $subfolderCount)
    Write-Host ("    {0,-20}: {1}" -f "Records", $recordCount)
    
    Write-Host ""
}
New-Alias -Name kgetfolder -Value Get-KeeperFolder

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
    
    $folder = resolveKeeperFolder -Identifier $Uid -Vault $vault

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
    
    $vault.UpdateFolder($folder.FolderUid, $Name, $options).GetAwaiter().GetResult()
}
