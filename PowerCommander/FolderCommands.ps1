#requires -Version 5.1

class KeeperFolderListItem {
    [string]$FolderUid
    [string]$Name
    [string]$FolderType
    [string]$Category
    [string]$ParentUid
    [string]$SharedFolderUid
    [int]$SubfolderCount
    [int]$RecordCount
    [string]$Path
}

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

function tryResolveKeeperFolder {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)][string] $Identifier,
        [Parameter(Mandatory = $true)][KeeperSecurity.Vault.VaultOnline] $Vault,
        [Parameter()][switch] $SupportPaths
    )

    [KeeperSecurity.Vault.FolderNode]$folder = $null

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

    $objs = @(Get-KeeperChildItem -ObjectType Folder -Recursive | Where-Object Name -eq $Identifier)
    if ($objs.Count -eq 0) {
        return $null
    }
    if ($objs.Count -gt 1) {
        Write-Error -Message "There are more than one folders with name `"$Identifier`". Use Folder UID$(if ($SupportPaths.IsPresent) { ' or full path' }) to specify the correct one using UID" -ErrorAction Stop
    }

    $folderUid = $objs[0].Uid
    if ($Vault.TryGetFolder($folderUid, [ref]$folder)) {
        return $folder
    }

    return $null
}

function resolveKeeperFolder {
    <#
    .Synopsis
    Internal helper function to resolve a classic folder by UID, name, or path.
    Throws if the identifier is a nested shared folder (use NSF cmdlets) or not found.
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)][string] $Identifier,
        [Parameter(Mandatory = $true)][KeeperSecurity.Vault.VaultOnline] $Vault,
        [Parameter()][switch] $SupportPaths
    )

    $folder = tryResolveKeeperFolder -Identifier $Identifier -Vault $Vault -SupportPaths:$SupportPaths
    if ($folder) {
        return $folder
    }

    $nsfFolder = resolveKeeperNSFFolder -Identifier $Identifier -Vault $Vault
    if ($nsfFolder) {
        Write-Error -Message "The specified identifier `"$Identifier`" corresponds to a Nested Shared Folder. Use Set-KeeperNSFFolder (nsf-rndir) to edit Nested Shared Folders." -ErrorAction Stop
    }

    Write-Error -Message "Folder `"$Identifier`" not found or not accessible" -ErrorAction Stop
}

function Get-KeeperFolders {
    <#
	.Synopsis
	List all folders in the Keeper vault.

	.Description
	Returns a list of all folders in the Keeper vault with their details including
	UID, Name, Type (UserFolder/SharedFolder), Parent folder, and counts of subfolders and records.
	
	.Parameter Filter
	Filter folders by name (supports wildcards: * and ?)

	.Parameter Type
	Filter by folder type: 'User', 'Shared', or 'All' (default: All)

	.Parameter IncludeRoot
	Include the root folder in the results

	.Parameter Verbose
	Show detailed information including full paths
    
	.Parameter AsObject
	Return the folders as objects instead of displaying formatted information

	.Parameter ClassicOnly
	Exclude nested shared (NSF) folders from KeeperDrive sync.

	.Example
	Get-KeeperFolders
	Lists all folders in the vault

	.Example
	Get-KeeperFolders -Filter "Engineering*"
	Lists all folders whose names start with "Engineering"

	.Example
	Get-KeeperFolders -Type Shared
	Lists only shared folders

	.Example
	Get-KeeperFolders -Verbose
	Lists all folders with detailed information including full paths
#>

    [CmdletBinding()]
    Param (
        [Parameter(Position = 0)][string] $Filter,
        [Parameter()][ValidateSet('All', 'User', 'Shared')]
        [string] $Type = 'All',
        [Parameter()][switch] $IncludeRoot,
        [Parameter()][switch] $AsObject,
        [Parameter()][switch] $ClassicOnly
    )

    [KeeperSecurity.Vault.VaultOnline]$vault = getVault

    $folders = [System.Collections.Generic.List[KeeperFolderListItem]]::new()

    if (-not $ClassicOnly.IsPresent -and $Type -eq 'All') {
        foreach ($nsfFolder in $vault.KeeperNSFFolderNodes) {
            if ($Filter -and -not ($nsfFolder.Name -like $Filter)) { continue }
            $item = [KeeperFolderListItem]::new()
            $item.FolderUid       = $nsfFolder.FolderUid
            $item.Name            = $nsfFolder.Name
            $item.FolderType      = 'folder'
            $item.Category        = 'Nested Shared Folder'
            $item.ParentUid       = $nsfFolder.ParentUid
            $item.SharedFolderUid = $null
            $item.SubfolderCount  = $nsfFolder.Subfolders.Count
            $item.RecordCount     = $nsfFolder.Records.Count
            $item.Path            = $null
            $folders.Add($item) | Out-Null
        }
    }

    foreach ($folder in $vault.Folders) {
        if ([string]::IsNullOrEmpty($folder.FolderUid) -and -not $IncludeRoot.IsPresent) {
            continue
        }
        
        if ($Type -ne 'All') {
            $isShared = $folder.FolderType -eq [KeeperSecurity.Vault.FolderType]::SharedFolder -or 
                        $folder.FolderType -eq [KeeperSecurity.Vault.FolderType]::SharedFolderFolder
            
            if ($Type -eq 'Shared' -and -not $isShared) {
                continue
            }
            if ($Type -eq 'User' -and $isShared) {
                continue
            }
        }
        
        if ($Filter) {
            if (-not ($folder.Name -like $Filter)) {
                continue
            }
        }
        
        $folderInfo = [KeeperFolderListItem]::new()
        $folderInfo.FolderUid       = $folder.FolderUid
        $folderInfo.Name            = $folder.Name
        $folderInfo.FolderType      = $folder.FolderType.ToString()
        $folderInfo.Category        = 'Classic'
        $folderInfo.ParentUid       = $folder.ParentUid
        $folderInfo.SharedFolderUid = $folder.SharedFolderUid
        $folderInfo.SubfolderCount  = $folder.Subfolders.Count
        $folderInfo.RecordCount     = $folder.Records.Count
        $folderInfo.Path            = if ($PSCmdlet.MyInvocation.BoundParameters['Verbose']) {
            getVaultFolderPath $vault $folder.FolderUid
        } else {
            $null
        }

        $folders.Add($folderInfo) | Out-Null
    }

    $folders = @($folders | Sort-Object Name)
    
    if ($folders.Count -eq 0) {
        Write-Host "No folders found matching criteria."
        return
    }
    
    if ($AsObject.IsPresent) {
        return $folders
    }

    Write-Host ""
    Write-Host "Found $($folders.Count) folder(s)" -ForegroundColor Green
    Write-Host ""
    
    if ($PSCmdlet.MyInvocation.BoundParameters['Verbose']) {
        $folders | Format-Table -Property @(
            @{Label='UID'; Expression={$_.FolderUid}; Width=25},
            @{Label='Name'; Expression={$_.Name}; Width=35},
            @{Label='Type'; Expression={$_.FolderType}; Width=20},
            @{Label='Category'; Expression={$_.Category}; Width=22},
            @{Label='Subfolders'; Expression={$_.SubfolderCount}; Width=10; Align='Right'},
            @{Label='Records'; Expression={$_.RecordCount}; Width=8; Align='Right'},
            @{Label='Path'; Expression={$_.Path}}
        ) -AutoSize
    } else {
        $folders | Format-Table -Property @(
            @{Label='UID'; Expression={$_.FolderUid}; Width=25},
            @{Label='Name'; Expression={$_.Name}; Width=35},
            @{Label='Type'; Expression={$_.FolderType}; Width=20},
            @{Label='Category'; Expression={$_.Category}; Width=22},
            @{Label='Subfolders'; Expression={$_.SubfolderCount}; Width=10; Align='Right'},
            @{Label='Records'; Expression={$_.RecordCount}; Width=8; Align='Right'}
        ) -AutoSize
    }


}
New-Alias -Name kfolders -Value Get-KeeperFolders

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

    $folder = tryResolveKeeperFolder -Identifier $Uid -Vault $vault -SupportPaths
    if (-not $folder) {
        $nsfFolder = resolveKeeperNSFFolder -Identifier $Uid -Vault $vault
        if ($nsfFolder) {
            if ($AsObject.IsPresent) { return $nsfFolder }
            Get-KeeperNSFRecord -Uid $Uid
            return
        }
        Write-Error -Message "Folder `"$Uid`" not found or not accessible" -ErrorAction Stop
    }

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
