#requires -Version 5.0

using namespace KeeperSecurity

function Add-KeeperFolder {
<#
	.Synopsis
	Creates or Modifies a Keeper record in the current folder.

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

	[Vault.VaultOnline]$vault = $Script:Vault
	if (-not $vault) {
		Write-Error -Message 'Not connected'
	}
	$objs = Get-KeeperChildItems -ObjectType Folder | where Name -eq $Name
	if ($objs.Length -gt 0 ) {
        Write-Error -Message "Folder `"$Name`" already exists"
	}

	$parentUid = $Script:CurrentFolder
	if ($ParentFolderUid) {
		[Vault.FolderNode]$folder = $null
		if (-not $vault.TryGetFolder($ParentFolderUid, [ref]$folder)) {
	        Write-Error -Message "Folder UID `"$ParentFolderUid`" does not exist"
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
	$task = $vault.CreateFolder($Name, $parentUid, $options)
	$_ = $task.GetAwaiter().GetResult()
}