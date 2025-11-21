#requires -Version 5.1

function Export-KeeperMembership {
    <#
	.Synopsis
	Download shared folder and team membership data to a JSON file

	.Parameter FileName
	Output JSON filename (default: shared_folder_membership.json)

	.Parameter Force
	If file exists, overwrite it. Otherwise, merge with existing data

	.Parameter FoldersOnly
	Download shared folders only, skip teams

	.Parameter ForceManageUsers
	Force manage users permission for all users

	.Parameter ForceManageRecords
	Force manage records permission for all users

	.Parameter SubFolderHandling
	Shared sub-folder handling: 'ignore' or 'flatten'

	.Description
	Downloads shared folder and team membership information from your Keeper vault.
	This is useful for migration, backup, or analysis of access permissions.
	
	If the output file exists and -Force is not specified, the new data will be 
	merged with the existing file content.

	.Example
	Export-KeeperMembership
	Downloads membership to default file "shared_folder_membership.json"

	.Example
	Export-KeeperMembership -FileName "backup.json" -Force
	Downloads membership and overwrites existing backup.json

	.Example
	Export-KeeperMembership -FoldersOnly
	Downloads only shared folder membership, skipping teams

	.Example
	Export-KeeperMembership -FileName "membership.json" -ForceManageUsers -ForceManageRecords
	Downloads membership with forced permissions for all users
#>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $false, Position = 0)]
        [string] $FileName = "shared_folder_membership.json",

        [Parameter(Mandatory = $false)]
        [switch] $Force,

        [Parameter(Mandatory = $false)]
        [switch] $FoldersOnly,

        [Parameter(Mandatory = $false)]
        [switch] $ForceManageUsers,

        [Parameter(Mandatory = $false)]
        [switch] $ForceManageRecords,

        [Parameter(Mandatory = $false)]
        [ValidateSet('ignore', 'flatten')]
        [string] $SubFolderHandling
    )

    [KeeperSecurity.Vault.VaultOnline]$vault = getVault

    # Ensure .json extension
    if (-not $FileName.EndsWith(".json", [StringComparison]::OrdinalIgnoreCase)) {
        $FileName += ".json"
    }

    # Check if file exists
    $fileExists = Test-Path $FileName
    if ($fileExists -and $Force) {
        Write-Host "File `"$FileName`" will be overwritten (--force flag is set)."
    }

    Write-Host "Downloading shared folder membership from Keeper..."

    # Create logger function
    $logger = [Action[KeeperSecurity.Vault.Severity, string]] {
        param($severity, $message)
        
        if ($severity -eq [KeeperSecurity.Vault.Severity]::Warning -or 
            $severity -eq [KeeperSecurity.Vault.Severity]::Error) {
            Write-Host $message
        }
        Write-Debug $message
    }

    # Create download options
    $downloadOptions = New-Object KeeperSecurity.Vault.DownloadMembershipOptions
    $downloadOptions.FoldersOnly = $FoldersOnly.IsPresent

    if ($ForceManageUsers.IsPresent) {
        $downloadOptions.ForceManageUsers = $true
    }

    if ($ForceManageRecords.IsPresent) {
        $downloadOptions.ForceManageRecords = $true
    }

    if ($SubFolderHandling) {
        $downloadOptions.SubFolderHandling = $SubFolderHandling
    }

    # Download membership
    try {
        $exportFile = $null
        
        if ($fileExists -and -not $Force) {
            # Merge with existing file
            $mergeTask = [KeeperSecurity.Vault.KeeperMembershipDownload]::MergeMembershipToFile(
                $vault,
                $FileName,
                $downloadOptions,
                $logger
            )
            $mergeTask.Wait()
            
            # Get the result for statistics
            $downloadTask = [KeeperSecurity.Vault.KeeperMembershipDownload]::DownloadMembership(
                $vault,
                $downloadOptions,
                $logger
            )
            $downloadTask.Wait()
            $exportFile = $downloadTask.Result
        }
        else {
            # Overwrite file
            $task = [KeeperSecurity.Vault.KeeperMembershipDownload]::DownloadMembershipToFile(
                $vault,
                $FileName,
                $downloadOptions,
                $logger
            )
            $task.Wait()
            
            # Get the result for statistics
            $downloadTask = [KeeperSecurity.Vault.KeeperMembershipDownload]::DownloadMembership(
                $vault,
                $downloadOptions,
                $logger
            )
            $downloadTask.Wait()
            $exportFile = $downloadTask.Result
        }

        # Display summary
        $sharedFolderCount = if ($exportFile.SharedFolders) { $exportFile.SharedFolders.Length } else { 0 }
        $teamCount = if ($exportFile.Teams) { $exportFile.Teams.Length } else { 0 }

        Write-Host ""
        Write-Host "Download Summary:"
        Write-Host "    Shared Folders: $sharedFolderCount"
        if (-not $FoldersOnly) {
            Write-Host "    Teams: $teamCount"
        }
        Write-Host "    Output File: $FileName"
        Write-Host ""
        Write-Host "Download membership completed successfully." -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to download membership: $_"
        throw
    }
}
New-Alias -Name kdwnmbs -Value Export-KeeperMembership

