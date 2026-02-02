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
	Force enable 'manage users' permission for all users in shared folders

	.Parameter ForceManageRecords
	Force enable 'manage records' permission for all users in shared folders

	.Parameter RestrictManageUsers
	Force disable 'manage users' permission for all users in shared folders

	.Parameter RestrictManageRecords
	Force disable 'manage records' permission for all users in shared folders

	.Parameter SubFolderHandling
	Shared sub-folder handling: 'ignore' or 'flatten'

	.Description
	Downloads shared folder and team membership information from your Keeper vault.
	This is useful for migration, backup, or analysis of access permissions.
	
	If the output file exists and -Force is not specified, the new data will be 
	merged with the existing file content.
	
	Use ForceManageUsers/ForceManageRecords to grant permissions to all users.
	Use RestrictManageUsers/RestrictManageRecords to revoke permissions from all users.

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
	Downloads membership with 'manage users' and 'manage records' permissions enabled for all users

	.Example
	Export-KeeperMembership -FileName "restricted.json" -RestrictManageUsers
	Downloads membership with 'manage users' permission disabled for all users
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
        [switch] $RestrictManageUsers,

        [Parameter(Mandatory = $false)]
        [switch] $RestrictManageRecords,

        [Parameter(Mandatory = $false)]
        [ValidateSet('ignore', 'flatten')]
        [string] $SubFolderHandling
    )

    [KeeperSecurity.Vault.VaultOnline]$vault = getVault

    Write-Host "Downloading shared folder membership from Keeper..."

    $downloadOptions = New-Object KeeperSecurity.Vault.DownloadMembershipOptions
    $downloadOptions.FoldersOnly = $FoldersOnly.IsPresent

    if ($ForceManageUsers -and $RestrictManageUsers) {
         throw "Cannot specify both -ForceManageUsers and -RestrictManageUsers" 
    }
    
    if ($ForceManageRecords -and $RestrictManageRecords) {
        throw "Cannot specify both -ForceManageRecords and -RestrictManageRecords" 
    }

    if ($ForceManageUsers.IsPresent) {
        $downloadOptions.ForceManageUsers = $true
    }

    if ($ForceManageRecords.IsPresent) {
        $downloadOptions.ForceManageRecords = $true
    }

    if ($RestrictManageUsers.IsPresent) {
        $downloadOptions.ForceManageUsers = $false
    }
    
    if ($RestrictManageRecords.IsPresent) {
        $downloadOptions.ForceManageRecords = $false
    }

    if ($SubFolderHandling) {
        $downloadOptions.SubFolderHandling = $SubFolderHandling
    }

    try {
        $downloadTask = [KeeperSecurity.Vault.KeeperMembershipDownload]::DownloadMembership(
            $vault,
            $downloadOptions
        )
        $downloadTask.Wait()
        $exportFile = $downloadTask.Result

        if (-not $FileName.EndsWith(".json", [StringComparison]::OrdinalIgnoreCase)) {
            $FileName += ".json"
        }

        $fileExists = Test-Path $FileName
        if ($fileExists -and $Force) {
            Write-Host "File `"$FileName`" will be overwritten (--force flag is set)."
        }
        
        $fullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($FileName)
        
        $directory = [System.IO.Path]::GetDirectoryName($fullPath)
        if (-not [string]::IsNullOrEmpty($directory) -and -not (Test-Path $directory)) {
            New-Item -ItemType Directory -Path $directory -Force | Out-Null
        }

        if ($fileExists -and -not $Force) {
            Write-Host "Merging with existing file..."
            
            if (Test-Path $fullPath) {
                $existingJson = [System.IO.File]::ReadAllText($fullPath)
                $jOptions = New-Object System.Runtime.Serialization.Json.DataContractJsonSerializerSettings
                $jOptions.UseSimpleDictionaryFormat = $true
                $jOptions.EmitTypeInformation = [System.Runtime.Serialization.EmitTypeInformation]::Never
                
                $serializer = New-Object System.Runtime.Serialization.Json.DataContractJsonSerializer(
                    [KeeperSecurity.Commands.ExportFile], $jOptions)
                
                $ms = New-Object System.IO.MemoryStream(,[System.Text.Encoding]::UTF8.GetBytes($existingJson))
                try {
                    $existingExportFile = $serializer.ReadObject($ms)
                    
                    $mergedSharedFolders = New-Object 'System.Collections.Generic.List[KeeperSecurity.Commands.ExportSharedFolder]'
                    $newUids = New-Object 'System.Collections.Generic.HashSet[string]'
                    
                    if ($exportFile.SharedFolders) {
                        foreach ($sf in $exportFile.SharedFolders) {
                            $mergedSharedFolders.Add($sf)
                            $newUids.Add($sf.Uid) | Out-Null
                        }
                    }
                    
                    if ($existingExportFile.SharedFolders) {
                        foreach ($sf in $existingExportFile.SharedFolders) {
                            if (-not $newUids.Contains($sf.Uid)) {
                                $mergedSharedFolders.Add($sf)
                            }
                        }
                    }
                    
                    $mergedTeams = New-Object 'System.Collections.Generic.List[KeeperSecurity.Commands.ExportTeam]'
                    $newTeamUids = New-Object 'System.Collections.Generic.HashSet[string]'
                    
                    if ($exportFile.Teams) {
                        foreach ($team in $exportFile.Teams) {
                            $mergedTeams.Add($team)
                            $newTeamUids.Add($team.Uid) | Out-Null
                        }
                    }
                    
                    if ($existingExportFile.Teams) {
                        foreach ($team in $existingExportFile.Teams) {
                            if (-not $newTeamUids.Contains($team.Uid)) {
                                $mergedTeams.Add($team)
                            }
                        }
                    }
                    
                    $mergedExportFile = New-Object KeeperSecurity.Commands.ExportFile
                    if ($mergedSharedFolders.Count -gt 0) {
                        $mergedExportFile.SharedFolders = $mergedSharedFolders.ToArray()
                    }
                    if ($mergedTeams.Count -gt 0) {
                        $mergedExportFile.Teams = $mergedTeams.ToArray()
                    }
                    
                    $exportFile = $mergedExportFile
                }
                finally {
                    $ms.Dispose()
                }
            }
        }

        $jsonBytes = [KeeperSecurity.Utils.JsonUtils]::DumpJson($exportFile, $true)
        $jsonContent = [System.Text.Encoding]::UTF8.GetString($jsonBytes)
        [System.IO.File]::WriteAllText($fullPath, $jsonContent)
        
        Write-Debug "Downloaded membership to $fullPath"

        $sharedFolderCount = if ($exportFile.SharedFolders) { $exportFile.SharedFolders.Length } else { 0 }
        $teamCount = if ($exportFile.Teams) { $exportFile.Teams.Length } else { 0 }

        Write-Host ""
        Write-Host "Download Summary:"
        Write-Host "    Shared Folders: $sharedFolderCount"
        if (-not $FoldersOnly) {
            Write-Host "    Teams: $teamCount"
        }
        Write-Host "    Output File: $fullPath"
        Write-Host ""
        Write-Host "Download membership completed successfully." -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to download membership: $_"
        throw
    }
}
New-Alias -Name kdwnmbs -Value Export-KeeperMembership

function Import-KeeperMembership {
    <#
	.Synopsis
	Load shared folder membership from a JSON file into Keeper

	.Parameter FileName
	Input JSON filename (default: shared_folder_membership.json)

	.Parameter FullSync
	Update and remove membership to match the file; otherwise only add/update

	.Description
	Reads shared folder membership from a JSON file (produced by Export-KeeperMembership/ smae formtat as what is exported by Export-KeeperMembership)
	and applies it to the vault. Use -FullSync to also remove users/teams that are not in the file.

	.Example
	Import-KeeperMembership
	Loads membership from default file "shared_folder_membership.json"

	.Example
	Import-KeeperMembership -FileName "backup.json" -FullSync
	Loads membership from backup.json and removes any users/teams not in the file
#>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $false, Position = 0)]
        [string] $FileName = "shared_folder_membership.json",

        [Parameter(Mandatory = $false)]
        [switch] $FullSync
    )

    $DefaultFileName = "shared_folder_membership.json"
    $MaxFileSizeBytes = 50 * 1024 * 1024  # 50 MB

    if ([string]::IsNullOrWhiteSpace($FileName)) {
        $FileName = $DefaultFileName
    }

    $fullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($FileName)
    if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
        Write-Error "Shared folder membership file `"$fullPath`" not found"
        return
    }

    $fileInfo = Get-Item -LiteralPath $fullPath
    if ($fileInfo.Length -gt $MaxFileSizeBytes) {
        $maxMB = $MaxFileSizeBytes / (1024 * 1024)
        $sizeMB = $fileInfo.Length / (1024 * 1024)
        Write-Error "File size ($sizeMB MB) exceeds maximum allowed size ($maxMB MB)"
        return
    }

    try {
        $jsonBytes = [System.IO.File]::ReadAllBytes($fullPath)
        $parseJson = [KeeperSecurity.Utils.JsonUtils].GetMethod("ParseJson", [Type[]]@([byte[]]))
        $importFile = $parseJson.MakeGenericMethod([KeeperSecurity.Commands.ImportFile]).Invoke($null, @(,$jsonBytes))
    }
    catch {
        Write-Error "Error reading membership file: $_"
        return
    }

    $sharedFolderCount = if ($importFile.SharedFolders) { $importFile.SharedFolders.Length } else { 0 }
    Write-Host "Processing $sharedFolderCount shared folder(s)..."

    [KeeperSecurity.Vault.VaultOnline]$vault = getVault

    $applyOptions = New-Object KeeperSecurity.Vault.ApplyMembershipOptions
    $applyOptions.FullSync = $FullSync.IsPresent

    try {
        $summaryTask = [KeeperSecurity.Vault.KeeperApplyMembership]::ApplyMembership($vault, $importFile, $applyOptions)
        $summaryTask.Wait()
        $summary = $summaryTask.Result

        Write-Host ""
        if ($summary.TeamsAdded -gt 0)   { Write-Host "$($summary.TeamsAdded) team(s) added to shared folders" }
        if ($summary.UsersAdded -gt 0)  { Write-Host "$($summary.UsersAdded) user(s) added to shared folders" }
        if ($summary.TeamsUpdated -gt 0) { Write-Host "$($summary.TeamsUpdated) team(s) updated in shared folders" }
        if ($summary.UsersUpdated -gt 0) { Write-Host "$($summary.UsersUpdated) user(s) updated in shared folders" }
        if ($summary.TeamsRemoved -gt 0) { Write-Host "$($summary.TeamsRemoved) team(s) removed from shared folders" }
        if ($summary.UsersRemoved -gt 0) { Write-Host "$($summary.UsersRemoved) user(s) removed from shared folders" }

        $anyChanges = ($summary.TeamsAdded + $summary.UsersAdded + $summary.TeamsUpdated + $summary.UsersUpdated + $summary.TeamsRemoved + $summary.UsersRemoved) -gt 0
        if (-not $anyChanges) {
            Write-Host "No changes applied. All memberships are up to date."
        }
        Write-Host ""
        Write-Host "Apply membership completed successfully." -ForegroundColor Green
    }
    catch {
        Write-Error "Error applying membership: $_"
        throw
    }
}
New-Alias -Name kapplymbs -Value Import-KeeperMembership