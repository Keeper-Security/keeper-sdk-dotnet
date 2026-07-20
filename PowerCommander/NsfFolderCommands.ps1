#requires -Version 5.1

. "$PSScriptRoot/NsfBatchSampleData.ps1"

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

function New-KeeperNSFFolders {
    <#
	.Synopsis
	Creates multiple Keeper NSF folders in a single batch API call (up to 100 per request).

	.Description
	Uses batching. Creating under an existing parent requires add/create
	permission on that parent. Folder keys are AES-GCM encrypted; the folder name is stored in
	encrypted FolderData.Data. Larger sets are chunked automatically (100 folders per request).

	JSON schema: a "folders" array. Each item: name (required), optional parent / parent_uid,
	optional color, optional inherit_permissions (default true).

	.Parameter FilePath
	Path to a UTF-8 JSON folder batch file.

	.Parameter Json
	Inline JSON string (same schema as -FilePath).

	.Parameter DownloadSampleFolders
	Writes a sample batch create JSON file and exits without creating folders.

	.EXAMPLE
	PS> New-KeeperNSFFolders -DownloadSampleFolders

	.EXAMPLE
	PS> New-KeeperNSFFolders -FilePath .\nsf-folders-batch.sample.json
#>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium', DefaultParameterSetName = 'File')]
    Param(
        [Parameter(Mandatory = $true, ParameterSetName = 'File')]
        [Parameter(Mandatory = $false, ParameterSetName = 'DownloadSample')]
        [ValidateNotNullOrEmpty()]
        [string] $FilePath,

        [Parameter(Mandatory = $true, ParameterSetName = 'Json')]
        [ValidateNotNullOrEmpty()]
        [string] $Json,

        [Parameter(Mandatory = $false, ParameterSetName = 'DownloadSample')]
        [switch] $DownloadSampleFolders
    )

    try {
        [KeeperSecurity.Vault.VaultOnline]$vault = getVault
    }
    catch {
        Write-Error "Not connected to Keeper. Please login first."
        return
    }

    if ($DownloadSampleFolders) {
        if (-not $FilePath) {
            $FilePath = 'nsf-folders-batch.sample.json'
        }

        $fullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($FilePath)
        $parentDir = Split-Path -Parent $fullPath
        if ($parentDir -and -not (Test-Path -LiteralPath $parentDir)) {
            New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
        }

        $sampleJson = Get-KeeperNSFFolderBatchSampleJson
        $utf8NoBom = New-Object System.Text.UTF8Encoding $false
        [System.IO.File]::WriteAllText($fullPath, $sampleJson, $utf8NoBom)

        Write-Host "Sample NSF folder batch file written to: $fullPath" -ForegroundColor Green
        Write-Host "Edit folder names / parent UIDs, then run:"
        Write-Host "    New-KeeperNSFFolders -FilePath `"$FilePath`""
        return
    }

    if (-not $FilePath -and -not $Json) {
        Write-Error "FilePath or Json is required when -DownloadSampleFolders is not specified."
        return
    }

    try {
        $jsonText = if ($PSCmdlet.ParameterSetName -eq 'File') {
            if (-not (Test-Path -LiteralPath $FilePath)) {
                throw "File not found: $FilePath"
            }
            Get-Content -LiteralPath $FilePath -Raw -Encoding UTF8
        }
        else {
            $Json
        }

        $folderRequests = ConvertTo-KeeperNSFFolderCreateRequests -JsonText $jsonText
        if (-not $folderRequests -or $folderRequests.Count -eq 0) {
            throw "Folder file contains no folders."
        }

        if ($folderRequests -isnot [System.Collections.Generic.List[KeeperSecurity.Vault.KeeperNSFFolderCreateRequest]]) {
            $typed = New-Object 'System.Collections.Generic.List[KeeperSecurity.Vault.KeeperNSFFolderCreateRequest]'
            foreach ($item in @($folderRequests)) {
                if ($item -is [KeeperSecurity.Vault.KeeperNSFFolderCreateRequest]) {
                    $typed.Add($item) | Out-Null
                }
            }
            $folderRequests = $typed
        }
    }
    catch {
        Write-Host "Error parsing folder payload: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    if (-not $PSCmdlet.ShouldProcess("$($folderRequests.Count) Keeper NSF folder(s)", "Create Keeper NSF folders")) {
        return
    }

    try {
        Write-Host "Creating $($folderRequests.Count) Keeper NSF folder(s) in batch..."
        $folderList = [System.Collections.Generic.List[KeeperSecurity.Vault.KeeperNSFFolderCreateRequest]]$folderRequests
        $results = $vault.CreateKeeperNSFFolders($folderList).GetAwaiter().GetResult()

        $ok = @($results | Where-Object { $_.Success })
        $fail = @($results | Where-Object { -not $_.Success })
        Write-Host "Batch complete: $($ok.Count) succeeded, $($fail.Count) failed."
        Write-Host ""

        foreach ($result in $results) {
            if ($result.Success) {
                Write-Host "  [OK]   $($result.Name)  UID: $($result.FolderUid)" -ForegroundColor Green
            }
            else {
                $msg = if ($result.Message) { $result.Message } else { '(no message)' }
                Write-Host "  [FAIL] $($result.Name)  status=$($result.Status)  $msg" -ForegroundColor Red
            }
        }

        return ,@($results)
    }
    catch {
        Write-Host "Error creating folders in batch: $($_.Exception.Message)" -ForegroundColor Red
    }
}

New-Alias -Name nsf-mkdirs -Value New-KeeperNSFFolders

function Script:ConvertTo-KeeperNSFFolderCreateRequests {
    Param(
        [Parameter(Mandatory = $true)]
        [string] $JsonText
    )

    $parsed = $JsonText | ConvertFrom-Json -ErrorAction Stop
    $items = @()
    if ($null -ne $parsed.folders) {
        $items = @($parsed.folders)
    }
    elseif ($parsed -is [System.Array]) {
        $items = @($parsed)
    }
    else {
        throw "JSON must contain a 'folders' array (or be a root array of folder objects)."
    }

    $list = New-Object 'System.Collections.Generic.List[KeeperSecurity.Vault.KeeperNSFFolderCreateRequest]'
    $index = 0
    foreach ($item in $items) {
        $name = $null
        if ($item.name) { $name = [string]$item.name }
        elseif ($item.Name) { $name = [string]$item.Name }

        if ([string]::IsNullOrWhiteSpace($name)) {
            throw "Folder item at index $index is missing required 'name'."
        }

        $parent = $null
        if ($item.parent) { $parent = [string]$item.parent }
        elseif ($item.parent_uid) { $parent = [string]$item.parent_uid }
        elseif ($item.ParentFolderUid) { $parent = [string]$item.ParentFolderUid }

        $color = $null
        if ($item.color) { $color = [string]$item.color }
        elseif ($item.Color) { $color = [string]$item.Color }

        $inherit = $true
        if ($null -ne $item.inherit_permissions) {
            $inherit = [bool]$item.inherit_permissions
        }
        elseif ($null -ne $item.InheritPermissions) {
            $inherit = [bool]$item.InheritPermissions
        }

        $req = New-Object KeeperSecurity.Vault.KeeperNSFFolderCreateRequest
        $req.Name = $name.Trim()
        if (-not [string]::IsNullOrWhiteSpace($parent)) {
            $req.ParentFolderUid = $parent.Trim()
        }
        $req.Color = $color
        $req.InheritPermissions = $inherit
        $list.Add($req) | Out-Null
        $index++
    }

    return ,$list
}

function Set-KeeperNSFFolderAccess {
    <#
	.Synopsis
	Grant or revoke user or team access to a Keeper NSF folder.

	.Description
	Changes the sharing permissions of a Keeper NSF folder using the v3 API.
	Supports granting access with a specified role, or revoking access entirely.
	Recipients may be user emails, team names, or team UIDs.
	For bulk grant/update/revoke from JSON, use Share-KeeperNSFFolderAccesses,
	Update-KeeperNSFFolderAccesses, or Unshare-KeeperNSFFolderAccesses.

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

function Share-KeeperNSFFolderAccesses {
    <#
	.Synopsis
	Batch-grant Keeper NSF folder access (user or team) — up to 500 entries per API request.

	.Description
	Uses vault/folders/v3/access_update (FolderAccessAdds). Independent of Set-KeeperNSFFolderAccess.
	Caller must have share/update-access permission on each folder.
	JSON schema: an "accesses" array. Each item: folder_uid, accessor (email/team name/UID),
	optional role (default viewer), optional as_team, optional expire_in / expire_at.

	.Parameter FilePath
	Path to a UTF-8 JSON folder access grant batch file.

	.Parameter Json
	Inline JSON string (same schema as -FilePath).

	.Parameter DownloadSampleAccesses
	Writes a sample grant batch JSON file and exits without granting access.

	.EXAMPLE
	PS> Share-KeeperNSFFolderAccesses -DownloadSampleAccesses

	.EXAMPLE
	PS> Share-KeeperNSFFolderAccesses -FilePath .\nsf-folders-access-grant-batch.sample.json
#>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium', DefaultParameterSetName = 'File')]
    Param(
        [Parameter(Mandatory = $true, ParameterSetName = 'File')]
        [Parameter(Mandatory = $false, ParameterSetName = 'DownloadSample')]
        [ValidateNotNullOrEmpty()]
        [string] $FilePath,

        [Parameter(Mandatory = $true, ParameterSetName = 'Json')]
        [ValidateNotNullOrEmpty()]
        [string] $Json,

        [Parameter(Mandatory = $false, ParameterSetName = 'DownloadSample')]
        [switch] $DownloadSampleAccesses
    )

    try {
        [KeeperSecurity.Vault.VaultOnline]$vault = getVault
    }
    catch {
        Write-Error "Not connected to Keeper. Please login first."
        return
    }

    if ($DownloadSampleAccesses) {
        if (-not $FilePath) {
            $FilePath = 'nsf-folders-access-grant-batch.sample.json'
        }

        $fullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($FilePath)
        $parentDir = Split-Path -Parent $fullPath
        if ($parentDir -and -not (Test-Path -LiteralPath $parentDir)) {
            New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
        }

        $sampleJson = Get-KeeperNSFFolderAccessGrantBatchSampleJson
        $utf8NoBom = New-Object System.Text.UTF8Encoding $false
        [System.IO.File]::WriteAllText($fullPath, $sampleJson, $utf8NoBom)

        Write-Host "Sample NSF folder access grant batch file written to: $fullPath" -ForegroundColor Green
        Write-Host "Replace placeholders, then run:"
        Write-Host "    Share-KeeperNSFFolderAccesses -FilePath `"$FilePath`""
        return
    }

    if (-not $FilePath -and -not $Json) {
        Write-Error "FilePath or Json is required when -DownloadSampleAccesses is not specified."
        return
    }

    try {
        $jsonText = if ($PSCmdlet.ParameterSetName -eq 'File') {
            if (-not (Test-Path -LiteralPath $FilePath)) {
                throw "File not found: $FilePath"
            }
            Get-Content -LiteralPath $FilePath -Raw -Encoding UTF8
        }
        else {
            $Json
        }

        $requests = ConvertTo-KeeperNSFFolderAccessGrantRequests -JsonText $jsonText
        if (-not $requests -or $requests.Count -eq 0) {
            throw "Access grant file contains no entries."
        }

        if ($requests -isnot [System.Collections.Generic.List[KeeperSecurity.Vault.KeeperNSFFolderAccessGrantRequest]]) {
            $typed = New-Object 'System.Collections.Generic.List[KeeperSecurity.Vault.KeeperNSFFolderAccessGrantRequest]'
            foreach ($item in @($requests)) {
                if ($item -is [KeeperSecurity.Vault.KeeperNSFFolderAccessGrantRequest]) {
                    $typed.Add($item) | Out-Null
                }
            }
            $requests = $typed
        }
    }
    catch {
        Write-Host "Error parsing folder access grant payload: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    if (-not $PSCmdlet.ShouldProcess("$($requests.Count) Keeper NSF folder access grant(s)", "Grant Keeper NSF folder access")) {
        return
    }

    try {
        Write-Host "Granting $($requests.Count) Keeper NSF folder access(es) in batch..."
        $list = [System.Collections.Generic.List[KeeperSecurity.Vault.KeeperNSFFolderAccessGrantRequest]]$requests
        $results = $vault.GrantKeeperNSFFolderAccesses($list).GetAwaiter().GetResult()
        Write-KeeperNSFFolderAccessBatchResults -Results $results -ActionLabel 'grant'
        return ,@($results)
    }
    catch {
        Write-Host "Error granting folder access in batch: $($_.Exception.Message)" -ForegroundColor Red
    }
}

New-Alias -Name nsf-share-folders -Value Share-KeeperNSFFolderAccesses

function Update-KeeperNSFFolderAccesses {
    <#
	.Synopsis
	Batch-update existing Keeper NSF folder access (user or team) — up to 500 entries per API request.

	.Description
	Uses vault/folders/v3/access_update (FolderAccessUpdates). Independent of Set-KeeperNSFFolderAccess.
	JSON schema: an "accesses" array. Each item: folder_uid, accessor, role and/or expire_in/expire_at,
	optional as_team.

	.Parameter FilePath
	Path to a UTF-8 JSON folder access update batch file.

	.Parameter Json
	Inline JSON string (same schema as -FilePath).

	.Parameter DownloadSampleAccesses
	Writes a sample update batch JSON file and exits without updating access.

	.EXAMPLE
	PS> Update-KeeperNSFFolderAccesses -DownloadSampleAccesses

	.EXAMPLE
	PS> Update-KeeperNSFFolderAccesses -FilePath .\nsf-folders-access-update-batch.sample.json
#>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium', DefaultParameterSetName = 'File')]
    Param(
        [Parameter(Mandatory = $true, ParameterSetName = 'File')]
        [Parameter(Mandatory = $false, ParameterSetName = 'DownloadSample')]
        [ValidateNotNullOrEmpty()]
        [string] $FilePath,

        [Parameter(Mandatory = $true, ParameterSetName = 'Json')]
        [ValidateNotNullOrEmpty()]
        [string] $Json,

        [Parameter(Mandatory = $false, ParameterSetName = 'DownloadSample')]
        [switch] $DownloadSampleAccesses
    )

    try {
        [KeeperSecurity.Vault.VaultOnline]$vault = getVault
    }
    catch {
        Write-Error "Not connected to Keeper. Please login first."
        return
    }

    if ($DownloadSampleAccesses) {
        if (-not $FilePath) {
            $FilePath = 'nsf-folders-access-update-batch.sample.json'
        }

        $fullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($FilePath)
        $parentDir = Split-Path -Parent $fullPath
        if ($parentDir -and -not (Test-Path -LiteralPath $parentDir)) {
            New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
        }

        $sampleJson = Get-KeeperNSFFolderAccessUpdateBatchSampleJson
        $utf8NoBom = New-Object System.Text.UTF8Encoding $false
        [System.IO.File]::WriteAllText($fullPath, $sampleJson, $utf8NoBom)

        Write-Host "Sample NSF folder access update batch file written to: $fullPath" -ForegroundColor Green
        Write-Host "Replace placeholders, then run:"
        Write-Host "    Update-KeeperNSFFolderAccesses -FilePath `"$FilePath`""
        return
    }

    if (-not $FilePath -and -not $Json) {
        Write-Error "FilePath or Json is required when -DownloadSampleAccesses is not specified."
        return
    }

    try {
        $jsonText = if ($PSCmdlet.ParameterSetName -eq 'File') {
            if (-not (Test-Path -LiteralPath $FilePath)) {
                throw "File not found: $FilePath"
            }
            Get-Content -LiteralPath $FilePath -Raw -Encoding UTF8
        }
        else {
            $Json
        }

        $requests = ConvertTo-KeeperNSFFolderAccessUpdateRequests -JsonText $jsonText
        if (-not $requests -or $requests.Count -eq 0) {
            throw "Access update file contains no entries."
        }

        if ($requests -isnot [System.Collections.Generic.List[KeeperSecurity.Vault.KeeperNSFFolderAccessUpdateRequest]]) {
            $typed = New-Object 'System.Collections.Generic.List[KeeperSecurity.Vault.KeeperNSFFolderAccessUpdateRequest]'
            foreach ($item in @($requests)) {
                if ($item -is [KeeperSecurity.Vault.KeeperNSFFolderAccessUpdateRequest]) {
                    $typed.Add($item) | Out-Null
                }
            }
            $requests = $typed
        }
    }
    catch {
        Write-Host "Error parsing folder access update payload: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    if (-not $PSCmdlet.ShouldProcess("$($requests.Count) Keeper NSF folder access update(s)", "Update Keeper NSF folder access")) {
        return
    }

    try {
        Write-Host "Updating $($requests.Count) Keeper NSF folder access(es) in batch..."
        $list = [System.Collections.Generic.List[KeeperSecurity.Vault.KeeperNSFFolderAccessUpdateRequest]]$requests
        $results = $vault.UpdateKeeperNSFFolderAccesses($list).GetAwaiter().GetResult()
        Write-KeeperNSFFolderAccessBatchResults -Results $results -ActionLabel 'update'
        return ,@($results)
    }
    catch {
        Write-Host "Error updating folder access in batch: $($_.Exception.Message)" -ForegroundColor Red
    }
}

New-Alias -Name nsf-update-folder-access -Value Update-KeeperNSFFolderAccesses

function Unshare-KeeperNSFFolderAccesses {
    <#
	.Synopsis
	Batch-revoke Keeper NSF folder access (user or team) — up to 500 entries per API request.

	.Description
	Uses vault/folders/v3/access_update (FolderAccessRemoves). Independent of Set-KeeperNSFFolderAccess.
	JSON schema: an "accesses" array. Each item: folder_uid, accessor, optional as_team.

	.Parameter FilePath
	Path to a UTF-8 JSON folder access revoke batch file.

	.Parameter Json
	Inline JSON string (same schema as -FilePath).

	.Parameter DownloadSampleAccesses
	Writes a sample revoke batch JSON file and exits without revoking access.

	.EXAMPLE
	PS> Unshare-KeeperNSFFolderAccesses -DownloadSampleAccesses

	.EXAMPLE
	PS> Unshare-KeeperNSFFolderAccesses -FilePath .\nsf-folders-access-revoke-batch.sample.json
#>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium', DefaultParameterSetName = 'File')]
    Param(
        [Parameter(Mandatory = $true, ParameterSetName = 'File')]
        [Parameter(Mandatory = $false, ParameterSetName = 'DownloadSample')]
        [ValidateNotNullOrEmpty()]
        [string] $FilePath,

        [Parameter(Mandatory = $true, ParameterSetName = 'Json')]
        [ValidateNotNullOrEmpty()]
        [string] $Json,

        [Parameter(Mandatory = $false, ParameterSetName = 'DownloadSample')]
        [switch] $DownloadSampleAccesses
    )

    try {
        [KeeperSecurity.Vault.VaultOnline]$vault = getVault
    }
    catch {
        Write-Error "Not connected to Keeper. Please login first."
        return
    }

    if ($DownloadSampleAccesses) {
        if (-not $FilePath) {
            $FilePath = 'nsf-folders-access-revoke-batch.sample.json'
        }

        $fullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($FilePath)
        $parentDir = Split-Path -Parent $fullPath
        if ($parentDir -and -not (Test-Path -LiteralPath $parentDir)) {
            New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
        }

        $sampleJson = Get-KeeperNSFFolderAccessRevokeBatchSampleJson
        $utf8NoBom = New-Object System.Text.UTF8Encoding $false
        [System.IO.File]::WriteAllText($fullPath, $sampleJson, $utf8NoBom)

        Write-Host "Sample NSF folder access revoke batch file written to: $fullPath" -ForegroundColor Green
        Write-Host "Replace placeholders, then run:"
        Write-Host "    Unshare-KeeperNSFFolderAccesses -FilePath `"$FilePath`""
        return
    }

    if (-not $FilePath -and -not $Json) {
        Write-Error "FilePath or Json is required when -DownloadSampleAccesses is not specified."
        return
    }

    try {
        $jsonText = if ($PSCmdlet.ParameterSetName -eq 'File') {
            if (-not (Test-Path -LiteralPath $FilePath)) {
                throw "File not found: $FilePath"
            }
            Get-Content -LiteralPath $FilePath -Raw -Encoding UTF8
        }
        else {
            $Json
        }

        $requests = ConvertTo-KeeperNSFFolderAccessRevokeRequests -JsonText $jsonText
        if (-not $requests -or $requests.Count -eq 0) {
            throw "Access revoke file contains no entries."
        }

        if ($requests -isnot [System.Collections.Generic.List[KeeperSecurity.Vault.KeeperNSFFolderAccessRevokeRequest]]) {
            $typed = New-Object 'System.Collections.Generic.List[KeeperSecurity.Vault.KeeperNSFFolderAccessRevokeRequest]'
            foreach ($item in @($requests)) {
                if ($item -is [KeeperSecurity.Vault.KeeperNSFFolderAccessRevokeRequest]) {
                    $typed.Add($item) | Out-Null
                }
            }
            $requests = $typed
        }
    }
    catch {
        Write-Host "Error parsing folder access revoke payload: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    if (-not $PSCmdlet.ShouldProcess("$($requests.Count) Keeper NSF folder access revoke(s)", "Revoke Keeper NSF folder access")) {
        return
    }

    try {
        Write-Host "Revoking $($requests.Count) Keeper NSF folder access(es) in batch..."
        $list = [System.Collections.Generic.List[KeeperSecurity.Vault.KeeperNSFFolderAccessRevokeRequest]]$requests
        $results = $vault.RevokeKeeperNSFFolderAccesses($list).GetAwaiter().GetResult()
        Write-KeeperNSFFolderAccessBatchResults -Results $results -ActionLabel 'revoke'
        return ,@($results)
    }
    catch {
        Write-Host "Error revoking folder access in batch: $($_.Exception.Message)" -ForegroundColor Red
    }
}

New-Alias -Name nsf-unshare-folders -Value Unshare-KeeperNSFFolderAccesses

function Script:Write-KeeperNSFFolderAccessBatchResults {
    Param(
        [Parameter(Mandatory = $true)]
        $Results,
        [string] $ActionLabel = 'access'
    )

    $ok = @($Results | Where-Object { $_.Success })
    $fail = @($Results | Where-Object { -not $_.Success })
    Write-Host "Batch complete: $($ok.Count) succeeded, $($fail.Count) failed."
    Write-Host ""

    foreach ($result in $Results) {
        $typeHint = if ($result.AccessType) { " ($($result.AccessType))" } else { '' }
        $roleHint = if ($result.Role) { " [$($result.Role)]" } else { '' }
        if ($result.Success) {
            Write-Host "  [OK]   $($result.FolderUid) -> $($result.Accessor)$typeHint$roleHint" -ForegroundColor Green
        }
        else {
            $msg = if ($result.Message) { $result.Message } else { '(no message)' }
            Write-Host "  [FAIL] $($result.FolderUid) -> $($result.Accessor)$typeHint  status=$($result.Status)  $msg" -ForegroundColor Red
        }
    }
}

function Script:Get-KeeperNSFFolderAccessJsonItems {
    Param(
        [Parameter(Mandatory = $true)]
        [string] $JsonText
    )

    $parsed = $JsonText | ConvertFrom-Json -ErrorAction Stop
    if ($null -ne $parsed.accesses) {
        return @($parsed.accesses)
    }
    if ($null -ne $parsed.shares) {
        return @($parsed.shares)
    }
    if ($parsed -is [System.Array]) {
        return @($parsed)
    }
    throw "JSON must contain an 'accesses' array (or be a root array of access objects)."
}

function Script:Get-KeeperNSFFolderAccessItemFields {
    Param($Item, [int] $Index, [switch] $RequireRole)

    $folderUid = $null
    if ($Item.folder_uid) { $folderUid = [string]$Item.folder_uid }
    elseif ($Item.uid) { $folderUid = [string]$Item.uid }
    elseif ($Item.FolderUid) { $folderUid = [string]$Item.FolderUid }

    $accessor = $null
    if ($Item.accessor) { $accessor = [string]$Item.accessor }
    elseif ($Item.email) { $accessor = [string]$Item.email }
    elseif ($Item.user_email) { $accessor = [string]$Item.user_email }
    elseif ($Item.Accessor) { $accessor = [string]$Item.Accessor }

    if ([string]::IsNullOrWhiteSpace($folderUid)) {
        throw "Access item at index $Index is missing required 'folder_uid' (or uid)."
    }
    if ([string]::IsNullOrWhiteSpace($accessor)) {
        throw "Access item at index $Index is missing required 'accessor' (or email)."
    }

    $role = $null
    if ($Item.role) { $role = [string]$Item.role }
    elseif ($Item.Role) { $role = [string]$Item.Role }

    $validRoles = @('viewer', 'share-manager', 'content-manager', 'content-share-manager', 'full-manager')
    if ($RequireRole) {
        if ([string]::IsNullOrWhiteSpace($role)) { $role = 'viewer' }
        $roleNormalized = $role.Trim().ToLowerInvariant()
        if ($validRoles -notcontains $roleNormalized) {
            throw "Invalid role '$role' at access index $Index. Valid roles: $($validRoles -join ', ')."
        }
        $role = $roleNormalized
    }
    elseif (-not [string]::IsNullOrWhiteSpace($role)) {
        $roleNormalized = $role.Trim().ToLowerInvariant()
        if ($validRoles -notcontains $roleNormalized) {
            throw "Invalid role '$role' at access index $Index. Valid roles: $($validRoles -join ', ')."
        }
        $role = $roleNormalized
    }

    $asTeam = $null
    if ($null -ne $Item.as_team) { $asTeam = [bool]$Item.as_team }
    elseif ($null -ne $Item.AsTeam) { $asTeam = [bool]$Item.AsTeam }

    $expireIn = $null
    if ($Item.expire_in) { $expireIn = $Item.expire_in }
    elseif ($Item.ExpireIn) { $expireIn = $Item.ExpireIn }

    $expireAt = $null
    if ($Item.expire_at) { $expireAt = [string]$Item.expire_at }
    elseif ($Item.ExpireAt) { $expireAt = [string]$Item.ExpireAt }

    $options = $null
    if ($expireIn -or $expireAt) {
        $expirationDto = Get-ExpirationDate -ExpireIn $expireIn -ExpireAt $expireAt
        $options = New-Object KeeperSecurity.Vault.SharedFolderUserOptions
        $options.Expiration = $expirationDto
    }

    return @{
        FolderUid = $folderUid.Trim()
        Accessor  = $accessor.Trim()
        Role      = $role
        AsTeam    = $asTeam
        Options   = $options
    }
}

function Script:ConvertTo-KeeperNSFFolderAccessGrantRequests {
    Param(
        [Parameter(Mandatory = $true)]
        [string] $JsonText
    )

    $items = Get-KeeperNSFFolderAccessJsonItems -JsonText $JsonText
    $list = New-Object 'System.Collections.Generic.List[KeeperSecurity.Vault.KeeperNSFFolderAccessGrantRequest]'
    $index = 0
    foreach ($item in $items) {
        $fields = Get-KeeperNSFFolderAccessItemFields -Item $item -Index $index -RequireRole
        $req = New-Object KeeperSecurity.Vault.KeeperNSFFolderAccessGrantRequest
        $req.FolderUid = $fields.FolderUid
        $req.Accessor = $fields.Accessor
        $req.Role = $fields.Role
        if ($null -ne $fields.AsTeam) { $req.AsTeam = $fields.AsTeam }
        if ($null -ne $fields.Options) { $req.Options = $fields.Options }
        $list.Add($req) | Out-Null
        $index++
    }
    return ,$list
}

function Script:ConvertTo-KeeperNSFFolderAccessUpdateRequests {
    Param(
        [Parameter(Mandatory = $true)]
        [string] $JsonText
    )

    $items = Get-KeeperNSFFolderAccessJsonItems -JsonText $JsonText
    $list = New-Object 'System.Collections.Generic.List[KeeperSecurity.Vault.KeeperNSFFolderAccessUpdateRequest]'
    $index = 0
    foreach ($item in $items) {
        $fields = Get-KeeperNSFFolderAccessItemFields -Item $item -Index $index
        if ([string]::IsNullOrWhiteSpace($fields.Role) -and $null -eq $fields.Options) {
            throw "Access update at index $index requires 'role' and/or expire_in/expire_at."
        }
        $req = New-Object KeeperSecurity.Vault.KeeperNSFFolderAccessUpdateRequest
        $req.FolderUid = $fields.FolderUid
        $req.Accessor = $fields.Accessor
        $req.Role = $fields.Role
        if ($null -ne $fields.AsTeam) { $req.AsTeam = $fields.AsTeam }
        if ($null -ne $fields.Options) { $req.Options = $fields.Options }
        $list.Add($req) | Out-Null
        $index++
    }
    return ,$list
}

function Script:ConvertTo-KeeperNSFFolderAccessRevokeRequests {
    Param(
        [Parameter(Mandatory = $true)]
        [string] $JsonText
    )

    $items = Get-KeeperNSFFolderAccessJsonItems -JsonText $JsonText
    $list = New-Object 'System.Collections.Generic.List[KeeperSecurity.Vault.KeeperNSFFolderAccessRevokeRequest]'
    $index = 0
    foreach ($item in $items) {
        $fields = Get-KeeperNSFFolderAccessItemFields -Item $item -Index $index
        $req = New-Object KeeperSecurity.Vault.KeeperNSFFolderAccessRevokeRequest
        $req.FolderUid = $fields.FolderUid
        $req.Accessor = $fields.Accessor
        if ($null -ne $fields.AsTeam) { $req.AsTeam = $fields.AsTeam }
        $list.Add($req) | Out-Null
        $index++
    }
    return ,$list
}

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
	Renames, recolors, or updates permission inheritance for a single Keeper NSF folder.

	.Description
	Updates one folder via the Keeper NSF v3 API.
	For updating many folders from JSON, use Set-KeeperNSFFolders (nsf-folders-update).

	.Parameter Folder
	Folder UID or name.

	.Parameter Name
	New folder name.

	.Parameter Color
	Optional folder color, or "none" to clear.

	.Parameter NoInheritPermissions
	Do not inherit parent folder permissions.

	.EXAMPLE
	PS> Set-KeeperNSFFolder <folderUid> -Name "Renamed" -Color blue

	.EXAMPLE
	PS> nsf-rndir <folderUid> -Name "Renamed"
#>
    [CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Default')]
    Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $Folder,

        [Alias('n')]
        [Parameter(ParameterSetName = 'Default')]
        [string] $Name,

        [ValidateSet('none', 'red', 'orange', 'yellow', 'green', 'blue', 'gray', 'grey')]
        [string] $Color,

        [Parameter()]
        [switch] $NoInheritPermissions
    )

    if (-not $Name -and -not $PSBoundParameters.ContainsKey('Color') -and -not $NoInheritPermissions.IsPresent) {
        Write-Error -Message "Specify -Name, -Color, and/or -NoInheritPermissions to update the folder."
        return
    }

    try {
        [KeeperSecurity.Vault.VaultOnline]$vault = getVault
    }
    catch {
        Write-Error -Message "Error getting vault: $($_.Exception.Message)"
        return
    }

    [KeeperSecurity.Vault.FolderNode]$folderNode = $null
    if (-not $vault.TryResolveKeeperNSFFolder($Folder, [ref]$folderNode)) {
        Write-Error -Message "Keeper NSF folder `"$Folder`" was not found. Run Sync-Keeper or nsf-list first."
        return
    }

    $newNameArg = if ($PSBoundParameters.ContainsKey('Name')) { $Name } else { $null }
    $colorArg = if ($PSBoundParameters.ContainsKey('Color')) { $Color } else { $null }
    $inheritVal = if ($NoInheritPermissions.IsPresent) { $false } else { $null }

    $target = if ([string]::IsNullOrEmpty($folderNode.FolderUid)) { $Folder } else { "$($folderNode.Name) ($($folderNode.FolderUid))" }
    if (-not $PSCmdlet.ShouldProcess($target, "Update Keeper NSF folder")) {
        return
    }

    try {
        $result = $vault.UpdateKeeperNSFFolder($folderNode.FolderUid, $newNameArg, $colorArg, $inheritVal).GetAwaiter().GetResult()
        [KeeperSecurity.Vault.VaultOnline]::ValidateFolderModifyResult($result)
        Write-Host "Folder '$($folderNode.FolderUid)' updated." -ForegroundColor Green
    }
    catch {
        Write-Error -Message $_.Exception.Message
        return
    }

    $vault.SyncDown($false).GetAwaiter().GetResult() | Out-Null
}
New-Alias -Name nsf-rndir -Value Set-KeeperNSFFolder

function Set-KeeperNSFFolders {
    <#
	.Synopsis
	Batch-updates Keeper NSF folders from JSON (up to 100 per API request).

	.Description
	Uses vault/folders/v3/update batching. Independent of Set-KeeperNSFFolder / nsf-rndir (single folder).
	Folder name/color are AES-GCM encrypted into FolderData.Data.
	Optional inherit_permissions may only be false (disable inheritance); true is rejected — same as
	Set-KeeperNSFFolder -NoInheritPermissions. Requires share/update-access permission on each folder.
	Larger sets are chunked automatically (100 folders per request).

	JSON schema: a "folders" array. Each item: uid (required), optional name, optional color,
	optional inherit_permissions (false only).

	.Parameter FilePath
	Path to a UTF-8 JSON folder update batch file.

	.Parameter Json
	Inline JSON string (same schema as -FilePath).

	.Parameter DownloadSampleFolders
	Writes a sample batch update JSON file and exits without updating folders.

	.EXAMPLE
	PS> Set-KeeperNSFFolders -DownloadSampleFolders

	.EXAMPLE
	PS> Set-KeeperNSFFolders -FilePath .\nsf-folders-update-batch.sample.json
#>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium', DefaultParameterSetName = 'File')]
    Param(
        [Parameter(Mandatory = $true, ParameterSetName = 'File')]
        [Parameter(Mandatory = $false, ParameterSetName = 'DownloadSample')]
        [ValidateNotNullOrEmpty()]
        [string] $FilePath,

        [Parameter(Mandatory = $true, ParameterSetName = 'Json')]
        [ValidateNotNullOrEmpty()]
        [string] $Json,

        [Parameter(Mandatory = $false, ParameterSetName = 'DownloadSample')]
        [switch] $DownloadSampleFolders
    )

    try {
        [KeeperSecurity.Vault.VaultOnline]$vault = getVault
    }
    catch {
        Write-Error "Not connected to Keeper. Please login first."
        return
    }

    if ($DownloadSampleFolders) {
        if (-not $FilePath) {
            $FilePath = 'nsf-folders-update-batch.sample.json'
        }

        $fullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($FilePath)
        $parentDir = Split-Path -Parent $fullPath
        if ($parentDir -and -not (Test-Path -LiteralPath $parentDir)) {
            New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
        }

        $sampleJson = Get-KeeperNSFFolderUpdateBatchSampleJson
        $utf8NoBom = New-Object System.Text.UTF8Encoding $false
        [System.IO.File]::WriteAllText($fullPath, $sampleJson, $utf8NoBom)

        Write-Host "Sample NSF folder update batch file written to: $fullPath" -ForegroundColor Green
        Write-Host "Replace REPLACE_WITH_FOLDER_UID_* values, then run:"
        Write-Host "    Set-KeeperNSFFolders -FilePath `"$FilePath`""
        return
    }

    if (-not $FilePath -and -not $Json) {
        Write-Error "FilePath or Json is required when -DownloadSampleFolders is not specified."
        return
    }

    try {
        $jsonText = if ($PSCmdlet.ParameterSetName -eq 'File') {
            if (-not (Test-Path -LiteralPath $FilePath)) {
                throw "File not found: $FilePath"
            }
            Get-Content -LiteralPath $FilePath -Raw -Encoding UTF8
        }
        else {
            $Json
        }

        $folderRequests = ConvertTo-KeeperNSFFolderUpdateRequests -JsonText $jsonText
        if (-not $folderRequests -or $folderRequests.Count -eq 0) {
            throw "Folder update file contains no folders."
        }

        if ($folderRequests -isnot [System.Collections.Generic.List[KeeperSecurity.Vault.KeeperNSFFolderUpdateRequest]]) {
            $typed = New-Object 'System.Collections.Generic.List[KeeperSecurity.Vault.KeeperNSFFolderUpdateRequest]'
            foreach ($item in @($folderRequests)) {
                if ($item -is [KeeperSecurity.Vault.KeeperNSFFolderUpdateRequest]) {
                    $typed.Add($item) | Out-Null
                }
            }
            $folderRequests = $typed
        }
    }
    catch {
        Write-Host "Error parsing folder update payload: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    if (-not $PSCmdlet.ShouldProcess("$($folderRequests.Count) Keeper NSF folder(s)", "Update Keeper NSF folders")) {
        return
    }

    try {
        Write-Host "Updating $($folderRequests.Count) Keeper NSF folder(s) in batch..."
        $folderList = [System.Collections.Generic.List[KeeperSecurity.Vault.KeeperNSFFolderUpdateRequest]]$folderRequests
        $results = $vault.UpdateKeeperNSFFolders($folderList).GetAwaiter().GetResult()

        $ok = @($results | Where-Object { $_.Success })
        $fail = @($results | Where-Object { -not $_.Success })
        Write-Host "Batch complete: $($ok.Count) succeeded, $($fail.Count) failed."
        Write-Host ""

        foreach ($result in $results) {
            if ($result.Success) {
                Write-Host "  [OK]   $($result.Name)  UID: $($result.FolderUid)" -ForegroundColor Green
            }
            else {
                $msg = if ($result.Message) { $result.Message } else { '(no message)' }
                Write-Host "  [FAIL] $($result.Name)  UID: $($result.FolderUid)  status=$($result.Status)  $msg" -ForegroundColor Red
            }
        }

        return ,@($results)
    }
    catch {
        Write-Host "Error updating folders in batch: $($_.Exception.Message)" -ForegroundColor Red
    }
}

New-Alias -Name nsf-folders-update -Value Set-KeeperNSFFolders

function Script:ConvertTo-KeeperNSFFolderUpdateRequests {
    Param(
        [Parameter(Mandatory = $true)]
        [string] $JsonText
    )

    $parsed = $JsonText | ConvertFrom-Json -ErrorAction Stop
    $items = @()
    if ($null -ne $parsed.folders) {
        $items = @($parsed.folders)
    }
    elseif ($parsed -is [System.Array]) {
        $items = @($parsed)
    }
    else {
        throw "JSON must contain a 'folders' array (or be a root array of folder update objects)."
    }

    $list = New-Object 'System.Collections.Generic.List[KeeperSecurity.Vault.KeeperNSFFolderUpdateRequest]'
    $index = 0
    foreach ($item in $items) {
        $uid = $null
        if ($item.uid) { $uid = [string]$item.uid }
        elseif ($item.folder_uid) { $uid = [string]$item.folder_uid }
        elseif ($item.FolderUid) { $uid = [string]$item.FolderUid }

        if ([string]::IsNullOrWhiteSpace($uid)) {
            throw "Folder update item at index $index is missing required 'uid' (or folder_uid)."
        }

        $hasName = $false
        $name = $null
        if ($null -ne $item.PSObject.Properties['name']) {
            $hasName = $true
            if ($null -ne $item.name) { $name = [string]$item.name }
        }
        elseif ($null -ne $item.PSObject.Properties['Name']) {
            $hasName = $true
            if ($null -ne $item.Name) { $name = [string]$item.Name }
        }

        $hasColor = $false
        $color = $null
        if ($null -ne $item.PSObject.Properties['color']) {
            $hasColor = $true
            if ($null -ne $item.color) { $color = [string]$item.color }
        }
        elseif ($null -ne $item.PSObject.Properties['Color']) {
            $hasColor = $true
            if ($null -ne $item.Color) { $color = [string]$item.Color }
        }

        $hasInherit = $false
        $inherit = $null
        if ($null -ne $item.PSObject.Properties['inherit_permissions']) {
            $hasInherit = $true
            if ($null -ne $item.inherit_permissions) { $inherit = [bool]$item.inherit_permissions }
        }
        elseif ($null -ne $item.PSObject.Properties['InheritPermissions']) {
            $hasInherit = $true
            if ($null -ne $item.InheritPermissions) { $inherit = [bool]$item.InheritPermissions }
        }

        if (-not $hasName -and -not $hasColor -and -not $hasInherit) {
            throw "Folder update item at index $index must include name, color, and/or inherit_permissions."
        }

        if ($hasInherit -and $null -ne $inherit -and $inherit -eq $true) {
            throw "Folder update item at index ${index}: inherit_permissions can only be false on update (same as Set-KeeperNSFFolder -NoInheritPermissions)."
        }

        $req = New-Object KeeperSecurity.Vault.KeeperNSFFolderUpdateRequest
        $req.FolderUid = $uid.Trim()
        if ($hasName) { $req.Name = $name }
        if ($hasColor) { $req.Color = $color }
        if ($hasInherit -and $null -ne $inherit) { $req.InheritPermissions = $inherit }
        $list.Add($req) | Out-Null
        $index++
    }

    return ,$list
}

function Remove-KeeperNSFFolder {
    <#
	.Synopsis
	Removes one or more Keeper NSF folders by UID/name (Keeper NSF v3 API).

	.Description
	Uses vault/folders/v3/remove_folder (preview/confirm). Max 100 folders per API request;
	larger sets are chunked automatically. For JSON batch remove, use Remove-KeeperNSFFolders (nsf-rmdirs).

	.Parameter Folder
	One or more folder UIDs or names.

	.Parameter Operation
	folder-trash (default, recoverable) or delete-permanent (irreversible).
	owner-trash is not supported for folders.

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
        try {
            $previewResult = $vault.RemoveKeeperNSFFolders($removals, $true).GetAwaiter().GetResult()
        }
        catch {
            Write-Error -Message $_.Exception.Message
            return
        }
        Write-KeeperNSFRemoveImpact -Response $previewResult.PreviewResponse -ItemLabel 'Folder'

        if ($previewResult.FailedChunkCount -gt 0) {
            Write-Error -Message "Folder remove preview failed for $($previewResult.FailedChunkCount) chunk(s)."
            foreach ($err in @($previewResult.ChunkErrors)) {
                Write-Warning "  $err"
            }
            return
        }

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

        if (-not $previewResult.ChunkConfirmationTokens -or $previewResult.ChunkConfirmationTokens.Count -eq 0) {
            Write-Error -Message "Preview did not return confirmation token(s)."
            return
        }

        Write-Host ""
        Write-Host "Removing folders..." -ForegroundColor Cyan
        try {
            $confirmResult = $vault.ConfirmKeeperNSFFolders($removals, $previewResult).GetAwaiter().GetResult()
        }
        catch {
            Write-Error -Message $_.Exception.Message
            return
        }
        if ($confirmResult.PartialSuccess) {
            Write-Warning "Partial folder removal: $($confirmResult.ConfirmedChunkCount) chunk(s) succeeded, $($confirmResult.FailedChunkCount) failed."
            foreach ($err in @($confirmResult.ChunkErrors)) {
                Write-Warning "  $err"
            }
            $vault.SyncDown($false).GetAwaiter().GetResult() | Out-Null
            return
        }
        if (-not $confirmResult.Confirmed) {
            $detail = if ($confirmResult.ChunkErrors -and $confirmResult.ChunkErrors.Count -gt 0) {
                ($confirmResult.ChunkErrors -join '; ')
            } else {
                'Folder removal was not confirmed by the server.'
            }
            Write-Error -Message $detail
            return
        }

        $vault.SyncDown($false).GetAwaiter().GetResult() | Out-Null
        Write-Host ""
        Write-Host "Keeper NSF folder removal completed." -ForegroundColor Green
    }
}
New-Alias -Name nsf-rmdir -Value Remove-KeeperNSFFolder

function Remove-KeeperNSFFolders {
    <#
	.Synopsis
	Batch-remove Keeper NSF folders from JSON (up to 100 per API request).

	.Description
	Uses vault/folders/v3/remove_folder (preview/confirm). Independent of Remove-KeeperNSFFolder / nsf-rmdir.
	Larger sets are chunked automatically (100 folders per request).
	Duplicate folder_uid values in the same batch are rejected.
	owner-trash is not supported for folders.

	JSON schema: a "folders" (or "removals") array. Each item: uid / folder_uid (required),
	optional operation (folder-trash default, or delete-permanent).

	.Parameter FilePath
	Path to a UTF-8 JSON folder remove batch file.

	.Parameter Json
	Inline JSON string (same schema as -FilePath).

	.Parameter DownloadSampleFolders
	Writes a sample batch remove JSON file and exits without removing folders.

	.Parameter Force
	Skip confirmation after preview.

	.Parameter DryRun
	Preview only; do not remove folders.

	.EXAMPLE
	PS> Remove-KeeperNSFFolders -DownloadSampleFolders

	.EXAMPLE
	PS> Remove-KeeperNSFFolders -FilePath .\nsf-folders-remove-batch.sample.json

	.EXAMPLE
	PS> Remove-KeeperNSFFolders -FilePath .\nsf-folders-remove-batch.sample.json -Force
#>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium', DefaultParameterSetName = 'File')]
    Param(
        [Parameter(Mandatory = $true, ParameterSetName = 'File')]
        [Parameter(Mandatory = $false, ParameterSetName = 'DownloadSample')]
        [ValidateNotNullOrEmpty()]
        [string] $FilePath,

        [Parameter(Mandatory = $true, ParameterSetName = 'Json')]
        [ValidateNotNullOrEmpty()]
        [string] $Json,

        [Parameter(Mandatory = $false, ParameterSetName = 'DownloadSample')]
        [switch] $DownloadSampleFolders,

        [Alias('f')]
        [switch] $Force,

        [switch] $DryRun
    )

    try {
        [KeeperSecurity.Vault.VaultOnline]$vault = getVault
    }
    catch {
        Write-Error "Not connected to Keeper. Please login first."
        return
    }

    if ($DownloadSampleFolders) {
        if (-not $FilePath) {
            $FilePath = 'nsf-folders-remove-batch.sample.json'
        }

        $fullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($FilePath)
        $parentDir = Split-Path -Parent $fullPath
        if ($parentDir -and -not (Test-Path -LiteralPath $parentDir)) {
            New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
        }

        $sampleJson = Get-KeeperNSFFolderRemoveBatchSampleJson
        $utf8NoBom = New-Object System.Text.UTF8Encoding $false
        [System.IO.File]::WriteAllText($fullPath, $sampleJson, $utf8NoBom)

        Write-Host "Sample NSF folder remove batch file written to: $fullPath" -ForegroundColor Green
        Write-Host "Replace REPLACE_WITH_FOLDER_UID_* values, then run:"
        Write-Host "    Remove-KeeperNSFFolders -FilePath `"$FilePath`""
        return
    }

    if (-not $FilePath -and -not $Json) {
        Write-Error "FilePath or Json is required when -DownloadSampleFolders is not specified."
        return
    }

    try {
        $jsonText = if ($PSCmdlet.ParameterSetName -eq 'File') {
            if (-not (Test-Path -LiteralPath $FilePath)) {
                throw "File not found: $FilePath"
            }
            Get-Content -LiteralPath $FilePath -Raw -Encoding UTF8
        }
        else {
            $Json
        }

        $specs = ConvertTo-KeeperNSFFolderRemovalSpecs -JsonText $jsonText
        if (-not $specs -or $specs.Count -eq 0) {
            throw "Folder remove file contains no folders."
        }
    }
    catch {
        Write-Host "Error parsing folder remove payload: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    $removals = New-Object 'System.Collections.Generic.List[KeeperSecurity.Vault.KeeperNSFFolderRemoval]'
    $seenUids = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $resolveErrors = New-Object System.Collections.Generic.List[string]
    $index = 0
    foreach ($spec in $specs) {
        [KeeperSecurity.Vault.FolderNode]$folderNode = $null
        if (-not $vault.TryResolveKeeperNSFFolder($spec.FolderUid, [ref]$folderNode)) {
            $resolveErrors.Add("Keeper NSF folder `"$($spec.FolderUid)`" was not found (index $index). Run Sync-Keeper or nsf-list first.")
            $index++
            continue
        }

        if (-not $seenUids.Add($folderNode.FolderUid)) {
            $resolveErrors.Add("Duplicate folder_uid '$($folderNode.FolderUid)' in the same request (index $index).")
            $index++
            continue
        }

        if ($spec.Operation -notin @('folder-trash', 'delete-permanent')) {
            $resolveErrors.Add("Invalid operation '$($spec.Operation)' at index $index. Use folder-trash or delete-permanent.")
            $index++
            continue
        }

        $op = switch ($spec.Operation) {
            'folder-trash' { [KeeperSecurity.Vault.KeeperNSFFolderRemoveOperation]::FolderTrash }
            'delete-permanent' { [KeeperSecurity.Vault.KeeperNSFFolderRemoveOperation]::DeletePermanent }
        }

        $removal = New-Object KeeperSecurity.Vault.KeeperNSFFolderRemoval
        $removal.FolderUid = $folderNode.FolderUid
        $removal.Operation = $op
        $removals.Add($removal)
        $index++
    }

    if ($resolveErrors.Count -gt 0) {
        foreach ($err in $resolveErrors) {
            Write-Error -Message $err
        }
        Write-Error -Message "Aborting folder remove batch: $($resolveErrors.Count) item(s) failed validation. Fix the JSON and retry."
        return
    }

    if ($removals.Count -eq 0) {
        return
    }

    $hasPermanent = @($removals | Where-Object {
            $_.Operation -eq [KeeperSecurity.Vault.KeeperNSFFolderRemoveOperation]::DeletePermanent
        }).Count -gt 0
    if ($hasPermanent -and -not $Force -and -not $DryRun) {
        Write-Host ""
        Write-Host "*** WARNING ***" -ForegroundColor Red
        Write-Host "  delete-permanent is IRREVERSIBLE."
        Write-Host "  All sub-folders and records inside will be permanently destroyed."
    }

    Write-Host ""
    Write-Host "=== Keeper NSF Folder Remove Preview ===" -ForegroundColor Cyan
    try {
        $previewResult = $vault.RemoveKeeperNSFFolders($removals, $true).GetAwaiter().GetResult()
    }
    catch {
        Write-Error -Message $_.Exception.Message
        return
    }
    Write-KeeperNSFRemoveImpact -Response $previewResult.PreviewResponse -ItemLabel 'Folder'

    if ($previewResult.FailedChunkCount -gt 0) {
        Write-Error -Message "Folder remove preview failed for $($previewResult.FailedChunkCount) chunk(s)."
        foreach ($err in @($previewResult.ChunkErrors)) {
            Write-Warning "  $err"
        }
        return
    }

    $previewErrors = @($previewResult.PreviewResponse.Results | Where-Object {
            $_.Error -and -not [string]::IsNullOrWhiteSpace($_.Error.Message)
        })
    if ($previewErrors.Count -gt 0) {
        Write-Host ""
        Write-Host "One or more folders could not be previewed. Aborting." -ForegroundColor Yellow
        return
    }

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

    if (-not $PSCmdlet.ShouldProcess("$($removals.Count) Keeper NSF folder(s)", "Remove Keeper NSF folders")) {
        return
    }

    if (-not $Force) {
        $prompt = if ($hasPermanent) {
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

    if (-not $previewResult.ChunkConfirmationTokens -or $previewResult.ChunkConfirmationTokens.Count -eq 0) {
        Write-Error -Message "Preview did not return confirmation token(s)."
        return
    }

    Write-Host ""
    Write-Host "Removing $($removals.Count) Keeper NSF folder(s) in batch..." -ForegroundColor Cyan
    try {
        $confirmResult = $vault.ConfirmKeeperNSFFolders($removals, $previewResult).GetAwaiter().GetResult()
    }
    catch {
        Write-Error -Message $_.Exception.Message
        return
    }

    if ($confirmResult.PartialSuccess) {
        Write-Warning "Partial folder removal: $($confirmResult.ConfirmedChunkCount) chunk(s) succeeded, $($confirmResult.FailedChunkCount) failed."
        foreach ($err in @($confirmResult.ChunkErrors)) {
            Write-Warning "  $err"
        }
        $vault.SyncDown($false).GetAwaiter().GetResult() | Out-Null
        return
    }
    if (-not $confirmResult.Confirmed) {
        $detail = if ($confirmResult.ChunkErrors -and $confirmResult.ChunkErrors.Count -gt 0) {
            ($confirmResult.ChunkErrors -join '; ')
        } else {
            'Folder removal was not confirmed by the server.'
        }
        Write-Error -Message $detail
        return
    }

    $vault.SyncDown($false).GetAwaiter().GetResult() | Out-Null
    Write-Host ""
    Write-Host "Keeper NSF folder removal completed." -ForegroundColor Green
}

New-Alias -Name nsf-rmdirs -Value Remove-KeeperNSFFolders

function Script:ConvertTo-KeeperNSFFolderRemovalSpecs {
    Param(
        [Parameter(Mandatory = $true)]
        [string] $JsonText
    )

    $parsed = $JsonText | ConvertFrom-Json -ErrorAction Stop
    $items = @()
    if ($null -ne $parsed.folders) {
        $items = @($parsed.folders)
    }
    elseif ($null -ne $parsed.removals) {
        $items = @($parsed.removals)
    }
    elseif ($parsed -is [System.Array]) {
        $items = @($parsed)
    }
    else {
        throw "JSON must contain a 'folders' (or 'removals') array (or be a root array of folder remove objects)."
    }

    if ($items.Count -eq 0) {
        throw "folders must not be empty."
    }

    $list = New-Object System.Collections.Generic.List[object]
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $index = 0
    foreach ($item in $items) {
        $uid = $null
        if ($item.uid) { $uid = [string]$item.uid }
        elseif ($item.folder_uid) { $uid = [string]$item.folder_uid }
        elseif ($item.FolderUid) { $uid = [string]$item.FolderUid }

        if ([string]::IsNullOrWhiteSpace($uid)) {
            throw "Folder remove item at index $index is missing required 'uid' (or folder_uid)."
        }

        $uid = $uid.Trim()
        if (-not $seen.Add($uid)) {
            throw "Duplicate folder_uid '$uid' in the same request (index $index)."
        }

        $operation = 'folder-trash'
        if ($null -ne $item.PSObject.Properties['operation'] -and $null -ne $item.operation) {
            $operation = [string]$item.operation
        }
        elseif ($null -ne $item.PSObject.Properties['Operation'] -and $null -ne $item.Operation) {
            $operation = [string]$item.Operation
        }

        $operation = $operation.Trim().ToLowerInvariant()
        if ($operation -eq 'owner-trash') {
            throw "Folder remove item at index ${index}: owner-trash (FOLDER_MOVE_TO_OWNER_TRASH) is not supported yet."
        }
        if ($operation -notin @('folder-trash', 'delete-permanent')) {
            throw "Folder remove item at index $index has invalid operation '$operation'. Use folder-trash or delete-permanent."
        }

        $list.Add([pscustomobject]@{
                FolderUid = $uid
                Operation = $operation
            }) | Out-Null
        $index++
    }

    return ,$list
}
