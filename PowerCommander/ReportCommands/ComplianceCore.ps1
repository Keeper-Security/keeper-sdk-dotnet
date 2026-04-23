#requires -Version 5.1

function Get-KeeperComplianceRestResponse {
    param(
        [Parameter(Mandatory = $true)]$Auth,
        [Parameter(Mandatory = $true)][string]$Endpoint,
        [Parameter()]$Request,
        [Parameter(Mandatory = $true)][type]$ResponseType
    )

    return $Auth.ExecuteAuthRest($Endpoint, $Request, $ResponseType).GetAwaiter().GetResult()
}

function Write-KeeperComplianceStatus {
    param(
        [Parameter(Mandatory = $true)][string]$Message
    )

    Write-Verbose -Message "[compliance] $Message"
}

function Set-KeeperComplianceLastSnapshotStatus {
    param(
        [Parameter()][bool]$FromCache = $false,
        [Parameter()][bool]$Incomplete = $false,
        [Parameter()][int]$PreliminaryUsersSkipped = 0,
        [Parameter()][int]$FullComplianceFailures = 0,
        [Parameter()][bool]$PrivilegeDeniedStoppedFullFetch = $false,
        [Parameter()][int]$RecordMetadataDecryptFailures = 0,
        [Parameter()][datetime]$BuiltAt = (Get-Date)
    )

    $script:ComplianceReportLastSnapshotStatus = [PSCustomObject][ordered]@{
        PSTypeName = 'KeeperComplianceSnapshotStatus'
        FromCache = $FromCache
        Incomplete = $Incomplete
        PreliminaryUsersSkipped = $PreliminaryUsersSkipped
        FullComplianceFailures = $FullComplianceFailures
        PrivilegeDeniedStoppedFullFetch = $PrivilegeDeniedStoppedFullFetch
        RecordMetadataDecryptFailures = $RecordMetadataDecryptFailures
        BuiltAt = $BuiltAt
    }
}

function ConvertTo-KeeperComplianceUid {
    param(
        [Parameter()]$ByteString
    )

    if (-not $ByteString -or $ByteString.IsEmpty) {
        return ''
    }

    return [KeeperSecurity.Utils.CryptoUtils]::Base64UrlEncode($ByteString.ToByteArray())
}

function Get-KeeperComplianceRecordData {
    param(
        [Parameter()]$EncryptedData,
        [Parameter()]$EcPrivateKey,
        [Parameter()]$Diagnostics,
        [Parameter()][string]$RecordUid,
        [Parameter()][ValidateSet('preliminary', 'full-compliance')][string]$Source = 'preliminary'
    )

    $result = [PSCustomObject]@{
        Title      = ''
        RecordType = ''
        Url        = ''
    }

    $ctx = if ($RecordUid) { "record=$RecordUid source=$Source" } else { "source=$Source" }

    if (-not $EncryptedData -or $EncryptedData.IsEmpty -or -not $EcPrivateKey) {
        Write-KeeperComplianceStatus "Compliance metadata: $ctx skipped (no ciphertext or EC key)."
        return $result
    }

    $encBytes = $EncryptedData.ToByteArray()

    $jsonBytes = $null
    try {
        $jsonBytes = [KeeperSecurity.Utils.CryptoUtils]::DecryptEc($encBytes, $EcPrivateKey)
    }
    catch {
        Write-KeeperComplianceStatus "Compliance metadata: $ctx DecryptEc failed: $($_.Exception.Message)"
        if ($Diagnostics) {
            $Diagnostics.RecordDataFailures = [int]$Diagnostics.RecordDataFailures + 1
        }
        return $result
    }

    if ($null -eq $jsonBytes -or $jsonBytes.Length -eq 0) {
        Write-KeeperComplianceStatus "Compliance metadata: $ctx decrypt ok but plaintext length=0."
        return $result
    }

    $decodeOffset = 0
    if ($jsonBytes.Length -ge 3 -and $jsonBytes[0] -eq 0xEF -and $jsonBytes[1] -eq 0xBB -and $jsonBytes[2] -eq 0xBF) {
        $decodeOffset = 3
    }
    $jsonText = [System.Text.Encoding]::UTF8.GetString($jsonBytes, $decodeOffset, $jsonBytes.Length - $decodeOffset)
    if ($jsonText.Length -gt 0 -and [int][char]$jsonText[0] -eq 0xFEFF) {
        $jsonText = $jsonText.Substring(1)
    }
    $jsonText = $jsonText.Trim()
    if ([string]::IsNullOrWhiteSpace($jsonText)) {
        Write-KeeperComplianceStatus "Compliance metadata: $ctx decrypt ok but JSON text empty after trim."
        return $result
    }

    $auditData = $null
    try {
        $auditData = $jsonText | ConvertFrom-Json
    }
    catch {
        Write-KeeperComplianceStatus "Compliance metadata: $ctx ConvertFrom-Json failed: $($_.Exception.Message)"
        if ($Diagnostics) {
            $Diagnostics.RecordDataFailures = [int]$Diagnostics.RecordDataFailures + 1
        }
        return $result
    }

    if ($null -eq $auditData) {
        Write-KeeperComplianceStatus "Compliance metadata: $ctx JSON root is null."
        return $result
    }
    if ($auditData -isnot [PSCustomObject]) {
        Write-KeeperComplianceStatus "Compliance metadata: $ctx JSON root is not an object (type=$($auditData.GetType().FullName))."
        return $result
    }

    foreach ($prop in $auditData.PSObject.Properties) {
        $n = [string]$prop.Name
        if ($n -ieq 'title') {
            $result.Title = [string]$prop.Value
        }
        elseif ($n -ieq 'record_type') {
            $result.RecordType = [string]$prop.Value
        }
        elseif ($n -ieq 'url') {
            $result.Url = [string]$prop.Value
        }
    }

    $titleLen = if ($result.Title) { $result.Title.Length } else { 0 }
    $urlLen = if ($result.Url) { $result.Url.Length } else { 0 }
    Write-KeeperComplianceStatus "Compliance metadata: $ctx extracted title_length=$titleLen record_type='$($result.RecordType)' url_length=$urlLen"

    return $result
}

function Merge-KeeperComplianceRecordFields {
    param(
        [Parameter(Mandatory = $true)]$RecordEntry,
        [Parameter(Mandatory = $true)]$RecordData
    )

    if ([string]::IsNullOrEmpty([string]$RecordEntry.Title) -and $RecordData.Title) {
        $RecordEntry.Title = [string]$RecordData.Title
    }
    if ([string]::IsNullOrEmpty([string]$RecordEntry.RecordType) -and $RecordData.RecordType) {
        $RecordEntry.RecordType = [string]$RecordData.RecordType
    }
    if ([string]::IsNullOrEmpty([string]$RecordEntry.Url) -and $RecordData.Url) {
        $RecordEntry.Url = [string]$RecordData.Url
    }
}

function Get-KeeperCompliancePrelimRequeueUserIds {
    param(
        [Parameter(Mandatory = $true)]$UserChunk,
        [Parameter(Mandatory = $true)]$SeenUserIds
    )

    $completeIds = [System.Collections.Generic.HashSet[long]]::new()
    if ($SeenUserIds.Count -gt 1) {
        foreach ($completedUserId in ($SeenUserIds | Select-Object -First ($SeenUserIds.Count - 1))) {
            $completeIds.Add([long]$completedUserId) | Out-Null
        }
    }
    return @($UserChunk | Where-Object { -not $completeIds.Contains([long]$_) })
}

function Add-KeeperComplianceUserQueueFront {
    param(
        [Parameter(Mandatory = $true)][System.Collections.Generic.Queue[long]]$Queue,
        [Parameter(Mandatory = $true)][long[]]$FrontIds
    )

    $newQ = [System.Collections.Generic.Queue[long]]::new()
    foreach ($id in $FrontIds) {
        $newQ.Enqueue($id)
    }
    while ($Queue.Count -gt 0) {
        $newQ.Enqueue($Queue.Dequeue())
    }
    return $newQ
}

$script:KeeperCompliancePermissionMasks = @(
    [PSCustomObject]@{ Mask = 1;  Name = 'owner' }
    [PSCustomObject]@{ Mask = 2;  Name = 'mask' }
    [PSCustomObject]@{ Mask = 4;  Name = 'edit' }
    [PSCustomObject]@{ Mask = 8;  Name = 'share' }
    [PSCustomObject]@{ Mask = 16; Name = 'share_admin' }
)
$script:KeeperCompliancePermissionShareAdmin = 16

function Get-KeeperCompliancePermissionText {
    param(
        [Parameter(Mandatory = $true)][int]$PermissionBits
    )

    $permissions = @()
    foreach ($permissionMask in $script:KeeperCompliancePermissionMasks) {
        if (($PermissionBits -band [int]$permissionMask.Mask) -ne 0) {
            $permissions += [string]$permissionMask.Name
        }
    }

    if ($permissions.Count -eq 0) {
        $permissions += 'read-only'
    }

    return ($permissions -join ',')
}

function Add-KeeperCompliancePermissionBits {
    param(
        [Parameter(Mandatory = $true)]$PermissionLookup,
        [Parameter(Mandatory = $true)][long]$UserUid,
        [Parameter(Mandatory = $true)][int]$PermissionBits
    )

    $currentBits = 0
    if ($PermissionLookup.ContainsKey($UserUid)) {
        $currentBits = [int]$PermissionLookup[$UserUid]
    }
    $PermissionLookup[$UserUid] = ($currentBits -bor $PermissionBits)
}

function Ensure-KeeperComplianceRecordEntry {
    param(
        [Parameter(Mandatory = $true)]$Snapshot,
        [Parameter(Mandatory = $true)][string]$RecordUid,
        [Parameter()][bool]$Shared = $false
    )

    if (-not $Snapshot.Records.ContainsKey($RecordUid)) {
        $Snapshot.Records[$RecordUid] = [PSCustomObject]@{
            Uid              = $RecordUid
            Title            = ''
            RecordType       = ''
            Url              = ''
            Shared           = $Shared
            InTrash          = $false
            UserPermissions  = @{}
            SharedFolderUids = [System.Collections.Generic.HashSet[string]]::new()
        }
    }
    elseif ($Shared -and -not $Snapshot.Records[$RecordUid].Shared) {
        $Snapshot.Records[$RecordUid].Shared = $true
    }

    return $Snapshot.Records[$RecordUid]
}

function Ensure-KeeperComplianceSharedFolderEntry {
    param(
        [Parameter(Mandatory = $true)]$Snapshot,
        [Parameter(Mandatory = $true)][string]$SharedFolderUid
    )

    if (-not $Snapshot.SharedFolders.ContainsKey($SharedFolderUid)) {
        $Snapshot.SharedFolders[$SharedFolderUid] = [PSCustomObject]@{
            Uid               = $SharedFolderUid
            Users             = [System.Collections.Generic.HashSet[long]]::new()
            Teams             = [System.Collections.Generic.HashSet[string]]::new()
            RecordPermissions = @{}
        }
    }

    return $Snapshot.SharedFolders[$SharedFolderUid]
}

function Add-KeeperCompliancePermissionByEmail {
    param(
        [Parameter(Mandatory = $true)]$PermissionLookup,
        [Parameter()][string]$Email,
        [Parameter(Mandatory = $true)][int]$PermissionBits
    )

    if (-not $Email) {
        return
    }

    $existingBits = 0
    if ($PermissionLookup.ContainsKey($Email)) {
        $existingBits = [int]$PermissionLookup[$Email]
    }
    $PermissionLookup[$Email] = ($existingBits -bor $PermissionBits)
}

function Add-KeeperCompliancePermissionByUserUid {
    param(
        [Parameter(Mandatory = $true)]$Snapshot,
        [Parameter(Mandatory = $true)]$PermissionLookup,
        [Parameter(Mandatory = $true)][long]$TargetUid,
        [Parameter(Mandatory = $true)][int]$PermissionBits
    )

    if (-not $Snapshot.Users.ContainsKey($TargetUid)) {
        return
    }

    Add-KeeperCompliancePermissionByEmail -PermissionLookup $PermissionLookup `
        -Email ([string]$Snapshot.Users[$TargetUid].Email) -PermissionBits $PermissionBits
}

function Write-KeeperReportOutput {
    param(
        [Parameter(Mandatory = $true)]$Rows,
        [Parameter()]$DisplayRows,
        [Parameter()][ValidateSet('table', 'json', 'csv')][string]$Format = 'table',
        [Parameter()][string]$Output,
        [Parameter()][int]$JsonDepth = 6,
        [Parameter()][string[]]$TableColumns
    )

    if ($null -eq $DisplayRows) {
        $DisplayRows = $Rows
    }

    if ($Output -and $Format -ne 'table') {
        $outPath = $Output
        switch ($Format) {
            'json' { Set-Content -Path $outPath -Value ($DisplayRows | ConvertTo-Json -Depth $JsonDepth) -Encoding utf8 }
            'csv'  { $DisplayRows | Export-Csv -Path $outPath -NoTypeInformation -Encoding utf8 }
        }
        Write-Host "Report exported to $outPath ($($Rows.Count) row(s) found)"
        return
    }

    switch ($Format) {
        'json' { $DisplayRows | ConvertTo-Json -Depth $JsonDepth }
        'csv'  { $DisplayRows | ConvertTo-Csv -NoTypeInformation }
        default {
            Write-Host ""
            $resolvedTableColumns = @(
                @($TableColumns) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }
            )
            if ($resolvedTableColumns.Count -eq 0 -and $DisplayRows.Count -gt 0) {
                $resolvedTableColumns = @($DisplayRows[0].PSObject.Properties.Name)
            }
            if ($resolvedTableColumns.Count -gt 0) {
                $DisplayRows | Format-Table -Property $resolvedTableColumns -AutoSize
            }
            else {
                $DisplayRows | Format-Table -AutoSize
            }
        }
    }
}

function Resolve-KeeperComplianceNode {
    param(
        [Parameter(Mandatory = $true)]$Node,
        [Parameter()][string]$Context = 'compliance report'
    )

    try {
        return (resolveSingleNode $Node)
    }
    catch {
        $message = [string]$_.Exception.Message
        if ($message.IndexOf('not found', [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
            Write-Error -Message "Cannot resolve node `"$Node`" for $Context. Use Get-KeeperEnterpriseNode or kein to list valid node IDs and names." -ErrorAction Stop
        }
        if ($message.IndexOf('not unique', [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
            Write-Error -Message "Node name `"$Node`" is ambiguous for $Context. Use the numeric node ID instead. Run Get-KeeperEnterpriseNode or kein to find the exact ID." -ErrorAction Stop
        }
        throw
    }
}

function Update-KeeperComplianceAnonymousUsers {
    param(
        [Parameter(Mandatory = $true)]$Response,
        [Parameter(Mandatory = $true)][long]$AnonymousSeed
    )

    $anonymousUserIds = @{}
    $nextSeed = $AnonymousSeed

    foreach ($userProfile in $Response.UserProfiles) {
        $userId = [long]$userProfile.EnterpriseUserId
        if (($userId -shr 32) -ne 0) {
            continue
        }

        $newUserId = $userId + $nextSeed
        $anonymousUserIds[$userId] = $newUserId
        $userProfile.EnterpriseUserId = $newUserId
        $nextSeed = $newUserId
    }

    foreach ($userRecord in $Response.UserRecords) {
        $userId = [long]$userRecord.EnterpriseUserId
        if ($anonymousUserIds.ContainsKey($userId)) {
            $userRecord.EnterpriseUserId = [long]$anonymousUserIds[$userId]
        }
    }

    foreach ($sharedFolderUser in $Response.SharedFolderUsers) {
        for ($i = 0; $i -lt $sharedFolderUser.EnterpriseUserIds.Count; $i++) {
            $userId = [long]$sharedFolderUser.EnterpriseUserIds[$i]
            if ($anonymousUserIds.ContainsKey($userId)) {
                $sharedFolderUser.EnterpriseUserIds[$i] = [long]$anonymousUserIds[$userId]
            }
        }
    }

    return $nextSeed
}

function Merge-KeeperComplianceResponse {
    param(
        [Parameter(Mandatory = $true)]$Snapshot,
        [Parameter(Mandatory = $true)]$Response
    )

    foreach ($userProfile in $Response.UserProfiles) {
        $userUid = [long]$userProfile.EnterpriseUserId
        if (-not $Snapshot.Users.ContainsKey($userUid)) {
            $Snapshot.Users[$userUid] = [PSCustomObject]@{
                UserUid  = $userUid
                Email    = [string]$userProfile.Email
                FullName = [string]$userProfile.FullName
                JobTitle = [string]$userProfile.JobTitle
                NodeId   = 0L
            }
            continue
        }

        if ([string]::IsNullOrEmpty([string]$Snapshot.Users[$userUid].Email) -and $userProfile.Email) {
            $Snapshot.Users[$userUid].Email = [string]$userProfile.Email
        }
        if ([string]::IsNullOrEmpty([string]$Snapshot.Users[$userUid].FullName) -and $userProfile.FullName) {
            $Snapshot.Users[$userUid].FullName = [string]$userProfile.FullName
        }
        if ($userProfile.JobTitle) {
            $Snapshot.Users[$userUid].JobTitle = [string]$userProfile.JobTitle
        }
    }

    foreach ($auditRecord in $Response.AuditRecords) {
        $recordUid = ConvertTo-KeeperComplianceUid -ByteString $auditRecord.RecordUid
        if (-not $recordUid) {
            continue
        }

        $recordEntry = Ensure-KeeperComplianceRecordEntry -Snapshot $Snapshot -RecordUid $recordUid

        $recordData = Get-KeeperComplianceRecordData -EncryptedData $auditRecord.AuditData -EcPrivateKey $Snapshot.EcPrivateKey `
            -Diagnostics $Snapshot.Diagnostics -RecordUid $recordUid -Source 'full-compliance'
        Merge-KeeperComplianceRecordFields -RecordEntry $recordEntry -RecordData $recordData

        $recordEntry.InTrash = [bool]$auditRecord.InTrash
    }

    foreach ($auditTeamUser in $Response.AuditTeamUsers) {
        $teamUid = ConvertTo-KeeperComplianceUid -ByteString $auditTeamUser.TeamUid
        if (-not $teamUid) {
            continue
        }

        if (-not $Snapshot.Teams.ContainsKey($teamUid)) {
            $Snapshot.Teams[$teamUid] = [PSCustomObject]@{
                Uid   = $teamUid
                Users = [System.Collections.Generic.HashSet[long]]::new()
            }
        }

        foreach ($userUid in $auditTeamUser.EnterpriseUserIds) {
            $Snapshot.Teams[$teamUid].Users.Add([long]$userUid) | Out-Null
        }
    }

    foreach ($sharedFolderRecord in $Response.SharedFolderRecords) {
        $sharedFolderUid = ConvertTo-KeeperComplianceUid -ByteString $sharedFolderRecord.SharedFolderUid
        if (-not $sharedFolderUid) {
            continue
        }

        $sharedFolderEntry = Ensure-KeeperComplianceSharedFolderEntry -Snapshot $Snapshot -SharedFolderUid $sharedFolderUid

        foreach ($recordPermission in $sharedFolderRecord.RecordPermissions) {
            $recordUid = ConvertTo-KeeperComplianceUid -ByteString $recordPermission.RecordUid
            if (-not $recordUid) {
                continue
            }

            $existingBits = 0
            if ($sharedFolderEntry.RecordPermissions.ContainsKey($recordUid)) {
                $existingBits = [int]$sharedFolderEntry.RecordPermissions[$recordUid]
            }
            $sharedFolderEntry.RecordPermissions[$recordUid] = ($existingBits -bor [int]$recordPermission.PermissionBits)

            $recordEntry = Ensure-KeeperComplianceRecordEntry -Snapshot $Snapshot -RecordUid $recordUid -Shared:$true
            $recordEntry.SharedFolderUids.Add($sharedFolderUid) | Out-Null
        }

        foreach ($shareAdminRecord in $sharedFolderRecord.ShareAdminRecords) {
            foreach ($recordPermissionIndex in $shareAdminRecord.RecordPermissionIndexes) {
                if ($recordPermissionIndex -lt 0 -or $recordPermissionIndex -ge $sharedFolderRecord.RecordPermissions.Count) {
                    continue
                }

                $recordPermission = $sharedFolderRecord.RecordPermissions[$recordPermissionIndex]
                $recordUid = ConvertTo-KeeperComplianceUid -ByteString $recordPermission.RecordUid
                if (-not $recordUid -or -not $Snapshot.Records.ContainsKey($recordUid)) {
                    continue
                }

                Add-KeeperCompliancePermissionBits -PermissionLookup $Snapshot.Records[$recordUid].UserPermissions `
                    -UserUid ([long]$shareAdminRecord.EnterpriseUserId) -PermissionBits $script:KeeperCompliancePermissionShareAdmin
            }
        }
    }

    foreach ($userRecord in $Response.UserRecords) {
        $userUid = [long]$userRecord.EnterpriseUserId
        foreach ($recordPermission in $userRecord.RecordPermissions) {
            $recordUid = ConvertTo-KeeperComplianceUid -ByteString $recordPermission.RecordUid
            if (-not $recordUid -or -not $Snapshot.Records.ContainsKey($recordUid)) {
                continue
            }

            Add-KeeperCompliancePermissionBits -PermissionLookup $Snapshot.Records[$recordUid].UserPermissions `
                -UserUid $userUid -PermissionBits ([int]$recordPermission.PermissionBits)
        }
    }

    foreach ($sharedFolderUser in $Response.SharedFolderUsers) {
        $sharedFolderUid = ConvertTo-KeeperComplianceUid -ByteString $sharedFolderUser.SharedFolderUid
        if (-not $sharedFolderUid) {
            continue
        }

        $sharedFolderEntry = Ensure-KeeperComplianceSharedFolderEntry -Snapshot $Snapshot -SharedFolderUid $sharedFolderUid

        foreach ($userUid in $sharedFolderUser.EnterpriseUserIds) {
            $sharedFolderEntry.Users.Add([long]$userUid) | Out-Null
        }
    }

    foreach ($sharedFolderTeam in $Response.SharedFolderTeams) {
        $sharedFolderUid = ConvertTo-KeeperComplianceUid -ByteString $sharedFolderTeam.SharedFolderUid
        if (-not $sharedFolderUid) {
            continue
        }

        $sharedFolderEntry = Ensure-KeeperComplianceSharedFolderEntry -Snapshot $Snapshot -SharedFolderUid $sharedFolderUid

        foreach ($teamUidBytes in $sharedFolderTeam.TeamUids) {
            $teamUid = ConvertTo-KeeperComplianceUid -ByteString $teamUidBytes
            if ($teamUid) {
                $sharedFolderEntry.Teams.Add([string]$teamUid) | Out-Null
            }
        }
    }
}

function Get-KeeperComplianceEnterpriseNodeSubtreeIds {
    param(
        [Parameter(Mandatory = $true)]$EnterpriseData,
        [Parameter(Mandatory = $true)][long]$RootNodeId
    )

    if ($RootNodeId -le 0) {
        return $null
    }

    $subnodes = @{}
    foreach ($n in $EnterpriseData.Nodes) {
        $parentId = [long]$n.ParentNodeId
        $childId = [long]$n.Id
        if ($parentId -gt 0) {
            if (-not $subnodes.ContainsKey($parentId)) {
                $subnodes[$parentId] = [System.Collections.Generic.List[long]]::new()
            }
            $subnodes[$parentId].Add($childId) | Out-Null
        }
    }

    $set = [System.Collections.Generic.HashSet[long]]::new()
    $queue = [System.Collections.Generic.Queue[long]]::new()
    $queue.Enqueue($RootNodeId) | Out-Null
    while ($queue.Count -gt 0) {
        $nid = $queue.Dequeue()
        [void]$set.Add($nid)
        if ($subnodes.ContainsKey($nid)) {
            foreach ($c in $subnodes[$nid]) {
                $queue.Enqueue($c) | Out-Null
            }
        }
    }

    $lookup = @{}
    foreach ($nid in $set) {
        $lookup["$([long]$nid)"] = $true
    }
    return $lookup
}

function Test-KeeperComplianceHasNonEmptyStringList {
    param(
        [Parameter()][AllowNull()][string[]]$Strings
    )

    if ($null -eq $Strings) {
        return $false
    }
    foreach ($s in $Strings) {
        if (-not [string]::IsNullOrWhiteSpace([string]$s)) {
            return $true
        }
    }
    return $false
}

function Test-KeeperComplianceHasNodeFilter {
    param(
        [Parameter()][AllowNull()][string]$Node
    )

    return -not [string]::IsNullOrWhiteSpace($Node)
}

function Resolve-KeeperComplianceFetchOwnerIds {
    param(
        [Parameter()][string[]]$Username,
        [Parameter()][string[]]$Team,
        [Parameter()][string]$Node
    )

    $enterprise = getEnterprise
    $enterpriseData = $enterprise.enterpriseData
    $candidateUserIds = [System.Collections.Generic.HashSet[long]]::new()
    $hasPrefilter = $false
    $hasUsernameFilter = Test-KeeperComplianceHasNonEmptyStringList -Strings $Username
    $hasTeamFilter = Test-KeeperComplianceHasNonEmptyStringList -Strings $Team

    if ($hasUsernameFilter) {
        $hasPrefilter = $true
        $lookup = @{}
        foreach ($value in $Username) {
            if (-not [string]::IsNullOrWhiteSpace([string]$value)) {
                $lookup[$value.ToLowerInvariant()] = $true
            }
        }
        foreach ($enterpriseUser in $enterpriseData.Users) {
            if ($enterpriseUser.Email -and $lookup.ContainsKey(([string]$enterpriseUser.Email).ToLowerInvariant())) {
                $candidateUserIds.Add([long]$enterpriseUser.Id) | Out-Null
            }
        }
    }

    if ($hasTeamFilter) {
        $hasPrefilter = $true
        foreach ($teamRef in $Team) {
            if ([string]::IsNullOrWhiteSpace([string]$teamRef)) {
                continue
            }
            $resolvedTeam = Get-KeeperTeamByNameOrUid -EnterpriseData $enterpriseData -TeamInput $teamRef
            if (-not $resolvedTeam) {
                Write-Warning "No enterprise team matched '$teamRef' for compliance owner pre-filter."
                continue
            }
            foreach ($userUid in $enterpriseData.GetUsersForTeam($resolvedTeam.Uid)) {
                $candidateUserIds.Add([long]$userUid) | Out-Null
            }
        }
    }

    if (Test-KeeperComplianceHasNodeFilter -Node $Node) {
        $hasPrefilter = $true
        $nodeInput = $Node.Trim()
        $resolvedNode = Resolve-KeeperComplianceNode -Node $nodeInput -Context 'compliance owner pre-filter'
        $targetNodeId = [long]$resolvedNode.Id
        $rootNodeId = [long]$enterpriseData.RootNode.Id
        if ($targetNodeId -eq $rootNodeId) {
            if ($candidateUserIds.Count -eq 0 -and -not $hasUsernameFilter -and -not $hasTeamFilter) {
                foreach ($enterpriseUser in $enterpriseData.Users) {
                    $candidateUserIds.Add([long]$enterpriseUser.Id) | Out-Null
                }
            }
        }
        else {
            $nodeMatchedUserIds = [System.Collections.Generic.HashSet[long]]::new()
            foreach ($enterpriseUser in $enterpriseData.Users) {
                $userNodeId = [long]$enterpriseUser.ParentNodeId
                if ($userNodeId -le 0) {
                    $userNodeId = $rootNodeId
                }
                if ($userNodeId -eq $targetNodeId) {
                    $nodeMatchedUserIds.Add([long]$enterpriseUser.Id) | Out-Null
                }
            }

            if ($candidateUserIds.Count -eq 0 -and -not $hasUsernameFilter -and -not $hasTeamFilter) {
                foreach ($userUid in $nodeMatchedUserIds) {
                    $candidateUserIds.Add([long]$userUid) | Out-Null
                }
            }
            else {
                $filteredUserIds = [System.Collections.Generic.HashSet[long]]::new()
                foreach ($userUid in $candidateUserIds) {
                    if ($nodeMatchedUserIds.Contains([long]$userUid)) {
                        $filteredUserIds.Add([long]$userUid) | Out-Null
                    }
                }
                $candidateUserIds = $filteredUserIds
            }
        }
    }

    if (-not $hasPrefilter) {
        return $null
    }

    return @(
        $candidateUserIds |
            Where-Object {
                $enterpriseUser = $null
                [bool]($enterpriseData.TryGetUserById([long]$_, [ref]$enterpriseUser) -and $enterpriseUser)
            } |
            Sort-Object
    )
}

function Get-KeeperComplianceDiskCacheRoot {
    return [System.IO.Path]::Combine(
        [Environment]::GetFolderPath('UserProfile'),
        '.keeper',
        'powercommander',
        'compliance_cache'
    )
}

function Get-KeeperComplianceSqliteDbPath {
    param(
        [Parameter(Mandatory = $true)]$Enterprise,
        [Parameter(Mandatory = $true)]$Auth
    )

    $server = [string]$Auth.Endpoint.Server
    if ([string]::IsNullOrWhiteSpace($server)) {
        $server = 'keepersecurity.com'
    }
    $safeServer = [System.Text.RegularExpressions.Regex]::Replace($server, '[^\w\-\.]', '_')
    $entId = 0L
    if ($Enterprise.enterpriseData -and $Enterprise.enterpriseData.EnterpriseLicense) {
        $entId = [long]$Enterprise.enterpriseData.EnterpriseLicense.EnterpriseLicenseId
    }
    $mc = 0
    if ($Script:Context.ManagedCompanyId) {
        $mc = [int]$Script:Context.ManagedCompanyId
    }
    $suffix = if ($mc -gt 0) { "_mc$mc" } else { '' }
    $cacheRoot = Get-KeeperComplianceDiskCacheRoot
    $serverDir = [System.IO.Path]::Combine($cacheRoot, $safeServer)
    if (-not (Test-Path -LiteralPath $serverDir)) {
        [void][System.IO.Directory]::CreateDirectory($serverDir)
    }
    return [System.IO.Path]::Combine($serverDir, "compliance_${entId}${suffix}.db")
}

function Get-KeeperComplianceSqliteStorage {
    param(
        [Parameter(Mandatory = $true)]$Enterprise,
        [Parameter(Mandatory = $true)]$Auth
    )

    $dbPath = Get-KeeperComplianceSqliteDbPath -Enterprise $Enterprise -Auth $Auth
    if ($script:ComplianceSqliteStorage -and $script:ComplianceSqliteDbPath -eq $dbPath) {
        return $script:ComplianceSqliteStorage
    }

    $script:ComplianceSqliteStorage = $null
    $script:ComplianceSqliteDbPath = $null

    $connectionString = "Data Source=$dbPath;Pooling=True;"
    try {
        $storage = Get-SqliteComplianceStorageFromHelper -ConnectionString $connectionString
        $script:ComplianceSqliteStorage = $storage
        $script:ComplianceSqliteDbPath = $dbPath
        return $storage
    }
    catch {
        Write-Verbose -Message "[compliance] Failed to initialize SQLite compliance storage: $($_.Exception.Message)"
        return $null
    }
}

function Save-KeeperComplianceSnapshotToSqlite {
    param(
        [Parameter(Mandatory = $true)][string]$CacheKey,
        [Parameter(Mandatory = $true)]$Snapshot,
        [Parameter(Mandatory = $true)][bool]$Incomplete,
        [Parameter()][bool]$SharedOnly = $false,
        [Parameter(Mandatory = $true)]$Enterprise,
        [Parameter(Mandatory = $true)]$Auth
    )

    try {
        $storage = Get-KeeperComplianceSqliteStorage -Enterprise $Enterprise -Auth $Auth
        if (-not $storage) { return }

        $storage.ClearNonAgingData()

        $nowEpoch = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()

        $existingMeta = $null
        try { $existingMeta = @($storage.Metadata.GetAll()) | Select-Object -First 1 } catch { }

        $meta = New-Object KeeperSecurity.Compliance.ComplianceMetadata
        $meta.AccountUid = $CacheKey
        $meta.PrelimDataLastUpdate = $nowEpoch
        $meta.ComplianceDataLastUpdate = $nowEpoch
        $meta.SharedRecordsOnly = $SharedOnly
        if ($existingMeta) {
            $meta.RecordsDated = $existingMeta.RecordsDated
            $meta.LastPwAudit = $existingMeta.LastPwAudit
        }
        $storage.Metadata.Store($meta)

        $userEntities = [System.Collections.Generic.List[KeeperSecurity.Compliance.ComplianceUser]]::new()
        foreach ($userUid in $Snapshot.Users.Keys) {
            $u = $Snapshot.Users[$userUid]
            $cu = New-Object KeeperSecurity.Compliance.ComplianceUser
            $cu.UserUid = [long]$userUid
            $cu.Email = [System.Text.Encoding]::UTF8.GetBytes([string]$u.Email)
            $cu.Status = 0
            $cu.JobTitle = if ($u.JobTitle) { [System.Text.Encoding]::UTF8.GetBytes([string]$u.JobTitle) } else { [byte[]]@() }
            $cu.FullName = if ($u.FullName) { [System.Text.Encoding]::UTF8.GetBytes([string]$u.FullName) } else { [byte[]]@() }
            $cu.NodeId = if ($u.NodeId) { [long]$u.NodeId } else { 0L }
            $cu.LastRefreshed = $nowEpoch
            $cu.LastComplianceRefreshed = $nowEpoch
            $cu.LastAgingRefreshed = 0L
            $userEntities.Add($cu)
        }
        if ($userEntities.Count -gt 0) {
            $storage.Users.PutEntities($userEntities)
        }

        $recordEntities = [System.Collections.Generic.List[KeeperSecurity.Compliance.ComplianceRecord]]::new()
        foreach ($recUid in $Snapshot.Records.Keys) {
            $r = $Snapshot.Records[$recUid]
            $cr = New-Object KeeperSecurity.Compliance.ComplianceRecord
            $cr.RecordUid = [string]$recUid
            $cr.RecordUidBytes = [KeeperSecurity.Utils.CryptoUtils]::Base64UrlDecode([string]$recUid)
            $titleJson = @{ title = [string]$r.Title; type = [string]$r.RecordType; url = [string]$r.Url } | ConvertTo-Json -Compress
            $cr.EncryptedData = [System.Text.Encoding]::UTF8.GetBytes($titleJson)
            $cr.Shared = [bool]$r.Shared
            $cr.InTrash = [bool]$r.InTrash
            $cr.HasAttachments = $false
            $cr.LastComplianceRefreshed = $nowEpoch
            $recordEntities.Add($cr)
        }
        if ($recordEntities.Count -gt 0) {
            $storage.Records.PutEntities($recordEntities)
        }

        $userRecordLinks = [System.Collections.Generic.List[KeeperSecurity.Compliance.ComplianceUserRecordLink]]::new()
        foreach ($ownerUid in $Snapshot.OwnedRecordsByUser.Keys) {
            foreach ($recUid in $Snapshot.OwnedRecordsByUser[$ownerUid]) {
                $link = New-Object KeeperSecurity.Compliance.ComplianceUserRecordLink
                $link.RecordUid = [string]$recUid
                $link.UserUid = [long]$ownerUid
                $userRecordLinks.Add($link)
            }
        }
        if ($userRecordLinks.Count -gt 0) {
            $storage.UserRecordLinks.PutLinks($userRecordLinks)
        }

        $teamEntities = [System.Collections.Generic.List[KeeperSecurity.Compliance.ComplianceTeam]]::new()
        $teamUserLinks = [System.Collections.Generic.List[KeeperSecurity.Compliance.ComplianceTeamUserLink]]::new()
        foreach ($teamUid in $Snapshot.Teams.Keys) {
            $t = $Snapshot.Teams[$teamUid]
            $ct = New-Object KeeperSecurity.Compliance.ComplianceTeam
            $ct.TeamUid = [string]$teamUid
            $ct.TeamName = ''
            $ct.RestrictEdit = $false
            $ct.RestrictShare = $false
            $teamEntities.Add($ct)
            foreach ($memberUid in $t.Users) {
                $tl = New-Object KeeperSecurity.Compliance.ComplianceTeamUserLink
                $tl.TeamUid = [string]$teamUid
                $tl.UserUid = [long]$memberUid
                $teamUserLinks.Add($tl)
            }
        }
        if ($teamEntities.Count -gt 0) {
            $storage.Teams.PutEntities($teamEntities)
        }
        if ($teamUserLinks.Count -gt 0) {
            $storage.TeamUserLinks.PutLinks($teamUserLinks)
        }

        $sfRecordLinks = [System.Collections.Generic.List[KeeperSecurity.Compliance.ComplianceSfRecordLink]]::new()
        $sfUserLinks = [System.Collections.Generic.List[KeeperSecurity.Compliance.ComplianceSfUserLink]]::new()
        $sfTeamLinks = [System.Collections.Generic.List[KeeperSecurity.Compliance.ComplianceSfTeamLink]]::new()
        $recPermLinks = [System.Collections.Generic.List[KeeperSecurity.Compliance.ComplianceRecordPermissions]]::new()
        foreach ($sfUid in $Snapshot.SharedFolders.Keys) {
            $sf = $Snapshot.SharedFolders[$sfUid]
            foreach ($recUid in $sf.RecordPermissions.Keys) {
                $srl = New-Object KeeperSecurity.Compliance.ComplianceSfRecordLink
                $srl.FolderUid = [string]$sfUid
                $srl.RecordUid = [string]$recUid
                $srl.Permissions = [int]$sf.RecordPermissions[$recUid]
                $sfRecordLinks.Add($srl)
            }
            foreach ($userUid in $sf.Users) {
                $sul = New-Object KeeperSecurity.Compliance.ComplianceSfUserLink
                $sul.FolderUid = [string]$sfUid
                $sul.UserUid = [long]$userUid
                $sfUserLinks.Add($sul)
            }
            foreach ($teamUid in $sf.Teams) {
                $stl = New-Object KeeperSecurity.Compliance.ComplianceSfTeamLink
                $stl.FolderUid = [string]$sfUid
                $stl.TeamUid = [string]$teamUid
                $sfTeamLinks.Add($stl)
            }
        }
        if ($sfRecordLinks.Count -gt 0) {
            $storage.SfRecordLinks.PutLinks($sfRecordLinks)
        }
        if ($sfUserLinks.Count -gt 0) {
            $storage.SfUserLinks.PutLinks($sfUserLinks)
        }
        if ($sfTeamLinks.Count -gt 0) {
            $storage.SfTeamLinks.PutLinks($sfTeamLinks)
        }

        foreach ($recUid in $Snapshot.Records.Keys) {
            $r = $Snapshot.Records[$recUid]
            if ($r.UserPermissions -and $r.UserPermissions.Count -gt 0) {
                foreach ($userUid in $r.UserPermissions.Keys) {
                    $rp = New-Object KeeperSecurity.Compliance.ComplianceRecordPermissions
                    $rp.RecordUid = [string]$recUid
                    $rp.UserUid = [long]$userUid
                    $rp.Permissions = [int]$r.UserPermissions[$userUid]
                    $recPermLinks.Add($rp)
                }
            }
        }
        if ($recPermLinks.Count -gt 0) {
            $storage.RecordPermissions.PutLinks($recPermLinks)
        }

        Write-KeeperComplianceStatus "Saved compliance snapshot to SQLite."
    }
    catch {
        Write-Verbose -Message "[compliance] Failed to save SQLite cache: $($_.Exception.Message)"
    }
}

function Import-KeeperComplianceSnapshotFromSqlite {
    param(
        [Parameter(Mandatory = $true)][string]$CacheKey,
        [Parameter(Mandatory = $true)][TimeSpan]$CacheTtl,
        [Parameter(Mandatory = $true)]$Enterprise,
        [Parameter(Mandatory = $true)]$Auth
    )

    try {
        $storage = Get-KeeperComplianceSqliteStorage -Enterprise $Enterprise -Auth $Auth
        if (-not $storage) { return $null }

        $meta = $storage.Metadata.Load()
        if (-not $meta) { return $null }
        if ($meta.AccountUid -ne $CacheKey) { return $null }

        $loadedEpoch = $meta.ComplianceDataLastUpdate
        if ($loadedEpoch -le 0) { return $null }
        $loadedAt = [DateTimeOffset]::FromUnixTimeSeconds($loadedEpoch).LocalDateTime
        if (((Get-Date) - $loadedAt) -ge $CacheTtl) { return $null }

        $snapshot = [PSCustomObject]@{
            Users              = @{}
            Records            = @{}
            SharedFolders      = @{}
            Teams              = @{}
            OwnedRecordsByUser = @{}
        }

        foreach ($cu in $storage.Users.GetAll()) {
            $email = if ($cu.Email) { [System.Text.Encoding]::UTF8.GetString($cu.Email) } else { '' }
            $fullName = if ($cu.FullName -and $cu.FullName.Length -gt 0) { [System.Text.Encoding]::UTF8.GetString($cu.FullName) } else { '' }
            $jobTitle = if ($cu.JobTitle -and $cu.JobTitle.Length -gt 0) { [System.Text.Encoding]::UTF8.GetString($cu.JobTitle) } else { '' }
            $snapshot.Users[[long]$cu.UserUid] = [PSCustomObject]@{
                UserUid  = [long]$cu.UserUid
                Email    = $email
                FullName = $fullName
                JobTitle = $jobTitle
                NodeId   = [long]$cu.NodeId
            }
        }

        foreach ($cr in $storage.Records.GetAll()) {
            $recData = @{ Title = ''; RecordType = ''; Url = '' }
            if ($cr.EncryptedData -and $cr.EncryptedData.Length -gt 0) {
                try {
                    $json = [System.Text.Encoding]::UTF8.GetString($cr.EncryptedData) | ConvertFrom-Json
                    $recData.Title = [string]$json.title
                    $recData.RecordType = [string]$json.type
                    $recData.Url = [string]$json.url
                } catch {
                    Write-Verbose -Message "[compliance] Could not parse record data for $($cr.RecordUid): $($_.Exception.Message)"
                }
            }
            $snapshot.Records[[string]$cr.RecordUid] = [PSCustomObject]@{
                Uid              = [string]$cr.RecordUid
                Title            = $recData.Title
                RecordType       = $recData.RecordType
                Url              = $recData.Url
                Shared           = [bool]$cr.Shared
                InTrash          = [bool]$cr.InTrash
                UserPermissions  = @{}
                SharedFolderUids = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
            }
        }

        foreach ($rp in $storage.RecordPermissions.GetAllLinks()) {
            $recUid = [string]$rp.RecordUid
            if ($snapshot.Records.ContainsKey($recUid)) {
                $snapshot.Records[$recUid].UserPermissions[[long]$rp.UserUid] = [int]$rp.Permissions
            }
        }

        foreach ($link in $storage.UserRecordLinks.GetAllLinks()) {
            $userUid = [long]$link.UserUid
            $recUid = [string]$link.RecordUid
            if (-not $snapshot.OwnedRecordsByUser.ContainsKey($userUid)) {
                $snapshot.OwnedRecordsByUser[$userUid] = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
            }
            $snapshot.OwnedRecordsByUser[$userUid].Add($recUid) | Out-Null
        }

        foreach ($ct in $storage.Teams.GetAll()) {
            $teamUid = [string]$ct.TeamUid
            $teamUsers = [System.Collections.Generic.HashSet[long]]::new()
            foreach ($tl in $storage.TeamUserLinks.GetLinksForSubject($teamUid)) {
                $teamUsers.Add([long]$tl.UserUid) | Out-Null
            }
            $snapshot.Teams[$teamUid] = [PSCustomObject]@{
                Uid   = $teamUid
                Users = $teamUsers
            }
        }

        $sfMap = @{}
        foreach ($srl in $storage.SfRecordLinks.GetAllLinks()) {
            $sfUid = [string]$srl.FolderUid
            if (-not $sfMap.ContainsKey($sfUid)) {
                $sfMap[$sfUid] = [PSCustomObject]@{
                    Uid               = $sfUid
                    Users             = [System.Collections.Generic.HashSet[long]]::new()
                    Teams             = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
                    RecordPermissions = @{}
                }
            }
            $sfMap[$sfUid].RecordPermissions[[string]$srl.RecordUid] = [int]$srl.Permissions
            if ($snapshot.Records.ContainsKey([string]$srl.RecordUid)) {
                $snapshot.Records[[string]$srl.RecordUid].SharedFolderUids.Add($sfUid) | Out-Null
            }
        }
        foreach ($sul in $storage.SfUserLinks.GetAllLinks()) {
            $sfUid = [string]$sul.FolderUid
            if (-not $sfMap.ContainsKey($sfUid)) {
                $sfMap[$sfUid] = [PSCustomObject]@{
                    Uid               = $sfUid
                    Users             = [System.Collections.Generic.HashSet[long]]::new()
                    Teams             = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
                    RecordPermissions = @{}
                }
            }
            $sfMap[$sfUid].Users.Add([long]$sul.UserUid) | Out-Null
        }
        foreach ($stl in $storage.SfTeamLinks.GetAllLinks()) {
            $sfUid = [string]$stl.FolderUid
            if (-not $sfMap.ContainsKey($sfUid)) {
                $sfMap[$sfUid] = [PSCustomObject]@{
                    Uid               = $sfUid
                    Users             = [System.Collections.Generic.HashSet[long]]::new()
                    Teams             = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
                    RecordPermissions = @{}
                }
            }
            $sfMap[$sfUid].Teams.Add([string]$stl.TeamUid) | Out-Null
        }
        $snapshot.SharedFolders = $sfMap

        return @{
            Snapshot        = $snapshot
            LoadedAt        = $loadedAt
            Incomplete      = $false
            SharedRecordsOnly = [bool]$meta.SharedRecordsOnly
        }
    }
    catch {
        Write-Verbose -Message "[compliance] Failed to load SQLite cache: $($_.Exception.Message)"
        return $null
    }
}

function Import-KeeperComplianceAgingCacheFromSqlite {
    param(
        [Parameter(Mandatory = $true)]$Enterprise,
        [Parameter(Mandatory = $true)]$Auth
    )

    try {
        $storage = Get-KeeperComplianceSqliteStorage -Enterprise $Enterprise -Auth $Auth
        if (-not $storage) { return }

        if (-not $script:ComplianceAgingCache) {
            $script:ComplianceAgingCache = @{ Entries = @{} }
        }
        if (-not $script:ComplianceAgingCache.Entries) {
            $script:ComplianceAgingCache.Entries = @{}
        }
        $cacheTtl = [TimeSpan]::FromDays(1)
        $nowEpoch = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()

        foreach ($aging in $storage.RecordAging.GetAll()) {
            $recUid = [string]$aging.RecordUid
            if ($script:ComplianceAgingCache.Entries.ContainsKey($recUid)) {
                continue
            }
            if ($aging.LastCached -le 0) { continue }
            if (($nowEpoch - $aging.LastCached) -ge $cacheTtl.TotalSeconds) { continue }

            $lcDt = [DateTimeOffset]::FromUnixTimeSeconds($aging.LastCached).LocalDateTime
            $script:ComplianceAgingCache.Entries[$recUid] = @{
                Created      = if ($aging.Created -gt 0) { [DateTimeOffset]::FromUnixTimeSeconds($aging.Created).LocalDateTime } else { $null }
                LastPwChange = if ($aging.LastPwChange -gt 0) { [DateTimeOffset]::FromUnixTimeSeconds($aging.LastPwChange).LocalDateTime } else { $null }
                LastModified = if ($aging.LastModified -gt 0) { [DateTimeOffset]::FromUnixTimeSeconds($aging.LastModified).LocalDateTime } else { $null }
                LastRotation = if ($aging.LastRotation -gt 0) { [DateTimeOffset]::FromUnixTimeSeconds($aging.LastRotation).LocalDateTime } else { $null }
                LastCached   = $lcDt
            }
        }
    }
    catch {
        Write-Verbose -Message "[compliance] Failed to import aging from SQLite: $($_.Exception.Message)"
    }
}

function Save-KeeperComplianceAgingCacheToSqlite {
    param(
        [Parameter(Mandatory = $true)]$Enterprise,
        [Parameter(Mandatory = $true)]$Auth
    )

    if (-not $script:ComplianceAgingCache -or -not $script:ComplianceAgingCache.Entries) {
        return
    }
    try {
        $storage = Get-KeeperComplianceSqliteStorage -Enterprise $Enterprise -Auth $Auth
        if (-not $storage) { return }

        $entities = [System.Collections.Generic.List[KeeperSecurity.Compliance.ComplianceRecordAging]]::new()
        foreach ($k in $script:ComplianceAgingCache.Entries.Keys) {
            $e = $script:ComplianceAgingCache.Entries[$k]
            $ra = New-Object KeeperSecurity.Compliance.ComplianceRecordAging
            $ra.RecordUid = [string]$k
            $ra.Created = if ($e.Created) { [int64][DateTimeOffset]::new([datetime]$e.Created).ToUnixTimeSeconds() } else { 0L }
            $ra.LastPwChange = if ($e.LastPwChange) { [int64][DateTimeOffset]::new([datetime]$e.LastPwChange).ToUnixTimeSeconds() } else { 0L }
            $ra.LastModified = if ($e.LastModified) { [int64][DateTimeOffset]::new([datetime]$e.LastModified).ToUnixTimeSeconds() } else { 0L }
            $ra.LastRotation = if ($e.LastRotation) { [int64][DateTimeOffset]::new([datetime]$e.LastRotation).ToUnixTimeSeconds() } else { 0L }
            $ra.LastCached = if ($e.LastCached) { [int64][DateTimeOffset]::new([datetime]$e.LastCached).ToUnixTimeSeconds() } else { 0L }
            $entities.Add($ra)
        }
        if ($entities.Count -gt 0) {
            $storage.RecordAging.PutEntities($entities)
        }
    }
    catch {
        Write-Verbose -Message "[compliance] Failed to save aging to SQLite: $($_.Exception.Message)"
    }
}

function Remove-KeeperComplianceSqliteCache {
    param(
        [Parameter(Mandatory = $true)]$Enterprise,
        [Parameter(Mandatory = $true)]$Auth
    )

    $script:ComplianceSqliteStorage = $null
    $script:ComplianceSqliteDbPath = $null
    $dbPath = Get-KeeperComplianceSqliteDbPath -Enterprise $Enterprise -Auth $Auth
    if (Test-Path -LiteralPath $dbPath) {
        try {
            [Microsoft.Data.Sqlite.SqliteConnection]::ClearAllPools()
            [System.GC]::Collect()
            [System.GC]::WaitForPendingFinalizers()
        }
        catch {
            Write-Verbose -Message "[compliance] Could not clear SQLite connection pools: $($_.Exception.Message)"
        }
        Remove-Item -LiteralPath $dbPath -Force -ErrorAction SilentlyContinue
        foreach ($sidecar in @("$dbPath-wal", "$dbPath-shm")) {
            if (Test-Path -LiteralPath $sidecar) {
                Remove-Item -LiteralPath $sidecar -Force -ErrorAction SilentlyContinue
            }
        }
        if (Test-Path -LiteralPath $dbPath) {
            Write-Warning "[compliance] SQLite cache file could not be deleted (may be locked): $dbPath"
        }
        else {
            Write-Verbose -Message "[compliance] Removed SQLite cache: $dbPath"
        }
    }
}

function Assert-KeeperComplianceReportAccess {
    $enterprise = getEnterprise
    if (-not $enterprise -or -not $enterprise.loader -or -not $enterprise.roleData) {
        Write-Error "Enterprise connection is required for compliance reports." -ErrorAction Stop
    }
    $auth = $enterprise.loader.Auth
    $username = [string]$auth.Username
    if ([string]::IsNullOrWhiteSpace($username)) {
        Write-Error "Could not determine login username for compliance access validation." -ErrorAction Stop
    }
    $enterpriseUser = $null
    if (-not $enterprise.enterpriseData.TryGetUserByEmail($username, [ref]$enterpriseUser) -or -not $enterpriseUser) {
        foreach ($u in $enterprise.enterpriseData.Users) {
            if ($u.Email -and [string]::Compare([string]$u.Email, $username, $true) -eq 0) {
                $enterpriseUser = $u
                break
            }
        }
    }
    if (-not $enterpriseUser) {
        Write-Error "Could not resolve your enterprise user for compliance access validation. Your login ($username) was not found among enterprise users." -ErrorAction Stop
    }
    $uid = [long]$enterpriseUser.Id
    $hasPrivilege = $false
    foreach ($roleId in @($enterprise.roleData.GetRolesForUser($uid))) {
        foreach ($rp in @($enterprise.roleData.GetRolePermissions($roleId))) {
            if ($rp.RunComplianceReports) {
                $hasPrivilege = $true
                break
            }
        }
        if ($hasPrivilege) {
            break
        }
    }
    if (-not $hasPrivilege) {
        Write-Error "You do not have the required privilege to run a Compliance Report (RUN_COMPLIANCE_REPORTS)." -ErrorAction Stop
    }
    $license = $enterprise.enterpriseData.EnterpriseLicense
    $addonOk = $false
    if ($license -and $license.AddOns) {
        foreach ($a in $license.AddOns) {
            if ([string]$a.Name -eq 'compliance_report' -and $a.Enabled) {
                $addonOk = $true
                break
            }
        }
    }
    if (-not $addonOk) {
        Write-Error "Compliance reports add-on is required to perform this action. Ask your administrator to enable the compliance_report add-on." -ErrorAction Stop
    }
}

function Import-KeeperComplianceAgingUserRefreshFromSqlite {
    param(
        [Parameter(Mandatory = $true)]$Enterprise,
        [Parameter(Mandatory = $true)]$Auth
    )

    try {
        $storage = Get-KeeperComplianceSqliteStorage -Enterprise $Enterprise -Auth $Auth
        if (-not $storage) { return @{} }

        $h = @{}
        foreach ($cu in $storage.Users.GetAll()) {
            if ($cu.LastAgingRefreshed -gt 0) {
                $h[[string]$cu.UserUid] = [long]$cu.LastAgingRefreshed
            }
        }
        return $h
    }
    catch {
        return @{}
    }
}

function Save-KeeperComplianceAgingUserRefreshToSqlite {
    param(
        [Parameter(Mandatory = $true)]$Enterprise,
        [Parameter(Mandatory = $true)]$Auth,
        [Parameter(Mandatory = $true)][long[]]$UserIds
    )

    try {
        $storage = Get-KeeperComplianceSqliteStorage -Enterprise $Enterprise -Auth $Auth
        if (-not $storage) { return }

        $nowTs = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        $updates = [System.Collections.Generic.List[KeeperSecurity.Compliance.ComplianceUser]]::new()
        foreach ($id in $UserIds) {
            $existing = $storage.Users.GetEntity([string]$id)
            if ($existing) {
                $cu = New-Object KeeperSecurity.Compliance.ComplianceUser
                $cu.UserUid = $existing.UserUid
                $cu.Email = $existing.Email
                $cu.Status = $existing.Status
                $cu.JobTitle = $existing.JobTitle
                $cu.FullName = $existing.FullName
                $cu.NodeId = $existing.NodeId
                $cu.LastRefreshed = $existing.LastRefreshed
                $cu.LastComplianceRefreshed = $existing.LastComplianceRefreshed
                $cu.LastAgingRefreshed = $nowTs
                $updates.Add($cu)
            }
        }
        if ($updates.Count -gt 0) {
            $storage.Users.PutEntities($updates)
        }
    }
    catch {
        Write-Verbose -Message "[compliance] Failed to save aging user refresh to SQLite: $($_.Exception.Message)"
    }
}

function ConvertTo-KeeperComplianceRowPlainText {
    param([Parameter(Mandatory = $true)]$Row)

    $parts = [System.Collections.Generic.List[string]]::new()
    foreach ($p in $Row.PSObject.Properties) {
        if ($p.Name -eq 'permission_bits') {
            continue
        }
        $v = $p.Value
        if ($null -eq $v) {
            continue
        }
        if (($v -is [System.Array]) -or (($v -is [System.Collections.IEnumerable]) -and -not ($v -is [string]))) {
            $parts.Add(($v | ForEach-Object { [string]$_ }) -join ' ') | Out-Null
        }
        else {
            $parts.Add([string]$v) | Out-Null
        }
    }
    return (($parts | ForEach-Object { $_ }) -join ' ').ToLowerInvariant()
}

function Invoke-KeeperCompliancePatternFilterRows {
    param(
        [Parameter(Mandatory = $true)]$Rows,
        [Parameter()][string[]]$Patterns,
        [Parameter()][switch]$UseRegex,
        [Parameter()][switch]$MatchAll
    )

    if (-not $Patterns -or $Patterns.Count -eq 0) {
        return $Rows
    }

    function Test-PatternOne {
        param([string]$PatternStr, [string]$Plain)

        $s = $PatternStr.Trim()
        if ($s.StartsWith('regex:')) {
            $rx = $s.Substring(6)
            try {
                return [regex]::IsMatch($Plain, $rx, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
            }
            catch {
                return $Plain.Contains($rx.ToLowerInvariant())
            }
        }
        if ($s.StartsWith('exact:')) {
            $ex = $s.Substring(6)
            return $Plain -ceq $ex.ToLowerInvariant()
        }
        if ($s.StartsWith('not:')) {
            $rest = $s.Substring(4).Trim()
            if ($rest.StartsWith('regex:')) {
                $rx = $rest.Substring(6)
                try {
                    return -not [regex]::IsMatch($Plain, $rx, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
                }
                catch {
                    return $Plain -notlike "*$($rx.ToLowerInvariant())*"
                }
            }
            if ($rest.StartsWith('exact:')) {
                $ex = $rest.Substring(6)
                return $Plain -cne $ex.ToLowerInvariant()
            }
            return $Plain -notlike "*$($rest.ToLowerInvariant())*"
        }
        if ($UseRegex) {
            try {
                return [regex]::IsMatch($Plain, $s, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
            }
            catch {
                return $Plain.Contains($s.ToLowerInvariant())
            }
        }
        return $Plain.Contains($s.ToLowerInvariant())
    }

    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($row in $Rows) {
        $plain = ConvertTo-KeeperComplianceRowPlainText -Row $row
        $results = foreach ($p in $Patterns) {
            Test-PatternOne -PatternStr ([string]$p) -Plain $plain
        }
        $ok = if ($MatchAll) { @($results) -notcontains $false } else { @($results) -contains $true }
        if ($ok) {
            $out.Add($row) | Out-Null
        }
    }
    return @($out)
}

