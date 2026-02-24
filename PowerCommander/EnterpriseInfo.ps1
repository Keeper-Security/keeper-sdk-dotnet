function Script:Get-EnterpriseNodeAndDescendantIds {
    param([object]$enterpriseData, [long]$rootId)
    if ($rootId -le 0) { return $null }
    $subnodes = @{}
    foreach ($n in $enterpriseData.Nodes) {
        $id = $n.Id
        if ($n.ParentNodeId -gt 0) {
            if (-not $subnodes[$n.ParentNodeId]) { $subnodes[$n.ParentNodeId] = [System.Collections.Generic.List[long]]::new() }
            $subnodes[$n.ParentNodeId].Add($id) | Out-Null
        }
    }
    $set = [System.Collections.Generic.HashSet[long]]::new()
    $queue = [System.Collections.Generic.Queue[long]]::new()
    $queue.Enqueue($rootId) | Out-Null
    while ($queue.Count -gt 0) {
        $nid = $queue.Dequeue()
        [void]$set.Add($nid)
        if ($subnodes[$nid]) { foreach ($c in $subnodes[$nid]) { $queue.Enqueue($c) | Out-Null } }
    }
    return $set
}

function Get-KeeperEnterpriseInfoTree {
    <#
    .SYNOPSIS
    Display a tree structure of the enterprise (nodes with users, roles, teams).
    .DESCRIPTION
    Outputs a tree view of the enterprise hierarchy (nodes with users, roles, and teams). Output format is always tree.
    .PARAMETER Node
    Limit output to this node and its descendants (node name or ID).
    .PARAMETER Detailed
    Include node IDs and list individual users/roles/teams by name.
    .PARAMETER Output
    If supplied, write output to this file path.
    .EXAMPLE
    Get-KeeperEnterpriseInfoTree
    Get-KeeperEnterpriseInfoTree -Node "Sales" -Detailed -Output tree.txt
    #>
    [CmdletBinding()]
    Param (
        [Parameter()][string] $Node,
        [Parameter()][switch] $Detailed,
        [Parameter()][string] $Output
    )
    $enterprise = getEnterprise
    $ed = $enterprise.enterpriseData
    $rd = $enterprise.roleData

    $subnodes = @{}
    foreach ($n in $ed.Nodes) {
        $id = $n.Id
        if (-not $subnodes.ContainsKey($id)) { $subnodes[$id] = [System.Collections.Generic.List[long]]::new() }
        if ($n.ParentNodeId -gt 0) {
            if (-not $subnodes.ContainsKey($n.ParentNodeId)) { $subnodes[$n.ParentNodeId] = [System.Collections.Generic.List[long]]::new() }
            $subnodes[$n.ParentNodeId].Add($id) | Out-Null
        }
    }

    $rootId = $ed.RootNode.Id
    if ($Node) {
        $resolved = resolveSingleNode $Node
        if (-not $resolved) { Write-Error "Node '$Node' not found"; return }
        $rootId = $resolved.Id
    }

    $usersByNode = @{}
    foreach ($u in $ed.Users) {
        $nid = $u.ParentNodeId
        if (-not $usersByNode.ContainsKey($nid)) { $usersByNode[$nid] = [System.Collections.Generic.List[object]]::new() }
        $usersByNode[$nid].Add($u) | Out-Null
    }
    $rolesByNode = @{}
    foreach ($r in $rd.Roles) {
        $nid = $r.ParentNodeId
        if (-not $rolesByNode.ContainsKey($nid)) { $rolesByNode[$nid] = [System.Collections.Generic.List[object]]::new() }
        $rolesByNode[$nid].Add($r) | Out-Null
    }
    $teamsByNode = @{}
    foreach ($t in $ed.Teams) {
        $nid = $t.ParentNodeId
        if (-not $teamsByNode.ContainsKey($nid)) { $teamsByNode[$nid] = [System.Collections.Generic.List[object]]::new() }
        $teamsByNode[$nid].Add($t) | Out-Null
    }

    $lines = [System.Collections.Generic.List[string]]::new()
    function writeTreeNode {
        param([long]$nodeId, [string]$prefix, [bool]$isLastSibling = $true)
        $n = $null
        if (-not $ed.TryGetNode($nodeId, [ref]$n)) { return }
        $name = $n.DisplayName
        if ([string]::IsNullOrEmpty($name)) { $name = $enterprise.loader.EnterpriseName }
        if ($Detailed) { $name += " ($nodeId)" }
        if ($n.RestrictVisibility) { $name += " |Isolated|" }
        if ($prefix -eq '') {
            $lines.Add($name) | Out-Null
        } else {
            $lines.Add("$prefix+-- $name") | Out-Null
        }
        $us = $usersByNode[$nodeId]; $ro = $rolesByNode[$nodeId]; $te = $teamsByNode[$nodeId]
        $childIds = if ($subnodes[$nodeId]) { @($subnodes[$nodeId]) } else { @() }
        $sortedChildIds = if ($childIds.Count -gt 0) { @($childIds | Sort-Object { $nn = $null; if ($ed.TryGetNode($_, [ref]$nn)) { $nn.DisplayName } else { '' } }) } else { @() }
        $contentItems = [System.Collections.Generic.List[object]]::new()
        foreach ($cid in $sortedChildIds) { $contentItems.Add([PSCustomObject]@{ NodeId = $cid }) | Out-Null }
        if ($us -and $us.Count -gt 0) {
            if ($Detailed) { foreach ($u in ($us | Sort-Object { $_.Email })) { $contentItems.Add($($u.Email) + " ($($u.Id))") | Out-Null } }
            else { $contentItems.Add("$($us.Count) user(s)") | Out-Null }
        }
        if ($ro -and $ro.Count -gt 0) {
            if ($Detailed) {
                $i = 0; foreach ($r in ($ro | Sort-Object { $_.DisplayName })) {
                    if ($i -ge 50) { $contentItems.Add("$($ro.Count - 50) more role(s)"); break }
                    $contentItems.Add("$($r.DisplayName) ($($r.Id))") | Out-Null; $i++
                }
            } else { $contentItems.Add("$($ro.Count) role(s)") | Out-Null }
        }
        if ($te -and $te.Count -gt 0) {
            if ($Detailed) {
                $i = 0; foreach ($t in ($te | Sort-Object { $_.Name })) {
                    if ($i -ge 50) { $contentItems.Add("$($te.Count - 50) more team(s)"); break }
                    $contentItems.Add("$($t.Name) ($($t.Uid))") | Out-Null; $i++
                }
            } else { $contentItems.Add("$($te.Count) team(s)") | Out-Null }
        }
        $total = $contentItems.Count
        for ($i = 0; $i -lt $total; $i++) {
            $isLast = ($i -eq $total - 1)
            $branch = if ($isLastSibling -and $isLast) { '    ' } else { ' |   ' }
            $connector = if ($prefix -eq '') { ' ' } else { $prefix + $branch }
            $item = $contentItems[$i]
            if ($item -is [string]) {
                $lines.Add("$connector+-- $item") | Out-Null
            } else {
                writeTreeNode -nodeId $item.NodeId -prefix $connector -isLastSibling $isLast
            }
        }
    }
    writeTreeNode -nodeId $rootId -prefix "" -isLastSibling $true
    $out = $lines -join "`n"
    if ($Output) {
        Set-Content -Path $Output -Value $out -Encoding utf8
    } else {
        $out
    }
}

function Get-KeeperEnterpriseInfoNode {
    <#
    .SYNOPSIS
    Display node information as a table.
    .DESCRIPTION
    Outputs nodes with parent path, user/team/role counts, and optionally user/team/role lists and provisioning.
    .PARAMETER Pattern
    Optional search pattern to filter nodes.
    .PARAMETER Columns
    Comma-separated columns: parent_node, user_count, users, team_count, teams, role_count, roles, provisioning. Default: parent_node, user_count, team_count, role_count.
    .PARAMETER Node
    Filter by node name or ID: only nodes that are this node or its descendants.
    .PARAMETER Format
    Output format: table (default), json, csv.
    .PARAMETER Output
    If supplied, write output to this file path.
    .PARAMETER Offset
    Number of rows to skip (for pagination). Default 0.
    .PARAMETER Limit
    Maximum number of rows to return (0 = no limit). Use with Offset for range/pagination.
    .EXAMPLE
    Get-KeeperEnterpriseInfoNode
    Get-KeeperEnterpriseInfoNode -Columns "parent_node,user_count,users" -Pattern "Sales" -Node "Sales" -Format json -Output nodes.json -Offset 0 -Limit 50
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0)][string] $Pattern,
        [Parameter()][string] $Columns,
        [Parameter()][string] $Node,
        [Parameter()][ValidateSet('table', 'json', 'csv')][string] $Format = 'table',
        [Parameter()][string] $Output,
        [Parameter()][int] $Offset = 0,
        [Parameter()][int] $Limit = 0
    )
    $enterprise = getEnterprise
    $ed = $enterprise.enterpriseData
    $rd = $enterprise.roleData
    $userCount = @{}; $teamCount = @{}; $roleCount = @{}
    $userList = @{}; $teamList = @{}; $roleList = @{}
    foreach ($u in $ed.Users) {
        $userCount[$u.ParentNodeId] = ((if ($null -ne $userCount[$u.ParentNodeId]) { $userCount[$u.ParentNodeId] } else { 0 }) + 1)
        if (-not $userList[$u.ParentNodeId]) { $userList[$u.ParentNodeId] = [System.Collections.Generic.List[string]]::new() }
        $userList[$u.ParentNodeId].Add($u.Email) | Out-Null
    }
    foreach ($t in $ed.Teams) {
        $nid = if ($t.ParentNodeId -eq 0) { $ed.RootNode.Id } else { $t.ParentNodeId }
        $teamCount[$nid] = ((if ($null -ne $teamCount[$nid]) { $teamCount[$nid] } else { 0 }) + 1)
        if (-not $teamList[$nid]) { $teamList[$nid] = [System.Collections.Generic.List[string]]::new() }
        $teamList[$nid].Add($t.Name) | Out-Null
    }
    foreach ($r in $rd.Roles) {
        $roleCount[$r.ParentNodeId] = ((if ($null -ne $roleCount[$r.ParentNodeId]) { $roleCount[$r.ParentNodeId] } else { 0 }) + 1)
        if (-not $roleList[$r.ParentNodeId]) { $roleList[$r.ParentNodeId] = [System.Collections.Generic.List[string]]::new() }
        $roleList[$r.ParentNodeId].Add($r.DisplayName) | Out-Null
    }
    $nodeFilterIds = $null
    if ($Node) {
        $resolved = resolveSingleNode $Node
        if (-not $resolved) { Write-Error "Node '$Node' not found"; return }
        $nodeFilterIds = Get-EnterpriseNodeAndDescendantIds $ed $resolved.Id
    }
    $colSet = @('parent_node', 'user_count', 'team_count', 'role_count')
    if ($Columns) {
        $colSet = @($Columns -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^(parent_node|user_count|users|team_count|teams|role_count|roles|provisioning)$' })
        if ($colSet.Count -eq 0) { $colSet = @('parent_node', 'user_count', 'team_count', 'role_count') }
    }
    $patternLower = if ($Pattern) { $Pattern.Trim().ToLower() } else { '' }
    $out = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($n in ($ed.Nodes | Sort-Object { $_.DisplayName })) {
        if ($nodeFilterIds -and -not $nodeFilterIds.Contains($n.Id)) { continue }
        $row = [ordered]@{ NodeId = $n.Id; Name = $n.DisplayName }
        foreach ($c in $colSet) {
            switch ($c) {
                'parent_node'   { $row['ParentNode'] = if ($n.ParentNodeId -le 0) { '' } else { Get-KeeperNodePath -NodeId $n.ParentNodeId } }
                'user_count'    { $row['UserCount'] = (if ($null -ne $userCount[$n.Id]) { $userCount[$n.Id] } else { 0 }) }
                'users'         { $row['Users'] = ($userList[$n.Id] | Sort-Object) -join ', ' }
                'team_count'    { $row['TeamCount'] = (if ($null -ne $teamCount[$n.Id]) { $teamCount[$n.Id] } else { 0 }) }
                'teams'         { $row['Teams'] = ($teamList[$n.Id] | Sort-Object) -join ', ' }
                'role_count'   { $row['RoleCount'] = (if ($null -ne $roleCount[$n.Id]) { $roleCount[$n.Id] } else { 0 }) }
                'roles'         { $row['Roles'] = ($roleList[$n.Id] | Sort-Object) -join ', ' }
                'provisioning'  { $parts = @(); if ($n.BridgeId -gt 0) { $parts += 'Bridge' }; if ($n.ScimId -gt 0) { $parts += 'SCIM' }; if ($n.SsoServiceProviderIds -and $n.SsoServiceProviderIds.Length -gt 0) { $parts += 'SSO' }; $row['Provisioning'] = ($parts -join ', ') }
            }
        }
        if ($patternLower) {
            $text = ($row.Values | ForEach-Object { $_ }) -join ' '
            if ($text -notmatch [regex]::Escape($patternLower)) { continue }
        }
        $out.Add([PSCustomObject]$row) | Out-Null
    }
    $result = @($out | Sort-Object { $_.Name })
    if ($Offset -gt 0) { $result = @($result | Select-Object -Skip $Offset) }
    if ($Limit -gt 0) { $result = @($result | Select-Object -First $Limit) }
    if ($Format -eq 'table') { $disp = $result | Format-Table -AutoSize } else { $disp = $result }
    if ($Output) {
        if ($Format -eq 'json') { Set-Content -Path $Output -Value ($result | ConvertTo-Json -Depth 5) -Encoding utf8 }
        elseif ($Format -eq 'csv') { Set-Content -Path $Output -Value ($result | ConvertTo-Csv -NoTypeInformation) -Encoding utf8 }
        else { $result | Format-Table -AutoSize | Out-String | Set-Content -Path $Output -Encoding utf8 }
    } else {
        if ($Format -eq 'table') { $disp } else { $disp }
    }
}

function Get-KeeperEnterpriseInfoUser {
    <#
    .SYNOPSIS
    Display user information as a table.
    .DESCRIPTION
    Outputs users with status, node, roles, teams, and optional columns.
    .PARAMETER Pattern
    Optional search pattern to filter users.
    .PARAMETER Columns
    Comma-separated columns: name, status, transfer_status, node, role_count, roles, team_count, teams, queued_team_count, queued_teams, alias, 2fa_enabled. Default: name, status, transfer_status, node.
    .PARAMETER Node
    Filter by node name or ID: only users in this node or its descendants.
    .PARAMETER Format
    Output format: table (default), json, csv.
    .PARAMETER Output
    If supplied, write output to this file path.
    .PARAMETER Offset
    Number of rows to skip (for pagination). Default 0.
    .PARAMETER Limit
    Maximum number of rows to return (0 = no limit). Use with Offset for range/pagination.
    .EXAMPLE
    Get-KeeperEnterpriseInfoUser
    Get-KeeperEnterpriseInfoUser -Columns "name,status,node,roles" -Pattern "admin" -Node "Sales" -Format json -Output users.json -Offset 0 -Limit 100
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0)][string] $Pattern,
        [Parameter()][string] $Columns,
        [Parameter()][string] $Node,
        [Parameter()][ValidateSet('table', 'json', 'csv')][string] $Format = 'table',
        [Parameter()][string] $Output,
        [Parameter()][int] $Offset = 0,
        [Parameter()][int] $Limit = 0
    )
    $enterprise = getEnterprise
    $ed = $enterprise.enterpriseData
    $rd = $enterprise.roleData
    $roleUsers = @{}
    foreach ($r in $rd.Roles) {
        foreach ($uid in @($rd.GetUsersForRole($r.Id))) {
            if (-not $roleUsers[$uid]) { $roleUsers[$uid] = [System.Collections.Generic.List[long]]::new() }
            $roleUsers[$uid].Add($r.Id) | Out-Null
        }
    }
    $teamUsers = @{}
    foreach ($t in $ed.Teams) {
        foreach ($uid in @($ed.GetUsersForTeam($t.Uid))) {
            if (-not $teamUsers[$uid]) { $teamUsers[$uid] = [System.Collections.Generic.List[string]]::new() }
            $teamUsers[$uid].Add($t.Name) | Out-Null
        }
    }
    $colSet = @('name', 'status', 'transfer_status', 'node')
    if ($Columns) {
        $colSet = @($Columns -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^(name|status|transfer_status|node|role_count|roles|team_count|teams|queued_team_count|queued_teams|alias|2fa_enabled)$' })
        if ($colSet.Count -eq 0) { $colSet = @('name', 'status', 'transfer_status', 'node') }
    }
    $nodeFilterIds = $null
    if ($Node) {
        $resolved = resolveSingleNode $Node
        $nodeFilterIds = Get-EnterpriseNodeAndDescendantIds $ed $resolved.Id
    }
    $statusText = { param($s) switch ($s) { 'Active' { 'Active' } 'Inactive' { 'Invited' } 'Locked' { 'Locked' } 'Blocked' { 'Blocked' } 'Disabled' { 'Disabled' } default { $s } } }
    $transferText = { param($s) switch ([int]$s) { 0 { 'Undefined' } 1 { 'Not required' } 2 { 'Pending transfer' } 3 { 'Partially accepted' } 4 { 'Transfer accepted' } default { $s } } }
    $patternLower = if ($Pattern) { $Pattern.Trim().ToLower() } else { '' }
    $out = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($u in ($ed.Users | Sort-Object { $_.Email })) {
        $nid = if ($u.ParentNodeId -le 0) { $ed.RootNode.Id } else { $u.ParentNodeId }
        if ($nodeFilterIds -and -not $nodeFilterIds.Contains($nid)) { continue }
        $row = [ordered]@{ UserId = $u.Id; Email = $u.Email }
        foreach ($c in $colSet) {
            switch ($c) {
                'name'             { $row['Name'] = $u.DisplayName }
                'status'           { $row['Status'] = & $statusText $u.UserStatus }
                'transfer_status'  { $row['TransferStatus'] = & $transferText $u.TransferAcceptanceStatus }
                'node'             { $row['Node'] = Get-KeeperNodePath -NodeId $u.ParentNodeId -OmitRoot }
                'role_count'       { $row['RoleCount'] = (if ($null -ne $roleUsers[$u.Id]) { $roleUsers[$u.Id].Count } else { 0 }) }
                'roles'            { $rnames = @($roleUsers[$u.Id] | ForEach-Object { $rr = $null; if ($rd.TryGetRole($_, [ref]$rr)) { $rr.DisplayName } } | Sort-Object); $row['Roles'] = ($rnames -join ', ') }
                'team_count'       { $row['TeamCount'] = (if ($null -ne $teamUsers[$u.Id]) { $teamUsers[$u.Id].Count } else { 0 }) }
                'teams'            { $row['Teams'] = (($teamUsers[$u.Id] | Sort-Object) -join ', ') }
                'queued_team_count' { $row['QueuedTeamCount'] = 0 }
                'queued_teams'      { $row['QueuedTeams'] = '' }
                'alias'            { $row['Alias'] = '' }
                '2fa_enabled'      { $row['2FAEnabled'] = $u.TwoFactorEnabled }
            }
        }
        if ($patternLower) {
            $text = ($row.Values | ForEach-Object { $_ }) -join ' '
            if ($text -notmatch [regex]::Escape($patternLower)) { continue }
        }
        $out.Add([PSCustomObject]$row) | Out-Null
    }
    $result = @($out | Sort-Object { $_.Email })
    if ($Offset -gt 0) { $result = @($result | Select-Object -Skip $Offset) }
    if ($Limit -gt 0) { $result = @($result | Select-Object -First $Limit) }
    if ($Output) {
        if ($Format -eq 'json') { Set-Content -Path $Output -Value ($result | ConvertTo-Json -Depth 5) -Encoding utf8 }
        elseif ($Format -eq 'csv') { Set-Content -Path $Output -Value ($result | ConvertTo-Csv -NoTypeInformation) -Encoding utf8 }
        else { $result | Format-Table -AutoSize | Out-String | Set-Content -Path $Output -Encoding utf8 }
    } else {
        if ($Format -eq 'table') { $result | Format-Table -AutoSize } else { $result }
    }
}

function Get-KeeperEnterpriseInfoTeam {
    <#
    .SYNOPSIS
    Display team information as a table.
    .DESCRIPTION
    Outputs teams with restricts (Read/Write/Share), node, user/role counts, and optional user/role lists.
    .PARAMETER Pattern
    Optional search pattern to filter teams.
    .PARAMETER Columns
    Comma-separated columns: restricts, node, user_count, users, queued_user_count, queued_users, role_count, roles. Default: restricts, node, user_count.
    .PARAMETER Node
    Filter by node name or ID: only teams in this node or its descendants.
    .PARAMETER Format
    Output format: table (default), json, csv.
    .PARAMETER Output
    If supplied, write output to this file path.
    .PARAMETER Offset
    Number of rows to skip (for pagination). Default 0.
    .PARAMETER Limit
    Maximum number of rows to return (0 = no limit). Use with Offset for range/pagination.
    .EXAMPLE
    Get-KeeperEnterpriseInfoTeam
    Get-KeeperEnterpriseInfoTeam -Columns "restricts,node,user_count,users" -Pattern "Eng" -Node "Engineering" -Format json -Output teams.json -Offset 0 -Limit 50
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0)][string] $Pattern,
        [Parameter()][string] $Columns,
        [Parameter()][string] $Node,
        [Parameter()][switch] $ExactNode,
        [Parameter()][ValidateSet('table', 'json', 'csv')][string] $Format = 'table',
        [Parameter()][string] $Output,
        [Parameter()][int] $Offset = 0,
        [Parameter()][int] $Limit = 0
    )
    $enterprise = getEnterprise
    $ed = $enterprise.enterpriseData
    $rd = $enterprise.roleData
    $userCount = @{}; $roleCount = @{}
    $userList = @{}; $roleList = @{}
    foreach ($t in $ed.Teams) {
        $uids = @($ed.GetUsersForTeam($t.Uid))
        $userCount[$t.Uid] = $uids.Count
        $userList[$t.Uid] = @($uids | ForEach-Object { $uu = $null; if ($ed.TryGetUserById($_, [ref]$uu)) { $uu.Email } } | Sort-Object)
    }
    foreach ($t in $ed.Teams) {
        foreach ($rid in @($rd.GetRolesForTeam($t.Uid))) {
            if (-not $roleList[$t.Uid]) { $roleList[$t.Uid] = [System.Collections.Generic.List[string]]::new() }
            $rr = $null; if ($rd.TryGetRole($rid, [ref]$rr)) { $roleList[$t.Uid].Add($rr.DisplayName) | Out-Null }
        }
    }
    $nodeFilterIds = $null
    if ($Node) {
        $resolved = resolveSingleNode $Node
        if ($ExactNode) {
            $nodeFilterIds = [System.Collections.Generic.HashSet[long]]::new()
            [void]$nodeFilterIds.Add($resolved.Id)
        } else {
            $nodeFilterIds = Get-EnterpriseNodeAndDescendantIds $ed $resolved.Id
        }
    }
    $colSet = @('restricts', 'node', 'user_count')
    if ($Columns) {
        $colSet = @($Columns -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^(restricts|node|user_count|users|queued_user_count|queued_users|role_count|roles)$' })
        if ($colSet.Count -eq 0) { $colSet = @('restricts', 'node', 'user_count') }
    }
    $patternLower = if ($Pattern) { $Pattern.Trim().ToLower() } else { '' }
    $out = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($t in ($ed.Teams | Sort-Object { $_.Name })) {
        $nid = if ($t.ParentNodeId -eq 0) { $ed.RootNode.Id } else { $t.ParentNodeId }
        if ($nodeFilterIds -and -not $nodeFilterIds.Contains($nid)) { continue }
        $restrictParts = @()
        if ($t.RestrictView) { $restrictParts += 'Read' }
        if ($t.RestrictEdit) { $restrictParts += 'Write' }
        if ($t.RestrictSharing) { $restrictParts += 'Share' }
        $restricts = $restrictParts -join ', '
        $row = [ordered]@{ TeamUid = $t.Uid; Name = $t.Name }
        foreach ($c in $colSet) {
            switch ($c) {
                'restricts'        { $row['Restricts'] = $restricts }
                'node'             { $row['Node'] = Get-KeeperNodePath -NodeId $t.ParentNodeId -OmitRoot }
                'user_count'       { $row['UserCount'] = (if ($null -ne $userCount[$t.Uid]) { $userCount[$t.Uid] } else { 0 }) }
                'users'            { $row['Users'] = ($userList[$t.Uid] -join ', ') }
                'queued_user_count'{ $row['QueuedUserCount'] = 0 }
                'queued_users'     { $row['QueuedUsers'] = '' }
                'role_count'       { $row['RoleCount'] = (if ($null -ne $roleList[$t.Uid]) { $roleList[$t.Uid].Count } else { 0 }) }
                'roles'            { $row['Roles'] = (($roleList[$t.Uid] | Sort-Object) -join ', ') }
            }
        }
        if ($patternLower) {
            $text = ($row.Values | ForEach-Object { $_ }) -join ' '
            if ($text -notmatch [regex]::Escape($patternLower)) { continue }
        }
        $out.Add([PSCustomObject]$row) | Out-Null
    }
    $result = @($out | Sort-Object { $_.Name })
    if ($Offset -gt 0) { $result = @($result | Select-Object -Skip $Offset) }
    if ($Limit -gt 0) { $result = @($result | Select-Object -First $Limit) }
    if ($Output) {
        if ($Format -eq 'json') { Set-Content -Path $Output -Value ($result | ConvertTo-Json -Depth 5) -Encoding utf8 }
        elseif ($Format -eq 'csv') { Set-Content -Path $Output -Value ($result | ConvertTo-Csv -NoTypeInformation) -Encoding utf8 }
        else { $result | Format-Table -AutoSize | Out-String | Set-Content -Path $Output -Encoding utf8 }
    } else {
        if ($Format -eq 'table') { $result | Format-Table -AutoSize } else { $result }
    }
}

function Get-KeeperEnterpriseInfoRole {
    <#
    .SYNOPSIS
    Display role information as a table.
    .DESCRIPTION
    Outputs roles with node, user/team counts, admin flag, and optional user/team lists.
    .PARAMETER Pattern
    Optional search pattern to filter roles.
    .PARAMETER Columns
    Comma-separated columns: visible_below, default_role, admin, node, user_count, users, team_count, teams. Default: default_role, admin, node, user_count.
    .PARAMETER Node
    Filter by node name or ID: only roles in this node or its descendants.
    .PARAMETER Format
    Output format: table (default), json, csv.
    .PARAMETER Output
    If supplied, write output to this file path.
    .PARAMETER Offset
    Number of rows to skip (for pagination). Default 0.
    .PARAMETER Limit
    Maximum number of rows to return (0 = no limit). Use with Offset for range/pagination.
    .EXAMPLE
    Get-KeeperEnterpriseInfoRole
    Get-KeeperEnterpriseInfoRole -Columns "visible_below,node,user_count,users" -Pattern "Admin" -Node "Sales" -Format json -Output roles.json -Offset 0 -Limit 50
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0)][string] $Pattern,
        [Parameter()][string] $Columns,
        [Parameter()][string] $Node,
        [Parameter()][switch] $ExactNode,
        [Parameter()][ValidateSet('table', 'json', 'csv')][string] $Format = 'table',
        [Parameter()][string] $Output,
        [Parameter()][int] $Offset = 0,
        [Parameter()][int] $Limit = 0
    )
    $enterprise = getEnterprise
    $ed = $enterprise.enterpriseData
    $rd = $enterprise.roleData
    $userCount = @{}; $teamCount = @{}
    $userList = @{}; $teamList = @{}
    foreach ($r in $rd.Roles) {
        $uids = @($rd.GetUsersForRole($r.Id))
        $userCount[$r.Id] = $uids.Count
        $userList[$r.Id] = @($uids | ForEach-Object { $uu = $null; if ($ed.TryGetUserById($_, [ref]$uu)) { $uu.Email } } | Sort-Object)
    }
    foreach ($r in $rd.Roles) {
        foreach ($tuid in @($rd.GetTeamsForRole($r.Id))) {
            if (-not $teamList[$r.Id]) { $teamList[$r.Id] = [System.Collections.Generic.List[string]]::new() }
            $tt = $null; if ($ed.TryGetTeam($tuid, [ref]$tt)) { $teamList[$r.Id].Add($tt.Name) | Out-Null }
        }
    }
    $nodeFilterIds = $null
    if ($Node) {
        $resolved = resolveSingleNode $Node
        if ($ExactNode) {
            $nodeFilterIds = [System.Collections.Generic.HashSet[long]]::new()
            [void]$nodeFilterIds.Add($resolved.Id)
        } else {
            $nodeFilterIds = Get-EnterpriseNodeAndDescendantIds $ed $resolved.Id
        }
    }
    $managedNodes = @($rd.GetManagedNodes())
    $adminRoleIds = [System.Collections.Generic.HashSet[long]]::new()
    foreach ($mn in $managedNodes) { [void]$adminRoleIds.Add($mn.RoleId) }
    $colSet = @('visible_below', 'default_role', 'admin', 'node', 'user_count')
    if ($Columns) {
        $colSet = @($Columns -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^(visible_below|default_role|admin|node|user_count|users|team_count|teams)$' })
        if ($colSet.Count -eq 0) { $colSet = @('default_role', 'admin', 'node', 'user_count') }
    }
    $patternLower = if ($Pattern) { $Pattern.Trim().ToLower() } else { '' }
    $out = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($r in ($rd.Roles | Sort-Object { $_.DisplayName })) {
        $nid = if ($r.ParentNodeId -le 0) { $ed.RootNode.Id } else { $r.ParentNodeId }
        if ($nodeFilterIds -and -not $nodeFilterIds.Contains($nid)) { continue }
        $row = [ordered]@{ RoleId = $r.Id; Name = $r.DisplayName }
        foreach ($c in $colSet) {
            switch ($c) {
                'visible_below'  { $row['VisibleBelow'] = $r.VisibleBelow }
                'default_role'   { $row['DefaultRole'] = $r.NewUserInherit }
                'admin'         { $row['Admin'] = $adminRoleIds.Contains($r.Id) }
                'node'          { $row['Node'] = Get-KeeperNodePath -NodeId $r.ParentNodeId -OmitRoot }
                'user_count'    { $row['UserCount'] = (if ($null -ne $userCount[$r.Id]) { $userCount[$r.Id] } else { 0 }) }
                'users'         { $row['Users'] = ($userList[$r.Id] -join ', ') }
                'team_count'    { $row['TeamCount'] = (if ($null -ne $teamList[$r.Id]) { $teamList[$r.Id].Count } else { 0 }) }
                'teams'         { $row['Teams'] = (($teamList[$r.Id] | Sort-Object) -join ', ') }
            }
        }
        if ($patternLower) {
            $text = ($row.Values | ForEach-Object { $_ }) -join ' '
            if ($text -notmatch [regex]::Escape($patternLower)) { continue }
        }
        $out.Add([PSCustomObject]$row) | Out-Null
    }
    $result = @($out | Sort-Object { $_.Name })
    if ($Offset -gt 0) { $result = @($result | Select-Object -Skip $Offset) }
    if ($Limit -gt 0) { $result = @($result | Select-Object -First $Limit) }
    if ($Output) {
        if ($Format -eq 'json') { Set-Content -Path $Output -Value ($result | ConvertTo-Json -Depth 5) -Encoding utf8 }
        elseif ($Format -eq 'csv') { Set-Content -Path $Output -Value ($result | ConvertTo-Csv -NoTypeInformation) -Encoding utf8 }
        else { $result | Format-Table -AutoSize | Out-String | Set-Content -Path $Output -Encoding utf8 }
    } else {
        if ($Format -eq 'table') { $result | Format-Table -AutoSize } else { $result }
    }
}

function Get-KeeperEnterpriseInfoManagedCompany {
    <#
    .SYNOPSIS
    Display managed company information (MSP only).
    .DESCRIPTION
    Outputs managed company information. Available when logged in as MSP.
    .PARAMETER Pattern
    Optional search pattern to filter companies.
    .PARAMETER Node
    Filter by node name or ID: only managed companies in this node or its descendants.
    .PARAMETER ExactNode
    If set, -Node filters to that node only (exclude descendants).
    .PARAMETER Format
    Output format: table (default), json, csv.
    .PARAMETER Output
    If supplied, write output to this file path.
    .PARAMETER Offset
    Number of rows to skip (for pagination). Default 0.
    .PARAMETER Limit
    Maximum number of rows to return (0 = no limit). Use with Offset for range/pagination.
    .EXAMPLE
    Get-KeeperEnterpriseInfoManagedCompany
    Get-KeeperEnterpriseInfoManagedCompany -Format json -Output mcs.json -Offset 0 -Limit 20
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0)][string] $Pattern,
        [Parameter()][string] $Node,
        [Parameter()][switch] $ExactNode,
        [Parameter()][ValidateSet('table', 'json', 'csv')][string] $Format = 'table',
        [Parameter()][string] $Output,
        [Parameter()][int] $Offset = 0,
        [Parameter()][int] $Limit = 0
    )
    $enterprise = getMspEnterprise
    $ed = $enterprise.enterpriseData
    $mcs = $enterprise.mspData.ManagedCompanies
    if (-not $mcs) { return @() }
    $nodeFilterIds = $null
    if ($Node) {
        $resolved = resolveSingleNode $Node
        if ($ExactNode) {
            $nodeFilterIds = [System.Collections.Generic.HashSet[long]]::new()
            [void]$nodeFilterIds.Add($resolved.Id)
        } else {
            $nodeFilterIds = Get-EnterpriseNodeAndDescendantIds $ed $resolved.Id
        }
    }
    $planName = { param($planId) switch ($planId) { 'enterprise' { 'Enterprise' } 'enterprise_plus' { 'Enterprise Plus' } 'business' { 'Business' } 'businessPlus' { 'Business Plus' } default { $planId } } }
    $patternLower = if ($Pattern) { $Pattern.Trim().ToLower() } else { '' }
    $out = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($mc in ($mcs | Sort-Object { $_.EnterpriseName })) {
        $nid = if ($mc.ParentNodeId -le 0) { $ed.RootNode.Id } else { $mc.ParentNodeId }
        if ($nodeFilterIds -and -not $nodeFilterIds.Contains($nid)) { continue }
        $storage = if ($mc.FilePlanType) { $mc.FilePlanType } else { '' }
        $addons = if ($mc.AddOns) { $mc.AddOns.Count } else { 0 }
        $allocated = $mc.NumberOfSeats; if ($allocated -eq 2147483647) { $allocated = $null }
        $nodePath = Get-KeeperNodePath -NodeId $mc.ParentNodeId -OmitRoot
        $row = [PSCustomObject]@{
            CompanyId    = $mc.EnterpriseId
            CompanyName  = $mc.EnterpriseName
            Node        = $nodePath
            Plan        = & $planName $mc.ProductId
            Storage     = $storage
            Addons      = $addons
            Allocated   = $allocated
            Active      = $mc.NumberOfUsers
        }
        if ($patternLower) {
            $text = ($row.PSObject.Properties.Value | ForEach-Object { $_ }) -join ' '
            if ($text -notmatch [regex]::Escape($patternLower)) { continue }
        }
        $out.Add($row) | Out-Null
    }
    $result = @($out | Sort-Object { $_.CompanyName })
    if ($Offset -gt 0) { $result = @($result | Select-Object -Skip $Offset) }
    if ($Limit -gt 0) { $result = @($result | Select-Object -First $Limit) }
    if ($Output) {
        if ($Format -eq 'json') { Set-Content -Path $Output -Value ($result | ConvertTo-Json -Depth 5) -Encoding utf8 }
        elseif ($Format -eq 'csv') { Set-Content -Path $Output -Value ($result | ConvertTo-Csv -NoTypeInformation) -Encoding utf8 }
        else { $result | Format-Table -AutoSize | Out-String | Set-Content -Path $Output -Encoding utf8 }
    } else {
        if ($Format -eq 'table') { $result | Format-Table -AutoSize } else { $result }
    }
}

New-Alias -Name keitree -Value Get-KeeperEnterpriseInfoTree -ErrorAction SilentlyContinue
New-Alias -Name kein -Value Get-KeeperEnterpriseInfoNode -ErrorAction SilentlyContinue
New-Alias -Name keiu -Value Get-KeeperEnterpriseInfoUser -ErrorAction SilentlyContinue
New-Alias -Name keit -Value Get-KeeperEnterpriseInfoTeam -ErrorAction SilentlyContinue
New-Alias -Name keir -Value Get-KeeperEnterpriseInfoRole -ErrorAction SilentlyContinue
New-Alias -Name keimc -Value Get-KeeperEnterpriseInfoManagedCompany -ErrorAction SilentlyContinue
