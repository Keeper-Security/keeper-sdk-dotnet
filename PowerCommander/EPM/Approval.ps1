function script:ConvertFrom-KeeperEpmApprovalField {
    Param ([byte[]] $FieldData)
    if ($null -eq $FieldData -or $FieldData.Length -eq 0) { return '' }
    try {
        $text = [System.Text.Encoding]::UTF8.GetString($FieldData)
        $nonPrintable = 0
        foreach ($ch in $text.ToCharArray()) {
            if ([char]::IsControl($ch) -and $ch -ne "`n" -and $ch -ne "`r" -and $ch -ne "`t") { $nonPrintable++ }
        }
        $ratio = if ($text.Length -gt 0) { ($nonPrintable * 100.0 / $text.Length) } else { 100 }
        if ($ratio -lt 10) {
            try {
                $json = $text | ConvertFrom-Json -ErrorAction Stop
                if ($null -ne $json) {
                    $props = @($json.PSObject.Properties)
                    if ($props.Count -gt 0) {
                        $take = [Math]::Min(3, $props.Count)
                        $parts = @()
                        for ($i = 0; $i -lt $take; $i++) {
                            $p = $props[$i]
                            $parts += "$($p.Name): $($p.Value)"
                        }
                        $result = $parts -join ', '
                        if ($props.Count -gt 3) { $result += '...' }
                        return $result
                    }
                }
            }
            catch { }
            if ($text.Length -gt 50) { return $text.Substring(0, 47) + '...' }
            return $text
        }
    }
    catch { }
    return "(encrypted, $($FieldData.Length) bytes)"
}

function script:Get-KeeperEpmApprovalStatusInt {
    Param (
        [Parameter(Mandatory = $true)] $Plugin,
        [string] $ApprovalUid
    )
    if ([string]::IsNullOrEmpty($ApprovalUid)) { return 0 }
    $s = $Plugin.GetApprovalStatus($ApprovalUid)
    if ($null -eq $s) { return 0 }
    return [int]$s
}

function script:Get-KeeperEpmApprovalStatusDisplay {
    Param (
        [Parameter(Mandatory = $true)] $Plugin,
        [string] $ApprovalUid,
        [long] $Created,
        [int] $ExpireIn
    )
    $statusInt = Get-KeeperEpmApprovalStatusInt -Plugin $Plugin -ApprovalUid $ApprovalUid
    if ($statusInt -eq 0 -and $ExpireIn -gt 0) {
        $nowSeconds = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        $expireTime = $Created + $ExpireIn
        if ($nowSeconds -gt $expireTime) { return 'EXPIRED' }
    }
    switch ($statusInt) {
        0 { return 'PENDING' }
        1 { return 'APPROVED' }
        2 { return 'DENIED' }
        default { return 'UNKNOWN' }
    }
}

function script:Test-KeeperEpmApprovalExpired {
    Param (
        [Parameter(Mandatory = $true)] $Plugin,
        [Parameter(Mandatory = $true)] $Approval,
        [long] $NowSeconds
    )
    if ($Approval.ExpireIn -le 0) { return $false }
    $statusInt = Get-KeeperEpmApprovalStatusInt -Plugin $Plugin -ApprovalUid $Approval.ApprovalUid
    if ($statusInt -ne 0) { return $false }
    $expireTime = $Approval.Created + $Approval.ExpireIn
    return $NowSeconds -gt $expireTime
}

function script:Write-EpmApprovalModifyStatus {
    Param ($Status)
    if ($null -eq $Status) { return }
    if ($Status.Add -and $Status.Add.Count -gt 0) {
        Write-Output "  Added: $($Status.Add -join ', ')"
    }
    if ($Status.Update -and $Status.Update.Count -gt 0) {
        Write-Output "  Updated: $($Status.Update -join ', ')"
    }
    if ($Status.Remove -and $Status.Remove.Count -gt 0) {
        Write-Output "  Removed: $($Status.Remove -join ', ')"
    }
}

function Get-KeeperEpmApprovalList {
    
    <#
    .Synopsis
        List EPM/PEDM approval requests.
    .Parameter ExpiredOnly
        If set, list only expired pending approvals. If omitted, lists approvals that are not yet expired.
    #>
    
    [CmdletBinding()]
    Param (
        [Parameter()]
        [switch] $ExpiredOnly
    )

    $plugin = ensureEpmPlugin
    if (-not $plugin) {
        Write-Error -Message "EPM plugin is not available. Enterprise admin access is required." -ErrorAction Stop
    }

    $approvals = @($plugin.Approvals.GetAll())
    $nowSeconds = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()

    if ($ExpiredOnly) {
        $approvals = @($approvals | Where-Object { Test-KeeperEpmApprovalExpired -Plugin $plugin -Approval $_ -NowSeconds $nowSeconds })
    }
    else {
        $approvals = @($approvals | Where-Object { -not (Test-KeeperEpmApprovalExpired -Plugin $plugin -Approval $_ -NowSeconds $nowSeconds) })
    }

    if ($approvals.Count -eq 0) {
        if ($ExpiredOnly) { Write-Output 'No expired approvals found.' }
        else { Write-Output 'No approvals found.' }
        return
    }

    $rows = foreach ($appr in ($approvals | Sort-Object -Property ApprovalUid)) {
        $accountInfo = ConvertFrom-KeeperEpmApprovalField -FieldData $appr.AccountInfo
        $applicationInfo = ConvertFrom-KeeperEpmApprovalField -FieldData $appr.ApplicationInfo
        $justification = ConvertFrom-KeeperEpmApprovalField -FieldData $appr.Justification
        $status = Get-KeeperEpmApprovalStatusDisplay -Plugin $plugin -ApprovalUid $appr.ApprovalUid -Created $appr.Created -ExpireIn $appr.ExpireIn
        $expireIn = if ($appr.ExpireIn -gt 0) { "$($appr.ExpireIn)s" } else { '' }
        $created = [DateTimeOffset]::FromUnixTimeSeconds($appr.Created).ToString('yyyy-MM-dd HH:mm:ss')
        [PSCustomObject]@{
            'Approval UID'     = $appr.ApprovalUid
            'Approval Type'    = $appr.ApprovalType
            'Status'           = $status
            'Agent UID'        = if ($appr.AgentUid) { $appr.AgentUid } else { '' }
            'Account Info'     = $accountInfo
            'Application Info' = $applicationInfo
            'Justification'    = $justification
            'Expire In'        = $expireIn
            'Created'          = $created
        }
    }
    $rows | Format-Table -AutoSize
}

function Get-KeeperEpmApproval {
    <#
    .Synopsis
        View a single EPM approval by UID.
    .Parameter ApprovalUid
        The approval record UID.
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $ApprovalUid
    )

    $plugin = ensureEpmPlugin
    if (-not $plugin) {
        Write-Error -Message "EPM plugin is not available. Enterprise admin access is required." -ErrorAction Stop
    }

    $approval = $plugin.Approvals.GetEntity($ApprovalUid)
    if (-not $approval) {
        Write-Error -Message "Approval '$ApprovalUid' not found." -ErrorAction Stop
    }

    $status = Get-KeeperEpmApprovalStatusDisplay -Plugin $plugin -ApprovalUid $ApprovalUid -Created $approval.Created -ExpireIn $approval.ExpireIn
    Write-Output "Approval: $ApprovalUid"
    Write-Output "  Type: $($approval.ApprovalType)"
    Write-Output "  Status: $status"
    Write-Output "  Agent UID: $(if ($approval.AgentUid) { $approval.AgentUid } else { '' })"
    Write-Output "  Account Info: $(ConvertFrom-KeeperEpmApprovalField -FieldData $approval.AccountInfo)"
    Write-Output "  Application Info: $(ConvertFrom-KeeperEpmApprovalField -FieldData $approval.ApplicationInfo)"
    Write-Output "  Justification: $(ConvertFrom-KeeperEpmApprovalField -FieldData $approval.Justification)"
    if ($approval.ExpireIn -gt 0) { Write-Output "  Expire In: $($approval.ExpireIn)s" }
    else { Write-Output '  Expire In: N/A' }
    Write-Output "  Created: $([DateTimeOffset]::FromUnixTimeSeconds($approval.Created).ToString('yyyy-MM-dd HH:mm:ss'))"
}

function Approve-KeeperEpmApproval {
    <#
    .Synopsis
        Approve a pending EPM approval.
    .Parameter ApprovalUid
        The approval record UID.
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $ApprovalUid
    )

    $plugin = ensureEpmPlugin
    if (-not $plugin) {
        Write-Error -Message "EPM plugin is not available. Enterprise admin access is required." -ErrorAction Stop
    }

    $approval = $plugin.Approvals.GetEntity($ApprovalUid)
    if (-not $approval) {
        Write-Error -Message "Approval '$ApprovalUid' not found." -ErrorAction Stop
    }

    $current = Get-KeeperEpmApprovalStatusInt -Plugin $plugin -ApprovalUid $ApprovalUid
    if ($current -eq 1) {
        Write-Error -Message "Approval '$ApprovalUid' is already APPROVED. Cannot approve again." -ErrorAction Stop
    }
    if ($current -eq 2) {
        Write-Error -Message "Approval '$ApprovalUid' is already DENIED. Cannot approve a denied request." -ErrorAction Stop
    }

    $approveStatus = $plugin.ModifyApprovals(@($ApprovalUid), $null, $null).GetAwaiter().GetResult()
    Write-Output "Approval '$ApprovalUid' approved."
    if (($approveStatus.Add -and $approveStatus.Add.Count -gt 0) -or ($approveStatus.Update -and $approveStatus.Update.Count -gt 0) -or ($approveStatus.Remove -and $approveStatus.Remove.Count -gt 0)) {
        Write-EpmApprovalModifyStatus -Status $approveStatus
    }
    $plugin.SyncDown($false).GetAwaiter().GetResult() | Out-Null
}

function Deny-KeeperEpmApproval {
    <#
    .Synopsis
        Deny a pending EPM approval.
    .Parameter ApprovalUid
        The approval record UID.
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $ApprovalUid
    )

    $plugin = ensureEpmPlugin
    if (-not $plugin) {
        Write-Error -Message "EPM plugin is not available. Enterprise admin access is required." -ErrorAction Stop
    }

    $approval = $plugin.Approvals.GetEntity($ApprovalUid)
    if (-not $approval) {
        Write-Error -Message "Approval '$ApprovalUid' not found." -ErrorAction Stop
    }

    $current = Get-KeeperEpmApprovalStatusInt -Plugin $plugin -ApprovalUid $ApprovalUid
    if ($current -eq 2) {
        Write-Error -Message "Approval '$ApprovalUid' is already DENIED. Cannot deny again." -ErrorAction Stop
    }
    if ($current -eq 1) {
        Write-Error -Message "Approval '$ApprovalUid' is already APPROVED. Cannot deny an approved request." -ErrorAction Stop
    }

    $denyStatus = $plugin.ModifyApprovals($null, @($ApprovalUid), $null).GetAwaiter().GetResult()
    Write-Output "Approval '$ApprovalUid' denied."
    if (($denyStatus.Add -and $denyStatus.Add.Count -gt 0) -or ($denyStatus.Update -and $denyStatus.Update.Count -gt 0) -or ($denyStatus.Remove -and $denyStatus.Remove.Count -gt 0)) {
        Write-EpmApprovalModifyStatus -Status $denyStatus
    }
    $plugin.SyncDown($false).GetAwaiter().GetResult() | Out-Null
}

function Remove-KeeperEpmApproval {
    <#
    .Synopsis
        Remove an EPM approval record.
    .Parameter ApprovalUid
        The approval record UID.
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $ApprovalUid
    )

    $plugin = ensureEpmPlugin
    if (-not $plugin) {
        Write-Error -Message "EPM plugin is not available. Enterprise admin access is required." -ErrorAction Stop
    }

    $removeStatus = $plugin.ModifyApprovals($null, $null, @($ApprovalUid)).GetAwaiter().GetResult()
    Write-Output "Approval '$ApprovalUid' removed."
    if (($removeStatus.Add -and $removeStatus.Add.Count -gt 0) -or ($removeStatus.Update -and $removeStatus.Update.Count -gt 0) -or ($removeStatus.Remove -and $removeStatus.Remove.Count -gt 0)) {
        Write-EpmApprovalModifyStatus -Status $removeStatus
    }
    $plugin.SyncDown($false).GetAwaiter().GetResult() | Out-Null
}

New-Alias -Name kepm-approval-list   -Value Get-KeeperEpmApprovalList   -ErrorAction SilentlyContinue
New-Alias -Name kepm-approval-view    -Value Get-KeeperEpmApproval       -ErrorAction SilentlyContinue
New-Alias -Name kepm-approval-approve -Value Approve-KeeperEpmApproval -ErrorAction SilentlyContinue
New-Alias -Name kepm-approval-deny    -Value Deny-KeeperEpmApproval    -ErrorAction SilentlyContinue
New-Alias -Name kepm-approval-remove  -Value Remove-KeeperEpmApproval  -ErrorAction SilentlyContinue
New-Alias -Name kepm-approval-delete  -Value Remove-KeeperEpmApproval  -ErrorAction SilentlyContinue
