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
                        $parts = [System.Collections.Generic.List[string]]::new()
                        for ($i = 0; $i -lt $take; $i++) {
                            $p = $props[$i]
                            $parts.Add("$($p.Name): $($p.Value)")
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

function script:ConvertFrom-KeeperEpmTimestamp {
    Param ([long] $Timestamp)
    if ($Timestamp -le 0) { return [DateTimeOffset]::MinValue }
    return [DateTimeOffset]::FromUnixTimeMilliseconds($Timestamp)
}

function script:Get-KeeperEpmApprovalStatusInt {
    Param (
        [Parameter(Mandatory = $true)] $Plugin,
        [string] $ApprovalUid
    )
    if ([string]::IsNullOrEmpty($ApprovalUid)) { return 0 }
    try {
        $s = $Plugin.GetApprovalStatus($ApprovalUid)
        if ($null -eq $s) { return 0 }
        return [int]$s
    }
    catch {
        return 0
    }
}

function script:Get-KeeperEpmApprovalStatusDisplay {
    Param (
        [Parameter(Mandatory = $true)] $Plugin,
        [string] $ApprovalUid
    )
    $statusInt = Get-KeeperEpmApprovalStatusInt -Plugin $Plugin -ApprovalUid $ApprovalUid
    switch ($statusInt) {
        0 { return 'PENDING' }
        1 { return 'APPROVED' }
        2 { return 'DENIED' }
        3 { return 'EXPIRED' }
        5 { return 'ESCALATED' }
        default { return 'UNKNOWN' }
    }
}

function script:Get-KeeperEpmApprovalTypeName {
    Param ([int] $ApprovalType)
    switch ($ApprovalType) {
        1 { return 'PrivilegeElevation' }
        2 { return 'FileAccess' }
        5 { return 'CommandLine' }
        6 { return 'LeastPrivilege' }
        99 { return 'Custom' }
        default { return 'Other' }
    }
}

function Get-KeeperEpmApprovalList {
    <#
    .Synopsis
        List EPM/PEDM approval requests.
    .Parameter Type
        Filter by approval status: approved, denied, pending, expired, escalated. If omitted, lists all approvals.
    #>
    [CmdletBinding()]
    Param (
        [Parameter()]
        [ValidateSet('approved', 'denied', 'pending', 'expired', 'escalated')]
        [string] $Type
    )

    $plugin = ensureEpmPlugin
    if (-not $plugin) {
        Write-Error -Message "EPM plugin is not available. Enterprise admin access is required." -ErrorAction Stop
    }

    $approvals = @($plugin.Approvals.GetAll())

    $rows = foreach ($appr in ($approvals | Sort-Object -Property ApprovalUid)) {
        $status = Get-KeeperEpmApprovalStatusDisplay -Plugin $plugin -ApprovalUid $appr.ApprovalUid
        [PSCustomObject]@{
            'Approval UID'     = $appr.ApprovalUid
            'Approval Type'    = Get-KeeperEpmApprovalTypeName -ApprovalType $appr.ApprovalType
            'Status'           = $status
            'Agent UID'        = if ($appr.AgentUid) { $appr.AgentUid } else { '' }
            'Account Info'     = ConvertFrom-KeeperEpmApprovalField -FieldData $appr.AccountInfo
            'Application Info' = ConvertFrom-KeeperEpmApprovalField -FieldData $appr.ApplicationInfo
            'Justification'    = ConvertFrom-KeeperEpmApprovalField -FieldData $appr.Justification
            'Expire In'        = if ($appr.ExpireIn -gt 0) { $appr.ExpireIn } else { '' }
            'Created'          = (ConvertFrom-KeeperEpmTimestamp -Timestamp $appr.Created).ToString('yyyy-MM-dd HH:mm:ss')
        }
    }

    if (-not [string]::IsNullOrEmpty($Type)) {
        $filterType = $Type.ToUpperInvariant()
        $rows = @($rows | Where-Object { $_.'Status' -eq $filterType })
    }

    if ($rows.Count -eq 0) {
        if (-not [string]::IsNullOrEmpty($Type)) { Write-Output "No $Type approvals found." }
        else { Write-Output 'No approvals found.' }
        return
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

    $status = Get-KeeperEpmApprovalStatusDisplay -Plugin $plugin -ApprovalUid $ApprovalUid
    $typeName = Get-KeeperEpmApprovalTypeName -ApprovalType $approval.ApprovalType
    Write-Output "Approval: $ApprovalUid"
    Write-Output "  Type: $typeName"
    Write-Output "  Status: $status"
    Write-Output "  Agent UID: $(if ($approval.AgentUid) { $approval.AgentUid } else { '' })"
    Write-Output "  Account Info: $(ConvertFrom-KeeperEpmApprovalField -FieldData $approval.AccountInfo)"
    Write-Output "  Application Info: $(ConvertFrom-KeeperEpmApprovalField -FieldData $approval.ApplicationInfo)"
    Write-Output "  Justification: $(ConvertFrom-KeeperEpmApprovalField -FieldData $approval.Justification)"
    if ($approval.ExpireIn -gt 0) { Write-Output "  Expire In: $($approval.ExpireIn)" }
    else { Write-Output '  Expire In: N/A' }
    Write-Output "  Created: $((ConvertFrom-KeeperEpmTimestamp -Timestamp $approval.Created).ToString('yyyy-MM-dd HH:mm:ss'))"
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

    $currentStatus = Get-KeeperEpmApprovalStatusDisplay -Plugin $plugin -ApprovalUid $ApprovalUid
    if ($currentStatus -eq 'APPROVED') {
        Write-Error -Message "Approval '$ApprovalUid' is already APPROVED. Cannot approve again." -ErrorAction Stop
    }
    if ($currentStatus -eq 'DENIED') {
        Write-Error -Message "Approval '$ApprovalUid' is already DENIED. Cannot approve a denied request." -ErrorAction Stop
    }
    if ($currentStatus -eq 'EXPIRED') {
        Write-Error -Message "Approval '$ApprovalUid' is EXPIRED. Cannot approve an expired request." -ErrorAction Stop
    }

    try {
        $approveStatus = $plugin.ModifyApprovals([string[]]@($ApprovalUid), $null, $null).GetAwaiter().GetResult()

        if ($approveStatus.AddErrors -and $approveStatus.AddErrors.Count -gt 0) {
            $err = $approveStatus.AddErrors[0]
            Write-Error -Message "Failed to approve `"$($err.EntityUid)`": $($err.Message)" -ErrorAction Stop
        }
        if ($approveStatus.UpdateErrors -and $approveStatus.UpdateErrors.Count -gt 0) {
            $err = $approveStatus.UpdateErrors[0]
            Write-Error -Message "Failed to approve `"$($err.EntityUid)`": $($err.Message)" -ErrorAction Stop
        }
        Write-Output "Approval '$ApprovalUid' approved."
        writeEpmModifyStatus -Status $approveStatus
        $plugin.SyncDown($false).GetAwaiter().GetResult() | Out-Null
    } catch {
        Write-Error -Message "Error approving approval: $($_.Exception.Message)" -ErrorAction Stop
    }
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

    $currentStatus = Get-KeeperEpmApprovalStatusDisplay -Plugin $plugin -ApprovalUid $ApprovalUid
    if ($currentStatus -eq 'DENIED') {
        Write-Error -Message "Approval '$ApprovalUid' is already DENIED. Cannot deny again." -ErrorAction Stop
    }
    if ($currentStatus -eq 'APPROVED') {
        Write-Error -Message "Approval '$ApprovalUid' is already APPROVED. Cannot deny an approved request." -ErrorAction Stop
    }
    if ($currentStatus -eq 'EXPIRED') {
        Write-Error -Message "Approval '$ApprovalUid' is EXPIRED. Cannot deny an expired request." -ErrorAction Stop
    }

    try {
        $denyStatus = $plugin.ModifyApprovals($null, [string[]]@($ApprovalUid), $null).GetAwaiter().GetResult()

        if ($denyStatus.AddErrors -and $denyStatus.AddErrors.Count -gt 0) {
            $err = $denyStatus.AddErrors[0]
            Write-Error -Message "Failed to deny `"$($err.EntityUid)`": $($err.Message)" -ErrorAction Stop
        }
        if ($denyStatus.UpdateErrors -and $denyStatus.UpdateErrors.Count -gt 0) {
            $err = $denyStatus.UpdateErrors[0]
            Write-Error -Message "Failed to deny `"$($err.EntityUid)`": $($err.Message)" -ErrorAction Stop
        }
        Write-Output "Approval '$ApprovalUid' denied."
        writeEpmModifyStatus -Status $denyStatus
        $plugin.SyncDown($false).GetAwaiter().GetResult() | Out-Null
    } catch {
        Write-Error -Message "Error denying approval: $($_.Exception.Message)" -ErrorAction Stop
    }
}

function Remove-KeeperEpmApproval {
    <#
    .Synopsis
        Remove an EPM approval record.
    .Parameter ApprovalUid
        The approval record UID.
    .Parameter Force
        If set, skip confirmation prompt before delete.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    Param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $ApprovalUid,
        [Parameter()]
        [switch] $Force
    )

    $plugin = ensureEpmPlugin
    if (-not $plugin) {
        Write-Error -Message "EPM plugin is not available. Enterprise admin access is required." -ErrorAction Stop
    }

    $approval = $plugin.Approvals.GetEntity($ApprovalUid)
    if (-not $approval) {
        Write-Error -Message "Approval '$ApprovalUid' not found." -ErrorAction Stop
    }

    if (-not $Force -and -not $PSCmdlet.ShouldProcess("approval '$ApprovalUid'", "Remove")) {
        return
    }

    try {
        $removeStatus = $plugin.ModifyApprovals($null, $null, [string[]]@($ApprovalUid)).GetAwaiter().GetResult()

        if ($removeStatus.RemoveErrors -and $removeStatus.RemoveErrors.Count -gt 0) {
            $err = $removeStatus.RemoveErrors[0]
            Write-Error -Message "Failed to remove approval `"$($err.EntityUid)`": $($err.Message)" -ErrorAction Stop
        }
        if ($removeStatus.Remove -and $removeStatus.Remove.Count -gt 0) {
            Write-Output "Approval '$ApprovalUid' removed."
        } else {
            Write-Warning "Approval '$ApprovalUid' may not have been removed. Check server response."
        }
        writeEpmModifyStatus -Status $removeStatus
        $plugin.SyncDown($false).GetAwaiter().GetResult() | Out-Null
    } catch {
        Write-Error -Message "Error removing approval: $($_.Exception.Message)" -ErrorAction Stop
    }
}

New-Alias -Name kepm-approval-list   -Value Get-KeeperEpmApprovalList   -ErrorAction SilentlyContinue
New-Alias -Name kepm-approval-view    -Value Get-KeeperEpmApproval       -ErrorAction SilentlyContinue
New-Alias -Name kepm-approval-approve -Value Approve-KeeperEpmApproval -ErrorAction SilentlyContinue
New-Alias -Name kepm-approval-deny    -Value Deny-KeeperEpmApproval    -ErrorAction SilentlyContinue
New-Alias -Name kepm-approval-remove  -Value Remove-KeeperEpmApproval  -ErrorAction SilentlyContinue
