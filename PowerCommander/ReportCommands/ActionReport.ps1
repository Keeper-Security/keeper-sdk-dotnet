#requires -Version 5.1

function Get-KeeperActionReport {
    <#
    .SYNOPSIS
    Run an action report based on user activity.

    .DESCRIPTION
    Generates a report of enterprise users based on their activity (or lack thereof)
    and can optionally apply administrative actions (lock, delete, transfer) to those users.
    Mirrors the Commander 'action-report' command.

    Alias: action-report

    .PARAMETER Target
    Target user status to filter by:
      no-logon    - Users who haven't logged in within the specified period
      no-update   - Users who haven't added or updated records
      locked      - Users who have been locked for the specified period
      invited     - Users who have been invited but haven't accepted
      no-recovery - Users who haven't set up account recovery

    .PARAMETER DaysSince
    Number of days since the event of interest. Default: 30 (or 90 for locked).

    .PARAMETER Node
    Filter users by node name or ID. Includes child nodes.

    .PARAMETER ApplyAction
    Admin action to apply to matched users:
      none     - Report only (default)
      lock     - Lock the user accounts
      delete   - Delete the user accounts
      transfer - Transfer accounts to another user

    .PARAMETER TargetUser
    Username/email of the account to transfer users to. Required when -ApplyAction is 'transfer'.

    .PARAMETER DryRun
    Preview the action without actually executing it.

    .PARAMETER Force
    Skip the confirmation prompt for destructive actions.

    .PARAMETER Columns
    Comma-separated list of columns to display:
      user_id, email, name, status, transfer_status, node, 2fa_enabled,
      team_count, teams, role_count, roles

    .PARAMETER Format
    Output format: table (default), json, or csv.

    .PARAMETER Output
    File path to write the report output to.

    .PARAMETER SyntaxHelp
    Display detailed syntax help with examples.

    .EXAMPLE
    Get-KeeperActionReport
    Shows users who haven't logged in for 30 days (default).

    .EXAMPLE
    Get-KeeperActionReport -Target no-logon -DaysSince 60
    Shows users inactive for 60 days.

    .EXAMPLE
    Get-KeeperActionReport -Target locked -ApplyAction delete -DryRun
    Preview deleting locked users without executing.

    .EXAMPLE
    Get-KeeperActionReport -Target no-logon -ApplyAction lock -Node "Sales"
    Lock inactive users in the Sales node.

    .EXAMPLE
    Get-KeeperActionReport -Target locked -ApplyAction transfer -TargetUser admin@company.com
    Transfer locked user accounts to admin@company.com.

    .EXAMPLE
    Get-KeeperActionReport -Target invited -DaysSince 14 -Format csv -Output "invited_users.csv"
    Export invited users older than 14 days to CSV.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0)]
        [ValidateSet('no-logon', 'no-update', 'locked', 'invited', 'no-recovery')]
        [string] $Target = 'no-logon',

        [Parameter()]
        [int] $DaysSince,

        [Parameter()]
        [string] $Node,

        [Parameter()]
        [ValidateSet('none', 'lock', 'delete', 'transfer')]
        [string] $ApplyAction = 'none',

        [Parameter()]
        [string] $TargetUser,

        [Parameter()]
        [switch] $DryRun,

        [Parameter()]
        [switch] $Force,

        [Parameter()]
        [string] $Columns,

        [Parameter()]
        [ValidateSet('table', 'csv', 'json')]
        [string] $Format = 'table',

        [Parameter()]
        [string] $Output,

        [Parameter()]
        [switch] $SyntaxHelp
    )

    if ($SyntaxHelp) {
        Write-ActionReportSyntaxHelp
        return
    }

    try {
        [Enterprise]$enterprise = getEnterprise
    }
    catch {
        Write-Error "Failed to load enterprise context: $($_.Exception.Message)" -ErrorAction Stop
    }

    $auth = $enterprise.loader.Auth

    if ($ApplyAction -eq 'transfer' -and [string]::IsNullOrEmpty($TargetUser)) {
        Write-Error "-TargetUser is required when using -ApplyAction transfer" -ErrorAction Stop
    }

    $allowedActionsMap = @{
        'no-logon'    = @('none', 'lock')
        'no-update'   = @('none')
        'locked'      = @('none', 'delete', 'transfer')
        'invited'     = @('none', 'delete')
        'no-recovery' = @('none')
    }

    if ($ApplyAction -ne 'none') {
        $allowed = $allowedActionsMap[$Target]
        if ($ApplyAction -notin $allowed) {
            Write-Error "Action '$ApplyAction' is not allowed for target '$Target'. Allowed: $($allowed -join ', ')" -ErrorAction Stop
        }
    }

    $targetStatusMap = @{
        'no-logon'    = [KeeperSecurity.Enterprise.ActionReportTargetStatus]::NoLogon
        'no-update'   = [KeeperSecurity.Enterprise.ActionReportTargetStatus]::NoUpdate
        'locked'      = [KeeperSecurity.Enterprise.ActionReportTargetStatus]::Locked
        'invited'     = [KeeperSecurity.Enterprise.ActionReportTargetStatus]::Invited
        'no-recovery' = [KeeperSecurity.Enterprise.ActionReportTargetStatus]::NoRecovery
    }

    $adminActionMap = @{
        'none'     = [KeeperSecurity.Enterprise.ActionReportAdminAction]::None
        'lock'     = [KeeperSecurity.Enterprise.ActionReportAdminAction]::Lock
        'delete'   = [KeeperSecurity.Enterprise.ActionReportAdminAction]::Delete
        'transfer' = [KeeperSecurity.Enterprise.ActionReportAdminAction]::Transfer
    }

    $options = New-Object KeeperSecurity.Enterprise.ActionReportOptions
    $options.TargetStatus = $targetStatusMap[$Target]
    $options.Node = $Node
    $options.TargetUser = $TargetUser
    $options.DryRun = [bool]$DryRun
    $options.Force = [bool]$Force

    if ($PSBoundParameters.ContainsKey('DaysSince')) {
        $options.DaysSince = $DaysSince
    }

    $effectiveDays = if ($PSBoundParameters.ContainsKey('DaysSince')) { $DaysSince } else {
        if ($Target -eq 'locked') { 90 } else { 30 }
    }

    $needsConfirmation = $ApplyAction -in @('delete', 'transfer') -and -not $Force -and -not $DryRun
    $actionCancelled = $false

    if ($needsConfirmation) {
        $options.ApplyAction = [KeeperSecurity.Enterprise.ActionReportAdminAction]::None

        try {
            $result = [KeeperSecurity.Enterprise.ActionReportExtensions]::RunActionReport(
                $enterprise.enterpriseData,
                $auth,
                $options,
                $enterprise.roleData
            ).GetAwaiter().GetResult()
        }
        catch {
            Write-Error "Failed to run action report: $($_.Exception.Message)" -ErrorAction Stop
        }

        if (-not [string]::IsNullOrEmpty($result.ErrorMessage)) {
            Write-Error "Action report error: $($result.ErrorMessage)" -ErrorAction Stop
        }

        if ($result.Users.Count -gt 0) {
            Write-Host ""
            Write-Host "ALERT!" -ForegroundColor Red
            Write-Host ""
            Write-Host "You are about to $ApplyAction the following accounts:"
            $idx = 1
            foreach ($u in ($result.Users | Sort-Object -Property Username)) {
                Write-Host "$idx) $($u.Username)"
                $idx++
            }
            Write-Host ""
            Write-Host "This action cannot be undone."
            Write-Host ""
            $confirmation = Read-Host "Do you wish to proceed? (y/n)"
            if ($confirmation -notin @('y', 'yes')) {
                $actionCancelled = $true
            }
            else {
                $options.ApplyAction = $adminActionMap[$ApplyAction]
                $options.Force = $true

                try {
                    $actionResult = [KeeperSecurity.Enterprise.ActionReportExtensions]::RunActionReport(
                        $enterprise.enterpriseData,
                        $auth,
                        $options,
                        $enterprise.roleData
                    ).GetAwaiter().GetResult()

                    $result.ActionApplied = $actionResult.ActionApplied
                    $result.ActionStatus = $actionResult.ActionStatus
                    $result.AffectedCount = $actionResult.AffectedCount

                    if (-not [string]::IsNullOrEmpty($actionResult.ErrorMessage)) {
                        Write-Warning "Action error: $($actionResult.ErrorMessage)"
                    }
                }
                catch {
                    Write-Warning "Failed to apply action: $($_.Exception.Message)"
                }

                try {
                    $enterprise.loader.Load().GetAwaiter().GetResult() | Out-Null
                }
                catch {
                    Write-Warning "Failed to sync enterprise data: $($_.Exception.Message)"
                }
            }
        }
    }
    else {
        $options.ApplyAction = $adminActionMap[$ApplyAction]

        try {
            $result = [KeeperSecurity.Enterprise.ActionReportExtensions]::RunActionReport(
                $enterprise.enterpriseData,
                $auth,
                $options,
                $enterprise.roleData
            ).GetAwaiter().GetResult()
        }
        catch {
            Write-Error "Failed to run action report: $($_.Exception.Message)" -ErrorAction Stop
        }

        if (-not [string]::IsNullOrEmpty($result.ErrorMessage)) {
            Write-Error "Action report error: $($result.ErrorMessage)" -ErrorAction Stop
        }

        if ($ApplyAction -ne 'none' -and -not $DryRun -and $result.Users.Count -gt 0) {
            try {
                $enterprise.loader.Load().GetAwaiter().GetResult() | Out-Null
            }
            catch {
                Write-Warning "Failed to sync enterprise data: $($_.Exception.Message)"
            }
        }
    }

    $statusDescMap = @{
        'no-logon'    = 'No-logon'
        'no-update'   = 'No-update'
        'locked'      = 'Locked'
        'invited'     = 'Invited'
        'no-recovery' = 'No-recovery'
    }

    Write-Host ""
    Write-Host "Admin Action Taken:"
    if ($actionCancelled) {
        Write-Host "`tCOMMAND: NONE (Cancelled by user)"
        Write-Host "`tSTATUS: n/a"
        Write-Host "`tSERVER MESSAGE: n/a"
        Write-Host "`tAFFECTED: 0"
    }
    elseif ($ApplyAction -eq 'none') {
        Write-Host "`tCOMMAND: NONE (No action specified)"
        Write-Host "`tSTATUS: n/a"
        Write-Host "`tSERVER MESSAGE: n/a"
        Write-Host "`tAFFECTED: 0"
    }
    else {
        $actionApplied = if ($result.ActionApplied) { $result.ActionApplied } else { 'none' }
        $actionStatus = if ($result.ActionStatus) { $result.ActionStatus } else { 'n/a' }
        Write-Host "`tCOMMAND: $actionApplied"
        Write-Host "`tSTATUS: $actionStatus"
        Write-Host "`tSERVER MESSAGE: n/a"
        Write-Host "`tAFFECTED: $($result.AffectedCount)"
    }

    Write-Host ""
    Write-Host "Note: the following reflects data prior to any administrative action being applied"

    $statusDesc = $statusDescMap[$Target]
    $nodeInfo = if (-not [string]::IsNullOrEmpty($Node)) { " in Node `"$Node`"" } else { '' }
    Write-Host "$($result.Users.Count) User(s) With `"$statusDesc`" Status Older Than $effectiveDays Day(s)${nodeInfo}:"

    if ($result.Users.Count -eq 0) {
        Write-Host ""
        return
    }

    $enrichedUsers = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($user in $result.Users) {
        $teamUids = $enterprise.enterpriseData.GetTeamsForUser($user.UserId)
        $teamNames = [System.Collections.Generic.List[string]]::new()
        foreach ($uid in $teamUids) {
            $teamObj = $null
            if ($enterprise.enterpriseData.TryGetTeam($uid, [ref]$teamObj)) {
                $teamNames.Add($teamObj.Name)
            }
        }

        $roleNames = [System.Collections.Generic.List[string]]::new()
        foreach ($roleId in $enterprise.roleData.GetRolesForUser($user.UserId)) {
            $roleObj = $null
            if ($enterprise.roleData.TryGetRole($roleId, [ref]$roleObj)) {
                $roleNames.Add($roleObj.DisplayName)
            }
        }

        $euObj = $null
        $twoFa = $false
        if ($enterprise.enterpriseData.TryGetUserById($user.UserId, [ref]$euObj)) {
            $twoFa = $euObj.TwoFactorEnabled
        }

        $enrichedUsers.Add([PSCustomObject]@{
            UserId           = $user.UserId
            Username         = $user.Username
            DisplayName      = $user.DisplayName
            Status           = $user.Status
            TransferStatus   = $user.TransferStatus
            NodePath         = $user.NodePath
            TwoFactorEnabled = $twoFa
            TeamCount        = $teamUids.Length
            Teams            = $teamNames
            RoleCount        = $roleNames.Count
            Roles            = $roleNames
        })
    }

    $allColumns = [ordered]@{
        'user_id'         = @{ Header = 'User ID';         Value = { param($u) $u.UserId } }
        'email'           = @{ Header = 'Email';           Value = { param($u) $u.Username } }
        'name'            = @{ Header = 'Name';            Value = { param($u) if ($u.DisplayName) { $u.DisplayName } else { '' } } }
        'status'          = @{ Header = 'Status';          Value = { param($u) $u.Status.ToString() } }
        'transfer_status' = @{ Header = 'Transfer Status'; Value = { param($u) if ($u.TransferStatus) { $u.TransferStatus } else { '' } } }
        'node'            = @{ Header = 'Node';            Value = { param($u) if ($u.NodePath) { $u.NodePath } else { '' } } }
        '2fa_enabled'     = @{ Header = '2FA Enabled';     Value = { param($u) $u.TwoFactorEnabled.ToString() } }
        'team_count'      = @{ Header = 'Team Count';      Value = { param($u) $u.TeamCount.ToString() } }
        'teams'           = @{ Header = 'Teams';           Value = { param($u) if ($u.Teams.Count) { $u.Teams -join ', ' } else { '' } } }
        'role_count'      = @{ Header = 'Role Count';      Value = { param($u) $u.RoleCount.ToString() } }
        'roles'           = @{ Header = 'Roles';           Value = { param($u) if ($u.Roles.Count) { $u.Roles -join ', ' } else { '' } } }
    }

    $defaultColumnKeys = @('user_id', 'email', 'name', 'status', 'transfer_status', 'node')

    if ([string]::IsNullOrEmpty($Columns)) {
        $selectedKeys = $defaultColumnKeys
    }
    else {
        $requestedKeys = $Columns.Split(',') | ForEach-Object { $_.Trim().ToLowerInvariant().Replace(' ', '_') }
        $invalidKeys = $requestedKeys | Where-Object { -not $allColumns.Contains($_) }
        if ($invalidKeys) {
            Write-Warning "Unsupported column(s): $($invalidKeys -join ', '). Supported: $($allColumns.Keys -join ', ')"
        }
        $selectedKeys = $requestedKeys | Where-Object { $allColumns.Contains($_) }
        if ('email' -notin $selectedKeys) {
            $selectedKeys = @('email') + $selectedKeys
        }
    }

    $sortedUsers = $enrichedUsers | Sort-Object -Property Username

    $rows = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($user in $sortedUsers) {
        $props = [ordered]@{}
        foreach ($key in $selectedKeys) {
            $colDef = $allColumns[$key]
            $props[$colDef.Header] = & $colDef.Value $user
        }
        $rows.Add([PSCustomObject]$props)
    }

    Write-ActionReportOutput -Rows $rows -Format $Format -Output $Output
}

function Script:Write-ActionReportOutput {
    param(
        [Parameter(Mandatory)]
        [System.Collections.Generic.List[PSCustomObject]] $Rows,

        [Parameter()]
        [string] $Format = 'table',

        [Parameter()]
        [string] $Output
    )

    $content = $null

    switch ($Format) {
        'json' {
            $content = $Rows | ConvertTo-Json -Depth 5
        }
        'csv' {
            $content = ($Rows | ConvertTo-Csv -NoTypeInformation) -join "`n"
        }
        default {
            if (-not [string]::IsNullOrEmpty($Output)) {
                $content = ($Rows | Format-Table -AutoSize | Out-String).Trim()
            }
            else {
                $Rows | Format-Table -AutoSize
                return
            }
        }
    }

    if (-not [string]::IsNullOrEmpty($Output)) {
        try {
            $content | Out-File -FilePath $Output -Encoding utf8
            Write-Host "Report written to: $Output"
        }
        catch {
            Write-Error "Failed to write report to '$Output': $($_.Exception.Message)"
        }
    }
    else {
        Write-Output $content
    }
}

function Script:Write-ActionReportSyntaxHelp {
    Write-Host @"

Action Report Command Syntax Description:

This command generates a report of users based on their activity (or lack thereof)
and can optionally apply administrative actions to those users.

Target Statuses (-Target):
  no-logon      Users who haven't logged in within the specified period
                Allowed actions: none, lock

  no-update     Users who haven't added or updated records
                Allowed actions: none

  locked        Users who have been locked for the specified period
                Allowed actions: none, delete, transfer

  invited       Users who have been invited but haven't accepted
                Allowed actions: none, delete

  no-recovery   Users who haven't set up account recovery
                Allowed actions: none

Options:
  -Target <status>          Target user status (default: no-logon)
  -DaysSince <days>         Number of days since event (default: 30, or 90 for locked)
  -Node <name|id>           Filter users by node (includes child nodes)
  -ApplyAction <action>     Admin action: none, lock, delete, transfer
  -TargetUser <email>       Target user for transfer action
  -DryRun                   Preview action without executing
  -Force                    Skip confirmation for destructive actions
  -Columns <cols>           Columns to display (comma-separated)
  -Format <format>          Output format: table, csv, json
  -Output <path>            Write report to file

Examples:
  Get-KeeperActionReport
      Users who haven't logged in (30 days)

  Get-KeeperActionReport -Target no-logon -DaysSince 60
      Users inactive for 60 days

  Get-KeeperActionReport -Target locked -ApplyAction delete -DryRun
      Preview deleting locked users

  Get-KeeperActionReport -Target no-logon -ApplyAction lock -Node "Sales"
      Lock inactive users in Sales node

  Get-KeeperActionReport -Target locked -ApplyAction transfer -TargetUser admin@company.com
      Transfer locked user accounts

  action-report -Target invited -DaysSince 14 -Format csv -Output "invited.csv"
      Export invited users to CSV
"@
}

New-Alias -Name action-report -Value Get-KeeperActionReport
