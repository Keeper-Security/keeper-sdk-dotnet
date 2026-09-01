#requires -Version 5.1

function script:getPamWorkflowAuth {
    $vault = getPamVault
    [KeeperSecurity.Authentication.IAuthentication] $auth = $vault.Auth
    if (-not $auth) {
        Write-Error -Message 'Authentication is not available. Connect to Keeper first.' -ErrorAction Stop
    }

    return $auth
}

function script:assertPamWorkflowManagementPermission {
    Param (
        [Parameter(Mandatory = $true)]
        [KeeperSecurity.Authentication.IAuthentication] $Auth
    )

    if (-not [KeeperSecurity.Plugins.PAM.WorkflowUtils]::CanManageWorkflowSettings($Auth)) {
        Write-Error -Message ('You do not have permission to manage PAM workflow settings. ' +
            'Contact your Keeper administrator to enable the workflow-management enforcement for your role.') -ErrorAction Stop
    }
}

function script:resolvePamWorkflowRecord {
    Param (
        [Parameter(Mandatory = $true)]
        [KeeperSecurity.Vault.VaultOnline] $Vault,
        [Parameter(Mandatory = $true)]
        [string] $Identifier,

        [switch] $ValidateWorkflowType
    )

    if ([string]::IsNullOrWhiteSpace($Identifier)) {
        throw 'A PAM resource record UID or title is required.'
    }

    [System.Collections.Generic.IEnumerable[string]] $allowedTypes = $null
    if ($ValidateWorkflowType) {
        $workflowTypes = New-Object 'System.Collections.Generic.HashSet[string]'
        foreach ($typeName in [KeeperSecurity.Plugins.PAM.PamRecordTypes]::Workflow) {
            [void]$workflowTypes.Add([string]$typeName)
        }
        $allowedTypes = $workflowTypes
    }

    $previousErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Stop'
    try {
        return [KeeperSecurity.Plugins.PAM.PamVaultHelpers]::ResolveRecord($Vault, $Identifier.Trim(), $allowedTypes)
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
}

function script:convertPamWorkflowConfigToObject {
    Param (
        [Parameter(Mandatory = $true)]
        [Workflow.WorkflowConfig] $Config,
        [Parameter(Mandatory = $true)]
        [string] $RecordUid,

        [string] $RecordName
    )

    $parameters = $Config.Parameters
    $approvers = @(
        foreach ($approver in @($Config.Approvers)) {
            $item = [ordered]@{
                escalation = [bool]$approver.Escalation
            }
            if ($approver.EscalationAfterMs -gt 0) {
                $item['escalation_after'] = [KeeperSecurity.Plugins.PAM.WorkflowUtils]::FormatDuration($approver.EscalationAfterMs)
            }
            if ($approver.HasUser) {
                $item['type'] = 'user'
                $item['email'] = $approver.User
            }
            elseif ($approver.HasUserId) {
                $item['type'] = 'user_id'
                $item['user_id'] = $approver.UserId
            }
            elseif ($approver.HasTeamUid) {
                $item['type'] = 'team'
                $item['team_uid'] = encodePamByteString -ByteString $approver.TeamUid
            }
            $item
        }
    )

    $resolvedName = $RecordName
    if ($parameters -and $parameters.Resource -and -not [string]::IsNullOrWhiteSpace($parameters.Resource.Name)) {
        $resolvedName = $parameters.Resource.Name
    }

    return [ordered]@{
        record_uid = $RecordUid
        record_name = $resolvedName
        parameters = [ordered]@{
            approvals_needed = if ($parameters) { $parameters.ApprovalsNeeded } else { 0 }
            checkout_needed = if ($parameters) { $parameters.CheckoutNeeded } else { $false }
            start_access_on_approval = if ($parameters) { $parameters.StartAccessOnApproval } else { $false }
            require_reason = if ($parameters) { $parameters.RequireReason } else { $false }
            require_ticket = if ($parameters) { $parameters.RequireTicket } else { $false }
            require_mfa = if ($parameters) { $parameters.RequireMFA } else { $false }
            access_duration = if ($parameters) { [KeeperSecurity.Plugins.PAM.WorkflowUtils]::FormatDuration($parameters.AccessLength) } else { '' }
            allowed_times = if ($parameters) { [KeeperSecurity.Plugins.PAM.WorkflowUtils]::FormatTemporalFilter($parameters.AllowedTimes) } else { $null }
        }
        approvers = $approvers
    }
}

function script:convertPamWorkflowTimestamp {
    Param (
        [long] $Timestamp,
        [switch] $Raw
    )

    if ($Timestamp -le 0) {
        return $null
    }
    if ($Raw) {
        return $Timestamp
    }

    return [DateTimeOffset]::FromUnixTimeMilliseconds($Timestamp).LocalDateTime.ToString('yyyy-MM-dd HH:mm:ss')
}

function script:convertPamWorkflowStateToObject {
    Param (
        [Parameter(Mandatory = $true)]
        [Workflow.WorkflowState] $State,

        [string] $FallbackRecordUid,
        [string] $FallbackRecordName,
        [switch] $RawTimestamps
    )

    $status = $State.Status
    if ($null -eq $status) {
        $status = New-Object Workflow.WorkflowStatus
    }

    $recordUid = $FallbackRecordUid
    $recordName = $FallbackRecordName
    if ($State.Resource) {
        if ($State.Resource.Value -and -not $State.Resource.Value.IsEmpty) {
            $recordUid = encodePamByteString -ByteString $State.Resource.Value
        }
        if (-not [string]::IsNullOrWhiteSpace($State.Resource.Name)) {
            $recordName = $State.Resource.Name
        }
    }

    $approvedBy = @(
        foreach ($approval in @($status.ApprovedBy)) {
            [ordered]@{
                user = if ([string]::IsNullOrEmpty($approval.User)) { "User ID $($approval.UserId)" } else { $approval.User }
                approved_on = convertPamWorkflowTimestamp -Timestamp $approval.ApprovedOn -Raw:$RawTimestamps
            }
        }
    )

    return [ordered]@{
        flow_uid = if ($State.FlowUid -and -not $State.FlowUid.IsEmpty) { encodePamByteString -ByteString $State.FlowUid } else { $null }
        record_uid = $recordUid
        record_name = $recordName
        stage = [KeeperSecurity.Plugins.PAM.WorkflowUtils]::FormatStage($status)
        conditions = @($status.Conditions | ForEach-Object { [KeeperSecurity.Plugins.PAM.WorkflowUtils]::FormatCondition($_) })
        escalated = [bool]$status.Escalated
        checked_out_by = if ([string]::IsNullOrEmpty($status.CheckedOutBy)) { $null } else { $status.CheckedOutBy }
        can_force_checkin = [bool]$status.CanForceCheckIn
        started_on = convertPamWorkflowTimestamp -Timestamp $status.StartedOn -Raw:$RawTimestamps
        expires_on = convertPamWorkflowTimestamp -Timestamp $status.ExpiresOn -Raw:$RawTimestamps
        approved_by = $approvedBy
    }
}

function script:testPamWorkflowExempt {
    Param (
        [Parameter(Mandatory = $true)]
        [KeeperSecurity.Authentication.IAuthentication] $Auth,
        [Parameter(Mandatory = $true)]
        [KeeperSecurity.Vault.VaultOnline] $Vault,
        [Parameter(Mandatory = $true)]
        [KeeperSecurity.Vault.TypedRecord] $Record
    )

    [string[]] $teamUids = @($Vault.Teams | ForEach-Object { [string]$_.TeamUid })
    return [KeeperSecurity.Plugins.PAM.WorkflowUtils]::IsWorkflowExemptAsync(
        $Auth, $Record, $teamUids).GetAwaiter().GetResult()
}

function New-KeeperPamWorkflow {
    <#
        .SYNOPSIS
        Create workflow settings for a PAM resource record.

        .DESCRIPTION
        Creates workflow settings through the SDK PAM WorkflowUtils API.
        Workflow settings are stored by Keeper Router and are not record fields.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, DefaultParameterSetName = 'Execute')]
    [Alias('pam-workflow-new', 'pam-wf-new')]
    Param (
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'Execute')]
        [Alias('r')]
        [string] $Record,

        [Parameter(Mandatory = $true, ParameterSetName = 'Help')]
        [Alias('h')]
        [switch] $Help,

        [Parameter()]
        [Alias('n')]
        [ValidateRange(0, 2147483647)]
        [int] $ApprovalsNeeded = 1,

        [Parameter()]
        [Alias('co')]
        [switch] $Checkout,

        [Parameter()]
        [Alias('sa')]
        [switch] $StartOnApproval,

        [Parameter()]
        [Alias('rr')]
        [switch] $RequireReason,

        [Parameter()]
        [Alias('rt')]
        [switch] $RequireTicket,

        [Parameter()]
        [Alias('rm')]
        [switch] $RequireMfa,

        [Parameter()]
        [Alias('d')]
        [string] $Duration = '1d',

        [Parameter()]
        [string] $AllowedDays,

        [Parameter()]
        [string] $TimeRange,

        [Parameter()]
        [Alias('u')]
        [string[]] $User,

        [Parameter()]
        [string[]] $Approver,

        [Parameter()]
        [Alias('t')]
        [string[]] $Team,

        [Parameter()]
        [ValidateSet('table', 'json')]
        [string] $Format = 'table'
    )

    if ($Help) { Get-Help -Name New-KeeperPamWorkflow -Full; return }
    if ([string]::IsNullOrWhiteSpace($Record)) { Write-Error -Message 'A PAM resource record UID or title is required.' -ErrorAction Stop }

    $auth = getPamWorkflowAuth
    assertPamWorkflowManagementPermission -Auth $auth

    $vault = getPamVault
    $resource = resolvePamWorkflowRecord -Vault $vault -Identifier $Record -ValidateWorkflowType
    $existing = $null
    try {
        $existing = [KeeperSecurity.Plugins.PAM.WorkflowUtils]::ReadWorkflowConfigAsync(
            $auth, $resource.Uid, $resource.Title).GetAwaiter().GetResult()
    }
    catch {
        Write-Error -Message ('Failed to verify whether a PAM workflow is already configured. ' +
            [KeeperSecurity.Plugins.PAM.WorkflowUtils]::SanitizeRouterError($_.Exception)) -ErrorAction Stop
    }

    if ($null -ne $existing) {
        Write-Error -Message "Workflow is already configured for `"$($resource.Title)`" ($($resource.Uid)). Use Get-KeeperPamWorkflow to inspect it." -ErrorAction Stop
    }

    $approverUsers = @($User) + @($Approver) |
        Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
        ForEach-Object { [string]$_.Trim() } |
        Select-Object -Unique
    $teamUids = @($Team) |
        Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
        ForEach-Object { resolvePamWorkflowTeamUid -Identifier ([string]$_) } |
        Select-Object -Unique
    if ($ApprovalsNeeded -gt 0 -and @($approverUsers).Count -eq 0 -and @($teamUids).Count -eq 0) {
        Write-Error -Message 'At least one -Approver, -User, or -Team is required when -ApprovalsNeeded is greater than zero.' -ErrorAction Stop
    }

    try {
        $durationMs = [KeeperSecurity.Plugins.PAM.WorkflowUtils]::ConvertToMilliseconds(
            $(if ([string]::IsNullOrWhiteSpace($Duration)) { '1d' } else { $Duration }))
        $temporalFilter = [KeeperSecurity.Plugins.PAM.WorkflowUtils]::BuildTemporalFilter($AllowedDays, $TimeRange)
    }
    catch {
        Write-Error -Message $_.Exception.Message -ErrorAction Stop
    }

    if ($durationMs -le 0) {
        Write-Error -Message 'Duration must be greater than zero.' -ErrorAction Stop
    }

    $parameters = New-Object Workflow.WorkflowParameters
    $parameters.Resource = [KeeperSecurity.Plugins.PAM.WorkflowUtils]::CreateRecordRef($resource.Uid, $resource.Title)
    $parameters.ApprovalsNeeded = $ApprovalsNeeded
    $parameters.CheckoutNeeded = $Checkout.IsPresent
    $parameters.StartAccessOnApproval = $StartOnApproval.IsPresent
    $parameters.RequireReason = $RequireReason.IsPresent
    $parameters.RequireTicket = $RequireTicket.IsPresent
    $parameters.RequireMFA = $RequireMfa.IsPresent
    $parameters.AccessLength = $durationMs
    if ($null -ne $temporalFilter) {
        $parameters.AllowedTimes = $temporalFilter
    }

    if (-not $PSCmdlet.ShouldProcess($resource.Title, 'Create PAM workflow')) {
        return
    }

    try {
        $null = [KeeperSecurity.Plugins.PAM.WorkflowUtils]::CreateWorkflowConfigAsync(
            $auth, $parameters).GetAwaiter().GetResult()
    }
    catch {
        Write-Error -Message "Failed to create PAM workflow: $([KeeperSecurity.Plugins.PAM.WorkflowUtils]::SanitizeRouterError($_.Exception))" -ErrorAction Stop
    }

    $approversAdded = @()
    $approverError = $null
    if (@($approverUsers).Count -gt 0 -or @($teamUids).Count -gt 0) {
        try {
            $null = [KeeperSecurity.Plugins.PAM.WorkflowUtils]::AddWorkflowApproversAsync(
                $auth, $resource.Uid, $resource.Title, [string[]]$approverUsers, [string[]]$teamUids).GetAwaiter().GetResult()
            $approversAdded = @($approverUsers) + @($teamUids)
        }
        catch {
            $approverError = [KeeperSecurity.Plugins.PAM.WorkflowUtils]::SanitizeRouterError($_.Exception)
        }
    }

    $result = [ordered]@{
        status = if ($null -eq $approverError) { 'success' } else { 'partial' }
        record_uid = $resource.Uid
        record_name = $resource.Title
        workflow_config = [ordered]@{
            approvals_needed = $parameters.ApprovalsNeeded
            checkout_needed = $parameters.CheckoutNeeded
            require_reason = $parameters.RequireReason
            require_ticket = $parameters.RequireTicket
            require_mfa = $parameters.RequireMFA
            access_duration = [KeeperSecurity.Plugins.PAM.WorkflowUtils]::FormatDuration($parameters.AccessLength)
        }
        approvers = @($approversAdded)
    }
    if ($null -ne $approverError) {
        $partialFailureMessage = "Workflow was created, but approvers could not be added: $approverError"
        $result['warning'] = $partialFailureMessage
        Write-Error -Message $partialFailureMessage `
            -ErrorId 'PamWorkflowApproverAdditionFailed' `
            -Category OperationStopped `
            -TargetObject $resource.Uid
    }
    if ($Format -eq 'json') { $result | ConvertTo-Json -Depth 8 } else { [PSCustomObject]$result }
}

function Get-KeeperPamWorkflow {
    <#
        .SYNOPSIS
        Read workflow settings for a PAM resource record.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Execute')]
    [Alias('pam-workflow-read', 'pam-wf-read')]
    Param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Help')]
        [Alias('h')]
        [switch] $Help,

        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'Execute')]
        [Alias('r')]
        [string] $Record,

        [Parameter()]
        [ValidateSet('table', 'json')]
        [string] $Format = 'table'
    )

    if ($Help) { Get-Help -Name Get-KeeperPamWorkflow -Full; return }
    if ([string]::IsNullOrWhiteSpace($Record)) { Write-Error -Message 'A PAM resource record UID or title is required.' -ErrorAction Stop }

    $auth = getPamWorkflowAuth
    $vault = getPamVault
    $resource = resolvePamWorkflowRecord -Vault $vault -Identifier $Record
    try {
        $config = [KeeperSecurity.Plugins.PAM.WorkflowUtils]::ReadWorkflowConfigAsync(
            $auth, $resource.Uid, $resource.Title).GetAwaiter().GetResult()
    }
    catch {
        Write-Error -Message "Failed to read PAM workflow: $([KeeperSecurity.Plugins.PAM.WorkflowUtils]::SanitizeRouterError($_.Exception))" -ErrorAction Stop
    }

    if ($null -eq $config) {
        $result = [ordered]@{ status = 'no_workflow'; message = 'No workflow configured' }
    }
    else {
        $result = convertPamWorkflowConfigToObject -Config $config -RecordUid $resource.Uid -RecordName $resource.Title
    }

    if ($Format -eq 'json') { $result | ConvertTo-Json -Depth 12 } else { [PSCustomObject]$result }
}

function script:resolvePamWorkflowTeamUid {
    Param (
        [Parameter(Mandatory = $true)]
        [string] $Identifier
    )

    $vault = getPamVault
    $enterprise = $Script:Context.Enterprise
    if ($vault.Auth -and $vault.Auth.AuthContext.IsEnterpriseAdmin) {
        $enterprise = getEnterprise
    }
    $teams = if ($enterprise -and $enterprise.enterpriseData) { @($enterprise.enterpriseData.Teams) } else { @() }
    $match = $teams | Where-Object {
        [string]::Equals([string]$_.Uid, $Identifier.Trim(), [StringComparison]::Ordinal) -or
        [string]::Equals([string]$_.Name, $Identifier.Trim(), [StringComparison]::OrdinalIgnoreCase)
    }
    if (@($match).Count -eq 1) {
        return [string]$match[0].Uid
    }

    $vaultMatch = @($vault.Teams | Where-Object {
        [string]::Equals([string]$_.TeamUid, $Identifier.Trim(), [StringComparison]::Ordinal) -or
        [string]::Equals([string]$_.Name, $Identifier.Trim(), [StringComparison]::OrdinalIgnoreCase)
    })
    if ($vaultMatch.Count -eq 1) {
        return [string]$vaultMatch[0].TeamUid
    }

    throw "Team `"$Identifier`" not found. Use a valid team UID or team name."
}

function Update-KeeperPamWorkflow {
    <#
        .SYNOPSIS
        Update selected workflow settings for a PAM resource record.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, DefaultParameterSetName = 'Execute')]
    [Alias('pam-workflow-edit', 'pam-wf-edit')]
    Param (
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'Execute')]
        [Alias('r')]
        [string] $Record,

        [Parameter(Mandatory = $true, ParameterSetName = 'Help')]
        [Alias('h')]
        [switch] $Help,

        [Parameter()]
        [Alias('n')]
        [ValidateRange(0, 2147483647)]
        [Nullable[int]] $ApprovalsNeeded,

        [Parameter()]
        [Alias('co')]
        [Nullable[bool]] $Checkout,

        [Parameter()]
        [Alias('sa')]
        [Nullable[bool]] $StartOnApproval,

        [Parameter()]
        [Alias('rr')]
        [Nullable[bool]] $RequireReason,

        [Parameter()]
        [Alias('rt')]
        [Nullable[bool]] $RequireTicket,

        [Parameter()]
        [Alias('rm')]
        [Nullable[bool]] $RequireMfa,

        [Parameter()]
        [Alias('d')]
        [string] $Duration,

        [Parameter()]
        [string] $AllowedDays,

        [Parameter()]
        [string] $TimeRange,

        [Parameter()]
        [ValidateSet('table', 'json')]
        [string] $Format = 'table'
    )

    if ($Help) { Get-Help -Name Update-KeeperPamWorkflow -Full; return }
    if ([string]::IsNullOrWhiteSpace($Record)) { Write-Error -Message 'A PAM resource record UID or title is required.' -ErrorAction Stop }

    $auth = getPamWorkflowAuth
    assertPamWorkflowManagementPermission -Auth $auth
    $vault = getPamVault
    $resource = resolvePamWorkflowRecord -Vault $vault -Identifier $Record
    try {
        $current = [KeeperSecurity.Plugins.PAM.WorkflowUtils]::ReadWorkflowConfigAsync(
            $auth, $resource.Uid, $resource.Title).GetAwaiter().GetResult()
    }
    catch {
        Write-Error -Message "Failed to read PAM workflow: $([KeeperSecurity.Plugins.PAM.WorkflowUtils]::SanitizeRouterError($_.Exception))" -ErrorAction Stop
    }
    if ($null -eq $current -or $null -eq $current.Parameters) {
        Write-Error -Message "No workflow found for `"$($resource.Title)`". Create one first with New-KeeperPamWorkflow." -ErrorAction Stop
    }

    $parameters = $current.Parameters.Clone()
    $updatesProvided = $false
    if ($PSBoundParameters.ContainsKey('ApprovalsNeeded')) { $parameters.ApprovalsNeeded = $ApprovalsNeeded.Value; $updatesProvided = $true }
    if ($PSBoundParameters.ContainsKey('Checkout')) { $parameters.CheckoutNeeded = $Checkout.Value; $updatesProvided = $true }
    if ($PSBoundParameters.ContainsKey('StartOnApproval')) { $parameters.StartAccessOnApproval = $StartOnApproval.Value; $updatesProvided = $true }
    if ($PSBoundParameters.ContainsKey('RequireReason')) { $parameters.RequireReason = $RequireReason.Value; $updatesProvided = $true }
    if ($PSBoundParameters.ContainsKey('RequireTicket')) { $parameters.RequireTicket = $RequireTicket.Value; $updatesProvided = $true }
    if ($PSBoundParameters.ContainsKey('RequireMfa')) { $parameters.RequireMFA = $RequireMfa.Value; $updatesProvided = $true }

    try {
        if ($PSBoundParameters.ContainsKey('Duration')) {
            $parameters.AccessLength = [KeeperSecurity.Plugins.PAM.WorkflowUtils]::ConvertToMilliseconds($Duration)
            if ($parameters.AccessLength -le 0) { throw 'Duration must be greater than zero.' }
            $updatesProvided = $true
        }
        if ($PSBoundParameters.ContainsKey('AllowedDays') -or $PSBoundParameters.ContainsKey('TimeRange')) {
            $parameters.AllowedTimes = [KeeperSecurity.Plugins.PAM.WorkflowUtils]::BuildTemporalFilter(
                $AllowedDays, $TimeRange, $current.Parameters.AllowedTimes)
            $updatesProvided = $true
        }
    }
    catch {
        Write-Error -Message $_.Exception.Message -ErrorAction Stop
    }

    if (-not $updatesProvided) {
        Write-Error -Message 'No updates provided. Specify at least one workflow option to update.' -ErrorAction Stop
    }
    if (-not $PSCmdlet.ShouldProcess($resource.Title, 'Update PAM workflow')) { return }

    try {
        $null = [KeeperSecurity.Plugins.PAM.WorkflowUtils]::UpdateWorkflowConfigAsync(
            $auth, $parameters).GetAwaiter().GetResult()
    }
    catch {
        Write-Error -Message "Failed to update PAM workflow: $([KeeperSecurity.Plugins.PAM.WorkflowUtils]::SanitizeRouterError($_.Exception))" -ErrorAction Stop
    }

    $result = [ordered]@{ status = 'success'; record_uid = $resource.Uid; record_name = $resource.Title }
    if ($Format -eq 'json') { $result | ConvertTo-Json -Depth 8 } else { [PSCustomObject]$result }
}

function Remove-KeeperPamWorkflow {
    <#
        .SYNOPSIS
        Delete workflow settings from a PAM resource record.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High', DefaultParameterSetName = 'Execute')]
    [Alias('pam-workflow-delete', 'pam-wf-delete')]
    Param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Help')]
        [Alias('h')]
        [switch] $Help,

        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'Execute')]
        [Alias('r')]
        [string] $Record,

        [Parameter()]
        [ValidateSet('table', 'json')]
        [string] $Format = 'table'
    )

    if ($Help) { Get-Help -Name Remove-KeeperPamWorkflow -Full; return }
    if ([string]::IsNullOrWhiteSpace($Record)) { Write-Error -Message 'A PAM resource record UID or title is required.' -ErrorAction Stop }

    $auth = getPamWorkflowAuth
    assertPamWorkflowManagementPermission -Auth $auth
    $vault = getPamVault
    $resource = resolvePamWorkflowRecord -Vault $vault -Identifier $Record
    try {
        $current = [KeeperSecurity.Plugins.PAM.WorkflowUtils]::ReadWorkflowConfigAsync(
            $auth, $resource.Uid, $resource.Title).GetAwaiter().GetResult()
    }
    catch {
        Write-Error -Message "Failed to read PAM workflow before delete: $([KeeperSecurity.Plugins.PAM.WorkflowUtils]::SanitizeRouterError($_.Exception))" -ErrorAction Stop
    }
    if ($null -eq $current) {
        Write-Error -Message "No workflow configured for `"$($resource.Title)`"." -ErrorAction Stop
    }
    if (-not $PSCmdlet.ShouldProcess($resource.Title, 'Delete PAM workflow')) { return }

    try {
        $null = [KeeperSecurity.Plugins.PAM.WorkflowUtils]::DeleteWorkflowConfigAsync(
            $auth, $resource.Uid, $resource.Title).GetAwaiter().GetResult()
    }
    catch {
        Write-Error -Message "Failed to delete PAM workflow: $([KeeperSecurity.Plugins.PAM.WorkflowUtils]::SanitizeRouterError($_.Exception))" -ErrorAction Stop
    }

    $result = [ordered]@{ status = 'success'; record_uid = $resource.Uid; record_name = $resource.Title }
    if ($Format -eq 'json') { $result | ConvertTo-Json -Depth 8 } else { [PSCustomObject]$result }
}

function Add-KeeperPamWorkflowApprover {
    <#
        .SYNOPSIS
        Add users or teams as PAM workflow approvers.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, DefaultParameterSetName = 'Execute')]
    [Alias('pam-workflow-add-approver', 'pam-wf-add-approver')]
    Param (
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'Execute')]
        [Alias('r')]
        [string] $Record,

        [Parameter(Mandatory = $true, ParameterSetName = 'Help')]
        [Alias('h')]
        [switch] $Help,

        [Parameter()]
        [Alias('u')]
        [string[]] $User,

        [Parameter()]
        [string[]] $Approver,

        [Parameter()]
        [Alias('t')]
        [string[]] $Team,

        [Parameter()]
        [Alias('e')]
        [switch] $Escalation,

        [Parameter()]
        [string] $EscalationAfter,

        [Parameter()]
        [ValidateSet('table', 'json')]
        [string] $Format = 'table'
    )

    if ($Help) { Get-Help -Name Add-KeeperPamWorkflowApprover -Full; return }
    if ([string]::IsNullOrWhiteSpace($Record)) { Write-Error -Message 'A PAM resource record UID or title is required.' -ErrorAction Stop }

    $auth = getPamWorkflowAuth
    assertPamWorkflowManagementPermission -Auth $auth

    $users = @($User) + @($Approver) |
        Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
        ForEach-Object { [string]$_.Trim() } |
        Select-Object -Unique
    $teams = @($Team) |
        Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
        ForEach-Object { resolvePamWorkflowTeamUid -Identifier ([string]$_) } |
        Select-Object -Unique
    if (@($users).Count -eq 0 -and @($teams).Count -eq 0) {
        Write-Error -Message 'Specify at least one -User, -Approver, or -Team.' -ErrorAction Stop
    }
    if (-not [string]::IsNullOrWhiteSpace($EscalationAfter) -and -not $Escalation.IsPresent) {
        Write-Error -Message '-EscalationAfter requires -Escalation.' -ErrorAction Stop
    }

    $escalationAfterMs = 0
    if (-not [string]::IsNullOrWhiteSpace($EscalationAfter)) {
        try {
            $escalationAfterMs = [KeeperSecurity.Plugins.PAM.WorkflowUtils]::ConvertToMilliseconds($EscalationAfter)
        }
        catch {
            Write-Error -Message "Invalid escalation duration `"$EscalationAfter`": $($_.Exception.Message)" -ErrorAction Stop
        }
    }

    $vault = getPamVault
    $resource = resolvePamWorkflowRecord -Vault $vault -Identifier $Record
    if (-not $PSCmdlet.ShouldProcess($resource.Title, 'Add PAM workflow approvers')) { return }
    try {
        $null = [KeeperSecurity.Plugins.PAM.WorkflowUtils]::AddWorkflowApproversAsync(
            $auth, $resource.Uid, $resource.Title, [string[]]$users, [string[]]$teams,
            $Escalation.IsPresent, $escalationAfterMs).GetAwaiter().GetResult()
    }
    catch {
        Write-Error -Message "Failed to add PAM workflow approvers: $([KeeperSecurity.Plugins.PAM.WorkflowUtils]::SanitizeRouterError($_.Exception))" -ErrorAction Stop
    }

    $result = [ordered]@{
        status = 'success'
        record_uid = $resource.Uid
        record_name = $resource.Title
        approvers_added = @($users).Count + @($teams).Count
        escalation = $Escalation.IsPresent
    }
    if ($escalationAfterMs -gt 0) { $result['escalation_after'] = [KeeperSecurity.Plugins.PAM.WorkflowUtils]::FormatDuration($escalationAfterMs) }
    if ($Format -eq 'json') { $result | ConvertTo-Json -Depth 8 } else { [PSCustomObject]$result }
}

function Remove-KeeperPamWorkflowApprover {
    <#
        .SYNOPSIS
        Remove users or teams from PAM workflow approvers.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, DefaultParameterSetName = 'Execute')]
    [Alias('pam-workflow-remove-approver', 'pam-wf-remove-approver')]
    Param (
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'Execute')]
        [Alias('r')]
        [string] $Record,

        [Parameter(Mandatory = $true, ParameterSetName = 'Help')]
        [Alias('h')]
        [switch] $Help,

        [Parameter()]
        [Alias('u')]
        [string[]] $User,

        [Parameter()]
        [string[]] $Approver,

        [Parameter()]
        [Alias('t')]
        [string[]] $Team,

        [Parameter()]
        [ValidateSet('table', 'json')]
        [string] $Format = 'table'
    )

    if ($Help) { Get-Help -Name Remove-KeeperPamWorkflowApprover -Full; return }
    if ([string]::IsNullOrWhiteSpace($Record)) { Write-Error -Message 'A PAM resource record UID or title is required.' -ErrorAction Stop }

    $auth = getPamWorkflowAuth
    assertPamWorkflowManagementPermission -Auth $auth

    $users = @($User) + @($Approver) |
        Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
        ForEach-Object { [string]$_.Trim() } |
        Select-Object -Unique
    $teams = @($Team) |
        Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
        ForEach-Object { resolvePamWorkflowTeamUid -Identifier ([string]$_) } |
        Select-Object -Unique
    if (@($users).Count -eq 0 -and @($teams).Count -eq 0) {
        Write-Error -Message 'Specify at least one -User, -Approver, or -Team.' -ErrorAction Stop
    }

    $vault = getPamVault
    $resource = resolvePamWorkflowRecord -Vault $vault -Identifier $Record
    if (-not $PSCmdlet.ShouldProcess($resource.Title, 'Remove PAM workflow approvers')) { return }
    try {
        $null = [KeeperSecurity.Plugins.PAM.WorkflowUtils]::DeleteWorkflowApproversAsync(
            $auth, $resource.Uid, $resource.Title, [string[]]$users, [string[]]$teams).GetAwaiter().GetResult()
    }
    catch {
        Write-Error -Message "Failed to remove PAM workflow approvers: $([KeeperSecurity.Plugins.PAM.WorkflowUtils]::SanitizeRouterError($_.Exception))" -ErrorAction Stop
    }

    $result = [ordered]@{
        status = 'success'
        record_uid = $resource.Uid
        record_name = $resource.Title
        approvers_removed = @($users).Count + @($teams).Count
    }
    if ($Format -eq 'json') { $result | ConvertTo-Json -Depth 8 } else { [PSCustomObject]$result }
}

function Get-KeeperPamWorkflowState {
    <#
        .SYNOPSIS
        Get the workflow state for a PAM resource record.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Execute')]
    [Alias('pam-workflow-state', 'pam-wf-state')]
    Param (
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'Execute')]
        [Alias('r')]
        [string] $Record,

        [Parameter(Mandatory = $true, ParameterSetName = 'Help')]
        [Alias('h')]
        [switch] $Help,

        [Parameter()]
        [ValidateSet('table', 'json')]
        [string] $Format = 'table'
    )

    if ($Help) { Get-Help -Name Get-KeeperPamWorkflowState -Full; return }
    if ([string]::IsNullOrWhiteSpace($Record)) { Write-Error -Message 'A PAM resource record UID or title is required.' -ErrorAction Stop }

    $auth = getPamWorkflowAuth
    $vault = getPamVault
    $resource = resolvePamWorkflowRecord -Vault $vault -Identifier $Record
    try {
        if (testPamWorkflowExempt -Auth $auth -Vault $vault -Record $resource) {
            $result = [ordered]@{ status = 'exempt'; message = 'Workflow not required' }
            if ($Format -eq 'json') { $result | ConvertTo-Json -Depth 8 } else { [PSCustomObject]$result }
            return
        }

        $state = [KeeperSecurity.Plugins.PAM.WorkflowUtils]::GetWorkflowStateByRecordAsync(
            $auth, $resource.Uid, $resource.Title).GetAwaiter().GetResult()
    }
    catch {
        Write-Error -Message "Failed to get workflow state: $([KeeperSecurity.Plugins.PAM.WorkflowUtils]::SanitizeRouterError($_.Exception))" -ErrorAction Stop
    }

    if ($null -eq $state) {
        $result = [ordered]@{ status = 'no_workflow'; message = 'No workflow found' }
    }
    else {
        $result = convertPamWorkflowStateToObject -State $state `
            -FallbackRecordUid $resource.Uid -FallbackRecordName $resource.Title `
            -RawTimestamps:($Format -eq 'json')
    }

    if ($Format -eq 'json') { $result | ConvertTo-Json -Depth 12 } else { [PSCustomObject]$result }
}

function Get-KeeperPamWorkflowMyAccess {
    <#
        .SYNOPSIS
        Get current user's active workflow access requests.
    #>
    [CmdletBinding()]
    [Alias('pam-workflow-my-access', 'pam-wf-my-access')]
    Param (
        [Parameter()]
        [Alias('h')]
        [switch] $Help,

        [Parameter()]
        [ValidateSet('table', 'json')]
        [string] $Format = 'table'
    )

    if ($Help) { Get-Help -Name Get-KeeperPamWorkflowMyAccess -Full; return }

    $auth = getPamWorkflowAuth
    try {
        $accessState = [KeeperSecurity.Plugins.PAM.WorkflowUtils]::GetUserAccessStateAsync($auth).GetAwaiter().GetResult()
    }
    catch {
        Write-Error -Message "Failed to get user access state: $([KeeperSecurity.Plugins.PAM.WorkflowUtils]::SanitizeRouterError($_.Exception))" -ErrorAction Stop
    }

    if ($null -eq $accessState -or @($accessState.Workflows).Count -eq 0) {
        if ($Format -eq 'json') {
            $result = [ordered]@{ workflows = @() }
            $result | ConvertTo-Json -Depth 8
        }
        else {
            [PSCustomObject]@{ message = 'No active workflows'; workflow_count = 0 }
        }
        return
    }

    $workflows = @(
        foreach ($wf in @($accessState.Workflows)) {
            convertPamWorkflowStateToObject -State $wf -RawTimestamps:($Format -eq 'json')
        }
    )

    if ($Format -eq 'json') {
        $result = [ordered]@{ workflows = @($workflows) }
        $result | ConvertTo-Json -Depth 12
    }
    else {
        @($workflows) | ForEach-Object { [PSCustomObject]$_ }
    }
}
