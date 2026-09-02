#requires -Version 5.1

function script:resolvePamWorkflowRecord {
    Param (
        [Parameter(Mandatory = $true)]
        [KeeperSecurity.Vault.VaultOnline] $Vault,
        [Parameter(Mandatory = $true)]
        [string] $Identifier,
        [bool] $AllowMissing = $false
    )

    [KeeperSecurity.Vault.KeeperRecord]$byUid = $null
    if ($Vault.TryGetKeeperRecord($Identifier, [ref]$byUid) -and $byUid -is [KeeperSecurity.Vault.TypedRecord]) {
        return $byUid
    }

    $nameMatches = @($Vault.KeeperRecords | Where-Object {
            $_ -is [KeeperSecurity.Vault.TypedRecord] -and
            [string]::Equals($_.Title, $Identifier, [System.StringComparison]::OrdinalIgnoreCase)
        })

    if ($nameMatches.Count -gt 1) {
        Write-Error -Message "Record name '$Identifier' is not unique. Use record UID." -ErrorAction Stop
    }
    if ($nameMatches.Count -eq 1) {
        return $nameMatches[0]
    }

    if ($AllowMissing) {
        return $null
    }

    Write-Error -Message "Record `"$Identifier`" not found" -ErrorAction Stop
}

function script:decodePamWorkflowUidBytes {
    Param (
        [Parameter(Mandatory = $true)]
        [string] $Uid,
        [Parameter(Mandatory = $true)]
        [string] $ErrorMessage
    )

    $bytes = $null
    try {
        $bytes = [KeeperSecurity.Utils.CryptoUtils]::Base64UrlDecode($Uid.Trim())
    }
    catch {
        $bytes = $null
    }

    if ($null -eq $bytes -or $bytes.Length -ne 16) {
        Write-Error -Message $ErrorMessage -ErrorAction Stop
    }

    return $bytes
}

function script:testPamWorkflowExempt {
    Param (
        [Parameter(Mandatory = $true)]
        [KeeperSecurity.Authentication.IAuthentication] $Auth,
        [Parameter(Mandatory = $true)]
        [KeeperSecurity.Vault.TypedRecord] $Record,
        [KeeperSecurity.Vault.VaultOnline] $Vault
    )

    $teamUids = New-Object 'System.Collections.Generic.List[string]'
    if ($null -ne $Vault -and $null -ne $Vault.Teams) {
        foreach ($team in $Vault.Teams) {
            [void]$teamUids.Add($team.TeamUid)
        }
    }

    return [KeeperSecurity.Plugins.PAM.WorkflowUtils]::IsWorkflowExemptAsync($Auth, $Record, $teamUids).GetAwaiter().GetResult()
}

function script:writePamWorkflowExemptMessage {
    Write-Output ''
    Write-Output 'You are exempt from workflow restrictions on this record.'
    Write-Output 'As a record owner or approver, you can access this resource directly.'
    Write-Output ''
}

function script:resolvePamWorkflowResourceName {
    Param (
        [KeeperSecurity.Vault.VaultOnline] $Vault,
        $Resource
    )

    if ($null -eq $Resource) {
        return ''
    }

    if (-not [string]::IsNullOrEmpty($Resource.Name)) {
        return $Resource.Name
    }

    if ($null -ne $Resource.Value -and -not $Resource.Value.IsEmpty) {
        $uid = [KeeperSecurity.Utils.CryptoUtils]::Base64UrlEncode($Resource.Value.ToByteArray())
        [KeeperSecurity.Vault.KeeperRecord]$rec = $null
        if ($null -ne $Vault -and $Vault.TryGetKeeperRecord($uid, [ref]$rec) -and -not [string]::IsNullOrEmpty($rec.Title)) {
            return $rec.Title
        }
        return $null
    }

    return ''
}

function script:getPamWorkflowFlowUidString {
    Param ($FlowUid)

    if ($null -eq $FlowUid -or $FlowUid.IsEmpty) {
        return ''
    }
    return [KeeperSecurity.Utils.CryptoUtils]::Base64UrlEncode($FlowUid.ToByteArray())
}

function Get-KeeperPamWorkflowPending {
    <#
        .Synopsis
        Get PAM workflow access requests pending your approval.

        .Description
        Lists workflow access requests awaiting approval from the current user, either as a
        named approver or through team membership. Requests you submitted yourself are excluded.

        .Example
        Get-KeeperPamWorkflowPending
        pam-workflow-pending
    #>
    [CmdletBinding()]
    Param ()

    $vault = getPamVault
    $auth = getPamEnterpriseAuth

    $response = invokePamSdkCall {
        [KeeperSecurity.Plugins.PAM.WorkflowUtils]::GetApprovalRequestsAsync($auth).GetAwaiter().GetResult()
    }
    if ($null -eq $response -or $null -eq $response.Workflows -or $response.Workflows.Count -eq 0) {
        Write-Output 'No approval requests'
        return
    }

    $pending = invokePamSdkCall {
        [KeeperSecurity.Plugins.PAM.WorkflowUtils]::FilterPendingApprovalsAsync(
            $auth, $response.Workflows, $auth.Username).GetAwaiter().GetResult()
    }
    if ($null -eq $pending -or $pending.Count -eq 0) {
        Write-Output 'No pending approval requests'
        return
    }

    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($wf in $pending) {
        $recordUid = ''
        if ($null -ne $wf.Resource -and $null -ne $wf.Resource.Value -and -not $wf.Resource.Value.IsEmpty) {
            $recordUid = [KeeperSecurity.Utils.CryptoUtils]::Base64UrlEncode($wf.Resource.Value.ToByteArray())
        }

        $recordKey = $null
        if (-not [string]::IsNullOrEmpty($recordUid)) {
            [KeeperSecurity.Vault.KeeperRecord]$rec = $null
            if ($vault.TryGetKeeperRecord($recordUid, [ref]$rec)) {
                $recordKey = $rec.RecordKey
            }
        }

        $reasonEncrypted = [KeeperSecurity.Plugins.PAM.WorkflowUtils]::ExtractWorkflowParameter($wf, 'reason')
        $ticketEncrypted = [KeeperSecurity.Plugins.PAM.WorkflowUtils]::ExtractWorkflowParameter($wf, 'ticket')
        $reason = if ($null -ne $recordKey) {
            [KeeperSecurity.Plugins.PAM.WorkflowUtils]::DecryptWorkflowParameter($recordKey, $reasonEncrypted)
        } else { '' }
        $ticket = if ($null -ne $recordKey) {
            [KeeperSecurity.Plugins.PAM.WorkflowUtils]::DecryptWorkflowParameter($recordKey, $ticketEncrypted)
        } else { '' }

        $started = if ($wf.StartedOn -gt 0) {
            [DateTimeOffset]::FromUnixTimeMilliseconds($wf.StartedOn).LocalDateTime.ToString('yyyy-MM-dd HH:mm:ss')
        }
        else { '' }
        $expires = if ($wf.ExpiresOn -gt 0) {
            [DateTimeOffset]::FromUnixTimeMilliseconds($wf.ExpiresOn).LocalDateTime.ToString('yyyy-MM-dd HH:mm:ss')
        }
        else { '' }
        $duration = if ($wf.ExpiresOn -gt 0 -and $wf.StartedOn -gt 0) {
            [KeeperSecurity.Plugins.PAM.WorkflowUtils]::FormatDuration($wf.ExpiresOn - $wf.StartedOn)
        }
        else { '' }
        $requestedBy = if (-not [string]::IsNullOrEmpty($wf.User)) { $wf.User } else { "User ID $($wf.UserId)" }

        $rows.Add([PSCustomObject]@{
                'Record Name'  = resolvePamWorkflowResourceName -Vault $vault -Resource $wf.Resource
                'Record UID'   = $recordUid
                'Flow UID'     = getPamWorkflowFlowUidString $wf.FlowUid
                'Requested By' = $requestedBy
                'Reason'       = $reason
                'Ticket'       = $ticket
                'Started'      = $started
                'Expires'      = $expires
                'Duration'     = $duration
            })
    }

    $rows | Format-Table -AutoSize
}

function Approve-KeeperPamWorkflowAccess {
    <#
        .Synopsis
        Approve a PAM workflow access request.

        .Parameter FlowUid
        Flow UID of the pending request (see Get-KeeperPamWorkflowPending). Alias: -f.

        .Example
        Approve-KeeperPamWorkflowAccess -FlowUid "<flow-uid>"
        pam-workflow-approve "<flow-uid>"
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $true)]
        [Alias('f')]
        [string] $FlowUid
    )

    $auth = getPamEnterpriseAuth
    $trimmedFlowUid = $FlowUid.Trim()
    $flowUidBytes = decodePamWorkflowUidBytes -Uid $trimmedFlowUid -ErrorMessage "Invalid flow UID: `"$trimmedFlowUid`""

    $null = invokePamSdkCall {
        [KeeperSecurity.Plugins.PAM.WorkflowUtils]::ApproveWorkflowAccessAsync($auth, $flowUidBytes).GetAwaiter().GetResult()
    }

    Write-Output ''
    Write-Output 'Access request approved'
    Write-Output ''
    Write-Output "Flow UID: $trimmedFlowUid"
    Write-Output ''
}

function Deny-KeeperPamWorkflowAccess {
    <#
        .Synopsis
        Deny a PAM workflow access request.

        .Parameter FlowUid
        Flow UID of the pending request (see Get-KeeperPamWorkflowPending). Alias: -f.

        .Parameter Reason
        Optional reason shown to the requester. Alias: -r.

        .Example
        Deny-KeeperPamWorkflowAccess -FlowUid "<flow-uid>" -Reason "Not authorized"
        pam-workflow-deny "<flow-uid>" -r "Not authorized"
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $true)]
        [Alias('f')]
        [string] $FlowUid,

        [Parameter()]
        [Alias('r')]
        [string] $Reason
    )

    $auth = getPamEnterpriseAuth
    $trimmedFlowUid = $FlowUid.Trim()
    $flowUidBytes = decodePamWorkflowUidBytes -Uid $trimmedFlowUid -ErrorMessage "Invalid flow UID: `"$trimmedFlowUid`""

    $trimmedReason = if ($null -ne $Reason) { $Reason.Trim() } else { '' }
    $denialReasonEncrypted = $null
    if (-not [string]::IsNullOrEmpty($trimmedReason)) {
        $denialReasonEncrypted = invokePamSdkCall {
            [KeeperSecurity.Plugins.PAM.WorkflowUtils]::TryEncryptDenialReasonAsync(
                $auth, $flowUidBytes, $trimmedReason).GetAwaiter().GetResult()
        }
        if ($null -eq $denialReasonEncrypted) {
            Write-Output 'Warning: Could not encrypt denial reason for the requester -- reason will not be attached. The denial itself will still be sent.'
            $trimmedReason = ''
        }
    }

    $null = invokePamSdkCall {
        [KeeperSecurity.Plugins.PAM.WorkflowUtils]::DenyWorkflowAccessAsync(
            $auth, $flowUidBytes, $denialReasonEncrypted).GetAwaiter().GetResult()
    }

    Write-Output ''
    Write-Output 'Access request denied'
    Write-Output ''
    Write-Output "Flow UID: $trimmedFlowUid"
    if (-not [string]::IsNullOrEmpty($trimmedReason)) {
        Write-Output "Reason: $trimmedReason"
    }
    Write-Output ''
}

function Request-KeeperPamWorkflowAccess {
    <#
        .Synopsis
        Request, escalate, or cancel PAM workflow access to a record.

        .Description
        Submits a new access request for a PAM record through its configured workflow.
        Use -Escalate to escalate an already-pending request to escalation approvers, or
        -Cancel to cancel your own pending/active request. Record owners and approvers are
        exempt from workflow restrictions and can access the resource directly.

        .Parameter Record
        PAM resource record UID or title. Alias: -r.

        .Parameter Reason
        Reason for the access request. Alias: -re.

        .Parameter Ticket
        External ticket/reference number. Alias: -t.

        .Parameter Escalate
        Escalate a pending request to escalation approvers. Alias: -e.

        .Parameter Cancel
        Cancel a pending or active workflow request. Alias: -c.

        .Example
        Request-KeeperPamWorkflowAccess -Record "<uid>" -Reason "Need access to investigate an incident"
        Request-KeeperPamWorkflowAccess -Record "<uid>" -Escalate
        Request-KeeperPamWorkflowAccess -Record "<uid>" -Cancel
        pam-workflow-request "<uid>" -re "reason text"
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $true)]
        [Alias('r')]
        [string] $Record,

        [Parameter()]
        [Alias('re')]
        [string] $Reason,

        [Parameter()]
        [Alias('t')]
        [string] $Ticket,

        [Parameter()]
        [Alias('e')]
        [switch] $Escalate,

        [Parameter()]
        [Alias('c')]
        [switch] $Cancel
    )

    if ($Cancel.IsPresent -and $Escalate.IsPresent) {
        Write-Error -Message '-Cancel and -Escalate cannot be used together' -ErrorAction Stop
    }
    if ($Cancel.IsPresent -and (-not [string]::IsNullOrWhiteSpace($Reason) -or -not [string]::IsNullOrWhiteSpace($Ticket))) {
        Write-Error -Message '-Cancel cannot be used with -Reason or -Ticket' -ErrorAction Stop
    }

    $vault = getPamVault
    $auth = getPamEnterpriseAuth
    $record = resolvePamWorkflowRecord -Vault $vault -Identifier $Record.Trim()

    if ($Cancel.IsPresent) {
        $workflowState = invokePamSdkCall {
            [KeeperSecurity.Plugins.PAM.WorkflowUtils]::GetWorkflowStateByRecordAsync(
                $auth, $record.Uid, $record.Title).GetAwaiter().GetResult()
        }
        if ($null -eq $workflowState -or $null -eq $workflowState.FlowUid -or $workflowState.FlowUid.IsEmpty) {
            Write-Error -Message 'No active workflow request found for this record.' -ErrorAction Stop
        }

        $flowRef = [KeeperSecurity.Plugins.PAM.WorkflowUtils]::WorkflowRef($workflowState.FlowUid.ToByteArray())
        $null = invokePamSdkCall {
            [KeeperSecurity.Plugins.PAM.WorkflowUtils]::EndWorkflowAsync($auth, $flowRef).GetAwaiter().GetResult()
        }

        Write-Output ''
        Write-Output 'Workflow request cancelled'
        Write-Output ''
        Write-Output "Record: $($record.Title) ($($record.Uid))"
        Write-Output "Flow UID: $(getPamWorkflowFlowUidString $workflowState.FlowUid)"
        Write-Output ''
        return
    }

    if (testPamWorkflowExempt -Auth $auth -Record $record -Vault $vault) {
        writePamWorkflowExemptMessage
        return
    }

    if ($Escalate.IsPresent) {
        $null = invokePamSdkCall {
            [KeeperSecurity.Plugins.PAM.WorkflowUtils]::RequestEscalationAsync(
                $auth, $record.Uid, $record.Title).GetAwaiter().GetResult()
        }

        Write-Output ''
        Write-Output 'Request escalated'
        Write-Output ''
        Write-Output "Record: $($record.Title) ($($record.Uid))"
        Write-Output ''
        Write-Output 'Escalation approvers have been notified.'
        Write-Output ''
        return
    }

    $trimmedReason = if ($null -ne $Reason) { $Reason.Trim() } else { '' }
    $trimmedTicket = if ($null -ne $Ticket) { $Ticket.Trim() } else { '' }

    $null = invokePamSdkCall {
        [KeeperSecurity.Plugins.PAM.WorkflowUtils]::RequestWorkflowAccessAsync(
            $auth, $record.Uid, $record.Title, $record.RecordKey, $trimmedReason, $trimmedTicket).GetAwaiter().GetResult()
    }

    Write-Output ''
    Write-Output 'Access request sent'
    Write-Output ''
    Write-Output "Record: $($record.Title) ($($record.Uid))"
    if (-not [string]::IsNullOrEmpty($trimmedReason)) {
        Write-Output "Reason: $trimmedReason"
    }
    if (-not [string]::IsNullOrEmpty($trimmedTicket)) {
        Write-Output "Ticket: $trimmedTicket"
    }
    Write-Output ''
    Write-Output 'Approvers have been notified.'
    Write-Output ''
}

function Start-KeeperPamWorkflow {
    <#
        .Synopsis
        Start a PAM workflow (check out a record).

        .Parameter Uid
        Record UID, record title, or Flow UID. Alias: -u.

        .Example
        Start-KeeperPamWorkflow -Uid "<record-or-flow-uid>"
        pam-workflow-start "<uid>"
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $true)]
        [Alias('u')]
        [string] $Uid
    )

    $vault = getPamVault
    $auth = getPamEnterpriseAuth
    $trimmedUid = $Uid.Trim()
    $record = resolvePamWorkflowRecord -Vault $vault -Identifier $trimmedUid -AllowMissing $true

    $state = New-Object Workflow.WorkflowState
    if ($null -ne $record) {
        $state.Resource = [KeeperSecurity.Plugins.PAM.WorkflowUtils]::CreateRecordRef($record.Uid, $record.Title)
    }
    else {
        $uidBytes = decodePamWorkflowUidBytes -Uid $trimmedUid -ErrorMessage "`"$trimmedUid`" is not a known record or a valid flow UID"
        $state.FlowUid = [Google.Protobuf.ByteString]::CopyFrom($uidBytes)
        $state.Resource = [KeeperSecurity.Plugins.PAM.WorkflowUtils]::WorkflowRef($uidBytes)
    }

    $null = invokePamSdkCall {
        [KeeperSecurity.Plugins.PAM.WorkflowUtils]::StartWorkflowAsync($auth, $state).GetAwaiter().GetResult()
    }

    Write-Output ''
    Write-Output 'Workflow started (checked out)'
    Write-Output ''
    if ($null -ne $record) {
        Write-Output "Record: $($record.Title) ($($record.Uid))"
    }
    else {
        Write-Output "Flow UID: $trimmedUid"
    }
    Write-Output ''
}

function Stop-KeeperPamWorkflow {
    <#
        .Synopsis
        End a PAM workflow (check in a record).

        .Description
        Ends an active or checked-out workflow. Use -Force to check in a record on behalf
        of another user when single-user checkout is enabled (requires approver/admin rights).

        .Parameter Uid
        Record UID, record title, or Flow UID. Alias: -u.

        .Parameter Force
        Force check-in another user's active session. Alias: -f.

        .Example
        Stop-KeeperPamWorkflow -Uid "<record-or-flow-uid>"
        Stop-KeeperPamWorkflow -Uid "<uid>" -Force
        pam-workflow-end "<uid>"
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $true)]
        [Alias('u')]
        [string] $Uid,

        [Parameter()]
        [Alias('f')]
        [switch] $Force
    )

    $vault = getPamVault
    $auth = getPamEnterpriseAuth
    $trimmedUid = $Uid.Trim()
    $record = resolvePamWorkflowRecord -Vault $vault -Identifier $trimmedUid -AllowMissing $true

    if ($Force.IsPresent) {
        $refMsg = $null
        $label = $null
        if ($null -ne $record) {
            $refMsg = [KeeperSecurity.Plugins.PAM.WorkflowUtils]::CreateRecordRef($record.Uid, $record.Title)
            $label = "Record: $($record.Title) ($($record.Uid))"
        }
        else {
            $uidBytes = decodePamWorkflowUidBytes -Uid $trimmedUid -ErrorMessage "`"$trimmedUid`" is not a known record or a valid flow UID"
            $refMsg = [KeeperSecurity.Plugins.PAM.WorkflowUtils]::WorkflowRef($uidBytes)
            $label = "Flow UID: $trimmedUid"
        }

        $null = invokePamSdkCall {
            [KeeperSecurity.Plugins.PAM.WorkflowUtils]::ForceCheckinAsync($auth, $refMsg).GetAwaiter().GetResult()
        }

        Write-Output ''
        Write-Output 'Record force checked in'
        Write-Output ''
        Write-Output $label
        Write-Output ''
        return
    }

    $flowRef = $null
    $label = ''
    $flowUidString = ''

    if ($null -ne $record) {
        $workflowState = invokePamSdkCall {
            [KeeperSecurity.Plugins.PAM.WorkflowUtils]::GetWorkflowStateByRecordAsync(
                $auth, $record.Uid, $record.Title).GetAwaiter().GetResult()
        }
        if ($null -eq $workflowState -or $null -eq $workflowState.FlowUid -or $workflowState.FlowUid.IsEmpty) {
            Write-Error -Message 'No active workflow found for this record. The workflow may have already ended or never started.' -ErrorAction Stop
        }

        $flowRef = [KeeperSecurity.Plugins.PAM.WorkflowUtils]::WorkflowRef($workflowState.FlowUid.ToByteArray())
        $label = "Record: $($record.Title) ($($record.Uid))"
        $flowUidString = getPamWorkflowFlowUidString $workflowState.FlowUid
    }
    else {
        $uidBytes = decodePamWorkflowUidBytes -Uid $trimmedUid -ErrorMessage "`"$trimmedUid`" is not a known record or a valid flow UID"
        $flowRef = [KeeperSecurity.Plugins.PAM.WorkflowUtils]::WorkflowRef($uidBytes)
        $label = "Flow UID: $trimmedUid"
    }

    $null = invokePamSdkCall {
        [KeeperSecurity.Plugins.PAM.WorkflowUtils]::EndWorkflowAsync($auth, $flowRef).GetAwaiter().GetResult()
    }

    Write-Output ''
    Write-Output 'Workflow ended (checked in)'
    Write-Output ''
    Write-Output $label
    if (-not [string]::IsNullOrEmpty($flowUidString)) {
        Write-Output "Flow UID: $flowUidString"
    }
    Write-Output ''
    Write-Output 'Credentials may have been rotated.'
    Write-Output ''
}

New-Alias -Name pam-workflow-pending -Value Get-KeeperPamWorkflowPending -ErrorAction SilentlyContinue
New-Alias -Name pam-workflow-approve -Value Approve-KeeperPamWorkflowAccess -ErrorAction SilentlyContinue
New-Alias -Name pam-workflow-deny -Value Deny-KeeperPamWorkflowAccess -ErrorAction SilentlyContinue
New-Alias -Name pam-workflow-request -Value Request-KeeperPamWorkflowAccess -ErrorAction SilentlyContinue
New-Alias -Name pam-workflow-start -Value Start-KeeperPamWorkflow -ErrorAction SilentlyContinue
New-Alias -Name pam-workflow-end -Value Stop-KeeperPamWorkflow -ErrorAction SilentlyContinue
