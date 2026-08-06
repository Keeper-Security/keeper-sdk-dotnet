#requires -Version 5.1

function script:writePamActionResult {
    Param (
        [KeeperSecurity.Plugins.PAM.PamGatewayActionResult] $Result,
        [bool] $PrintJobDetails = $false
    )

    if ($null -eq $Result) {
        return
    }

    if (-not $Result.IsOk) {
        if ([string]::IsNullOrEmpty($Result.RawPayloadJson)) {
            Write-Output 'Action failed.'
        }
        else {
            Write-Output $Result.RawPayloadJson
        }
        return
    }

    if ($Result.IsScheduled) {
        $conversationId = if ($null -eq $Result.ConversationId) { '' } else { $Result.ConversationId }
        $gwinfo = if ([string]::IsNullOrEmpty($Result.GatewayUid)) { '' } else { " -Gateway $($Result.GatewayUid)" }
        Write-Output "Scheduled action id: $conversationId"
        Write-Output "The action has been scheduled, use command 'Get-KeeperPamActionJobInfo -JobId `"$conversationId`"$gwinfo' to get status of the scheduled action"
        return
    }

    if ($PrintJobDetails) {
        writePamActionJobInfoDetails -Result $Result
        return
    }

    if (-not [string]::IsNullOrEmpty($Result.RawPayloadJson)) {
        Write-Output $Result.RawPayloadJson
    }
}

function script:writePamActionJobInfoDetails {
    Param (
        [KeeperSecurity.Plugins.PAM.PamGatewayActionResult] $Result
    )

    $job = $Result.JobInfo
    if ($null -eq $job `
            -or ([string]::IsNullOrEmpty($job.Status) `
                -and [string]::IsNullOrEmpty($job.Duration) `
                -and [string]::IsNullOrEmpty($job.ResponseMessage) `
                -and [string]::IsNullOrEmpty($job.ExecutionException))) {
        if ([string]::IsNullOrEmpty($Result.RawPayloadJson)) {
            Write-Output 'No job details returned.'
        }
        else {
            Write-Output $Result.RawPayloadJson
        }
        return
    }

    Write-Output 'Execution Details'
    Write-Output '-------------------------'
    if (-not [string]::IsNullOrEmpty($job.Status)) {
        Write-Output ("`tStatus              : {0}" -f $job.Status)
    }
    if (-not [string]::IsNullOrEmpty($job.Duration)) {
        Write-Output ("`tDuration            : {0}" -f $job.Duration)
    }
    if (-not [string]::IsNullOrEmpty($job.ResponseMessage)) {
        Write-Output ("`tResponse Message    : {0}" -f $job.ResponseMessage)
    }
    if (-not [string]::IsNullOrEmpty($job.ExecutionException)) {
        Write-Output ("`tExecution Exception : {0}" -f $job.ExecutionException)
    }
}

function Invoke-KeeperPamActionRotate {
    <#
        .Synopsis
        Rotate PAM credentials via the gateway.

        .Description
        Schedules or runs password rotation for a PAM user record, or for pamUser records
        in a shared folder. Use Get-KeeperPamActionJobInfo to check scheduled job status.

        .Parameter RecordUid
        Record UID to rotate. Alias: -r.

        .Parameter Folder
        Shared folder UID or title regex pattern to rotate pamUser records. Alias: -f.

        .Parameter DryRun
        Dry-run mode for folder rotation (selects records without rotating). Alias: -n.

        .Example
        Invoke-KeeperPamActionRotate -RecordUid "<uid>"
        Invoke-KeeperPamActionRotate -r "<uid>"
        Invoke-KeeperPamActionRotate -Folder "<folder-uid>" -DryRun
        pam-action-rotate -r "<uid>"
    #>
    [CmdletBinding(DefaultParameterSetName = 'Record')]
    Param (
        [Parameter(ParameterSetName = 'Record')]
        [Alias('r', 'record-uid')]
        [string] $RecordUid,

        [Parameter(ParameterSetName = 'Folder')]
        [Alias('f')]
        [string] $Folder,

        [Parameter(ParameterSetName = 'Folder')]
        [Alias('n', 'dry-run')]
        [switch] $DryRun
    )

    if ([string]::IsNullOrWhiteSpace($RecordUid) -and [string]::IsNullOrWhiteSpace($Folder)) {
        Write-Output '-RecordUid or -Folder is required. Usage: Invoke-KeeperPamActionRotate -RecordUid <uid> | -Folder <folder>'
        return
    }

    $vault = getPamRotationVault

    $options = New-Object KeeperSecurity.Plugins.PAM.PamRotateOptions
    $options.RecordUid = $RecordUid
    $options.Folder = $Folder
    $options.DryRun = $DryRun.IsPresent

    try {
        $result = [KeeperSecurity.Plugins.PAM.ActionUtils]::RotateAsync($vault, $options).GetAwaiter().GetResult()
    }
    catch [KeeperSecurity.Plugins.PAM.PamException] {
        Write-Output $_.Exception.Message
        return
    }

    if ($result.IsFolderMode) {
        $folder = $result.FolderResult
        Write-Output ("Selected for rotation - folders: {0}, records: {1}" -f $folder.FolderCount, $folder.RecordCount)
        if ($folder.DryRun) {
            return
        }

        foreach ($item in $folder.Results) {
            writePamActionResult -Result $item
        }
        foreach ($error in $folder.Errors) {
            Write-Output ("Record UID: {0} skipped: {1}" -f $error.RecordUid, $error.Message)
        }
        return
    }

    writePamActionResult -Result $result.RecordResult
}

function Get-KeeperPamActionJobInfo {
    <#
        .Synopsis
        Get status of a scheduled PAM gateway action job.

        .Description
        Queries the gateway for execution details of a previously scheduled PAM action
        (for example after Invoke-KeeperPamActionRotate).

        .Parameter JobId
        Scheduled action / conversation id. Quote values that contain '/'. Alias: -j.

        .Parameter Gateway
        Gateway UID when multiple gateways are present. Alias: -g.

        .Example
        Get-KeeperPamActionJobInfo -JobId "<conversation-id>"
        Get-KeeperPamActionJobInfo -j "<conversation-id>" -Gateway "<gateway-uid>"
        pam-action-job-info -j "<conversation-id>"
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0)]
        [Alias('j', 'job-id')]
        [string] $JobId,

        [Parameter()]
        [Alias('g')]
        [string] $Gateway
    )

    if ([string]::IsNullOrWhiteSpace($JobId)) {
        Write-Output 'job_id is required. Usage: Get-KeeperPamActionJobInfo -JobId "<job_id>" [-Gateway UID]'
        Write-Output "Tip: quote job ids that contain '/'."
        return
    }

    $vault = getPamRotationVault
    $auth = $vault.Auth
    if ($null -eq $auth) {
        Write-Error -Message 'Vault is not available.' -ErrorAction Stop
    }

    Write-Output ("Job id to check [{0}]" -f $JobId.Trim())
    try {
        $result = [KeeperSecurity.Plugins.PAM.ActionUtils]::GetJobInfoAsync(
            $auth, $JobId.Trim(), $Gateway).GetAwaiter().GetResult()
        writePamActionResult -Result $result -PrintJobDetails $true
    }
    catch [KeeperSecurity.Plugins.PAM.PamException] {
        Write-Output $_.Exception.Message
    }
}

New-Alias -Name pam-action-rotate -Value Invoke-KeeperPamActionRotate -ErrorAction SilentlyContinue
New-Alias -Name pam-action-job-info -Value Get-KeeperPamActionJobInfo -ErrorAction SilentlyContinue
