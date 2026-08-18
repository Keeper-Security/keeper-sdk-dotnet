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
        Write-Output $(if ([string]::IsNullOrEmpty($Result.RawPayloadJson)) { 'Action failed.' } else { $Result.RawPayloadJson })
        return
    }

    if ($Result.IsScheduled) {
        $conversationId = if ($null -eq $Result.ConversationId) { '' } else { $Result.ConversationId }
        $gwinfo = if ([string]::IsNullOrEmpty($Result.GatewayUid)) { '' } else { " -Gateway $($Result.GatewayUid)" }
        Write-Output "Scheduled action id: $conversationId"
        Write-Output "The action has been scheduled, use command 'pam-action-job-info -JobId `"$conversationId`"$gwinfo' to get status of the scheduled action"
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
    $hasDetails = $null -ne $job -and (
        -not [string]::IsNullOrEmpty($job.Status) `
            -or -not [string]::IsNullOrEmpty($job.Duration) `
            -or -not [string]::IsNullOrEmpty($job.ResponseMessage) `
            -or -not [string]::IsNullOrEmpty($job.ExecutionException))

    if (-not $hasDetails) {
        Write-Output $(if ([string]::IsNullOrEmpty($Result.RawPayloadJson)) { 'No job details returned.' } else { $Result.RawPayloadJson })
        return
    }

    Write-Output 'Execution Details'
    $details = [ordered]@{}
    if (-not [string]::IsNullOrEmpty($job.Status)) {
        $details['Status'] = $job.Status
    }
    if (-not [string]::IsNullOrEmpty($job.Duration)) {
        $details['Duration'] = $job.Duration
    }
    if (-not [string]::IsNullOrEmpty($job.ResponseMessage)) {
        $details['Response Message'] = $job.ResponseMessage
    }
    if (-not [string]::IsNullOrEmpty($job.ExecutionException)) {
        $details['Execution Exception'] = $job.ExecutionException
    }
    Write-Output (([PSCustomObject]$details | Format-List | Out-String).TrimEnd())
}

function Invoke-KeeperPamActionRotate {
    <#
        .Synopsis
        Rotate PAM credentials via the gateway.

        .Description
        Schedules or runs password rotation for a PAM user record, or for pamUser records
        in a shared folder. Use Get-KeeperPamActionJobInfo to check scheduled job status.

        .Parameter RecordUid
        Record UID or title to rotate. Alias: -r.

        .Parameter Folder
        Shared folder UID or title regex pattern to rotate pamUser records. Alias: -f.

        .Parameter DryRun
        Dry-run mode for folder rotation (selects records without rotating). Alias: -n.

        .Example
        Invoke-KeeperPamActionRotate -RecordUid "<uid>"
        Invoke-KeeperPamActionRotate -Folder "<folder-uid>" -DryRun
        pam-action-rotate -r "<uid>"
    #>
    [CmdletBinding(DefaultParameterSetName = 'Record')]
    Param (
        [Parameter(ParameterSetName = 'Record')]
        [Alias('r')]
        [string] $RecordUid,

        [Parameter(ParameterSetName = 'Folder')]
        [Alias('f')]
        [string] $Folder,

        [Parameter(ParameterSetName = 'Folder')]
        [Alias('n')]
        [switch] $DryRun
    )

    if ([string]::IsNullOrWhiteSpace($RecordUid) -and [string]::IsNullOrWhiteSpace($Folder)) {
        Write-Error -Message '-RecordUid or -Folder is required. Usage: Invoke-KeeperPamActionRotate -RecordUid <uid> | -Folder <folder>' -ErrorAction Stop
    }

    $vault = getVault

    if (-not [string]::IsNullOrWhiteSpace($RecordUid)) {
        $resolved = $null
        try {
            $resolved = [KeeperSecurity.Plugins.PAM.PamVaultHelpers]::ResolveRecord(
                $vault, $RecordUid.Trim(), $null)
        }
        catch [System.InvalidOperationException] {
            Write-Output $_.Exception.Message
            return
        }
        if ($null -ne $resolved) {
            $RecordUid = $resolved.Uid
        }
    }

    $options = New-Object KeeperSecurity.Plugins.PAM.PamRotateOptions
    $options.RecordUid = $RecordUid
    $options.Folder = $Folder
    $options.DryRun = $DryRun.IsPresent

    $result = invokePamSdkCall {
        [KeeperSecurity.Plugins.PAM.ActionUtils]::RotateAsync($vault, $options).GetAwaiter().GetResult()
    }
    if ($null -eq $result) {
        return
    }

    if ($result.IsFolderMode) {
        $folderResult = $result.FolderResult
        Write-Output ("Selected for rotation - folders: {0}, records: {1}" -f $folderResult.FolderCount, $folderResult.RecordCount)
        if ($folderResult.DryRun) {
            return
        }

        foreach ($item in $folderResult.Results) {
            writePamActionResult -Result $item
        }
        foreach ($errorItem in $folderResult.Errors) {
            Write-Output ("Record UID: {0} skipped: {1}" -f $errorItem.RecordUid, $errorItem.Message)
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
        pam-action-job-info -j "<conversation-id>" -Gateway "<gateway-uid>"
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0)]
        [Alias('j')]
        [string] $JobId,

        [Parameter()]
        [Alias('g')]
        [string] $Gateway
    )

    if ([string]::IsNullOrWhiteSpace($JobId)) {
        Write-Error -Message "JobId is required. Usage: Get-KeeperPamActionJobInfo -JobId `"<job_id>`" [-Gateway UID]`nTip: quote job ids that contain '/'." -ErrorAction Stop
    }

    $vault = getVault
    if ($null -eq $vault.Auth) {
        Write-Error -Message 'Vault is not available.' -ErrorAction Stop
    }

    $trimmedJobId = $JobId.Trim()
    Write-Output ("Job id to check [{0}]" -f $trimmedJobId)
    $result = invokePamSdkCall {
        [KeeperSecurity.Plugins.PAM.ActionUtils]::GetJobInfoAsync(
            $vault.Auth, $trimmedJobId, $Gateway).GetAwaiter().GetResult()
    }
    if ($null -eq $result) {
        return
    }
    writePamActionResult -Result $result -PrintJobDetails $true
}

New-Alias -Name pam-action-rotate -Value Invoke-KeeperPamActionRotate -ErrorAction SilentlyContinue
New-Alias -Name pam-action-job-info -Value Get-KeeperPamActionJobInfo -ErrorAction SilentlyContinue
