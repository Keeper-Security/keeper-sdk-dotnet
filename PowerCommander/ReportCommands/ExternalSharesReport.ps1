#requires -Version 5.1

function Get-KeeperExternalSharesData {
    param(
        [Parameter(Mandatory = $true)]$Snapshot,
        [Parameter()][ValidateSet('direct', 'shared-folder', 'all')][string]$ShareType = 'all'
    )

    $externalUsers = @{}
    foreach ($userEntry in $Snapshot.Users.Values) {
        $userUid = [long]$userEntry.UserUid
        $userEmail = [string]$userEntry.Email
        if (($userUid -shr 32) -eq 0 -and
            -not [string]::IsNullOrWhiteSpace($userEmail)) {
            $externalUsers[$userUid] = $userEntry
        }
    }

    $shareEntries = [System.Collections.Generic.List[PSCustomObject]]::new()
    if ($ShareType -in @('direct', 'all')) {
        foreach ($recordEntry in $Snapshot.Records.Values) {
            if (-not $recordEntry.Shared) {
                continue
            }

            foreach ($userUid in ($recordEntry.UserPermissions.Keys | Sort-Object)) {
                $targetUid = [long]$userUid
                if (-not $externalUsers.ContainsKey($targetUid)) {
                    continue
                }

                $permissionBits = 0
                if ($recordEntry.UserPermissions.ContainsKey($targetUid)) {
                    $permissionBits = [int]$recordEntry.UserPermissions[$targetUid]
                }

                $shareEntries.Add([PSCustomObject][ordered]@{
                    kind         = 'direct'
                    uid          = [string]$recordEntry.Uid
                    name         = [string]$recordEntry.Title
                    type         = 'Direct'
                    shared_to    = [string]$externalUsers[$targetUid].Email
                    permissions  = Get-KeeperCompliancePermissionText -PermissionBits $permissionBits
                    target_email = [string]$externalUsers[$targetUid].Email
                }) | Out-Null
            }
        }
    }

    if ($ShareType -in @('shared-folder', 'all')) {
        foreach ($folderEntry in $Snapshot.SharedFolders.Values) {
            foreach ($userUid in ($folderEntry.Users | Sort-Object)) {
                $targetUid = [long]$userUid
                if (-not $externalUsers.ContainsKey($targetUid)) {
                    continue
                }

                $shareEntries.Add([PSCustomObject][ordered]@{
                    kind         = 'shared-folder'
                    uid          = [string]$folderEntry.Uid
                    name         = ''
                    type         = 'Shared Folder'
                    shared_to    = [string]$externalUsers[$targetUid].Email
                    permissions  = ''
                    target_email = [string]$externalUsers[$targetUid].Email
                }) | Out-Null
            }
        }
    }

    return [PSCustomObject]@{
        ExternalUsers = $externalUsers
        ShareEntries  = @($shareEntries | Sort-Object type, uid, shared_to)
    }
}

function Get-KeeperExternalShareRows {
    param(
        [Parameter(Mandatory = $true)]$ExternalShareData
    )

    return @(
        $ExternalShareData.ShareEntries | ForEach-Object {
            [PSCustomObject][ordered]@{
                uid         = [string]$_.uid
                name        = [string]$_.name
                type        = [string]$_.type
                shared_to   = [string]$_.shared_to
                permissions = [string]$_.permissions
            }
        }
    )
}

function Remove-KeeperExternalShareEntries {
    param(
        [Parameter(Mandatory = $true)]$ExternalShareData,
        [Parameter()][ValidateSet('direct', 'shared-folder', 'all')][string]$ShareType = 'all'
    )

    $result = [PSCustomObject]@{
        Removed = 0
        Failed  = 0
        Errors  = [System.Collections.Generic.List[string]]::new()
    }

    foreach ($shareEntry in $ExternalShareData.ShareEntries) {
        if ($ShareType -ne 'all' -and $shareEntry.kind -ne $ShareType) {
            continue
        }

        $targetEmail = [string]$shareEntry.target_email
        if (-not $targetEmail) {
            continue
        }

        try {
            if ($shareEntry.kind -eq 'direct') {
                Revoke-KeeperRecordAccess -Record ([string]$shareEntry.uid) -User $targetEmail -ErrorAction Stop | Out-Null
            }
            else {
                Revoke-KeeperSharedFolderAccess -SharedFolder ([string]$shareEntry.uid) -User $targetEmail -ErrorAction Stop | Out-Null
            }
            $result.Removed++
        }
        catch {
            $result.Failed++
            $result.Errors.Add("$($shareEntry.kind):$($shareEntry.uid)->${targetEmail}: $($_.Exception.Message)") | Out-Null
        }
    }

    return $result
}

function Confirm-KeeperExternalShareRemoval {
    param(
        [Parameter(Mandatory = $true)]$PreviewRows,
        [Parameter(Mandatory = $true)]$ExternalShareData,
        [Parameter()][ValidateSet('direct', 'shared-folder', 'all')][string]$ShareType = 'all'
    )

    if ($PreviewRows.Count -gt 0) {
        Write-Host ""
        Write-Host "ALERT!"
        Write-Host "You are about to delete the following shares:"
        Write-Host ""
        $PreviewRows | Format-Table -Property uid, name, type, shared_to, permissions -Wrap
    }
    else {
        Write-Host "No external shares found."
        return
    }

    $answer = Read-Host "Do you wish to proceed? (y/n)"
    if ($answer -in @('y', 'Y', 'yes', 'YES', 'Yes')) {
        $removalResult = Remove-KeeperExternalShareEntries -ExternalShareData $ExternalShareData -ShareType $ShareType
        Write-Host "Removed $($removalResult.Removed) external share(s)."
        if ($removalResult.Failed -gt 0) {
            $errorPreview = @($removalResult.Errors | Select-Object -First 5) -join '; '
            Write-Warning "Failed to remove $($removalResult.Failed) external share(s). $errorPreview"
        }
    }
    else {
        Write-Host "Action aborted."
    }
}

function Get-KeeperExternalSharesReport {
    <#
        .Synopsis
        Run external shares report

        .Parameter Format
        table (default), json, or csv

        .Parameter Output
        File path for json/csv output

        .Parameter Action
        remove or none

        .Parameter ShareType
        direct, shared-folder, or all

        .Parameter Force
        Skip remove confirmation

        .Parameter RefreshData
        Rebuild compliance snapshot first
    #>
    [CmdletBinding()]
    param(
        [Parameter()][ValidateSet('table', 'json', 'csv')][string]$Format = 'table',
        [Parameter()][string]$Output,
        [Parameter()][ValidateSet('remove', 'none')][string]$Action = 'none',
        [Parameter()][ValidateSet('direct', 'shared-folder', 'all')][string]$ShareType = 'all',
        [Parameter()][switch]$Force,
        [Parameter()][switch]$RefreshData
    )

    Write-KeeperComplianceStatus "Starting external-shares-report. Format=$Format RefreshData=$RefreshData ShareType=$ShareType Action=$Action."
    $snapshot = Get-KeeperComplianceSnapshot -Rebuild:$RefreshData -NoRebuild:([bool](-not $RefreshData)) -SharedOnly
    $externalShareData = Get-KeeperExternalSharesData -Snapshot $snapshot -ShareType $ShareType

    if ($Action -eq 'remove') {
        $previewRows = Get-KeeperExternalShareRows -ExternalShareData $externalShareData
        if ($Force) {
            $removalResult = Remove-KeeperExternalShareEntries -ExternalShareData $externalShareData -ShareType $ShareType
            Write-Host "Removed $($removalResult.Removed) external share(s)."
            if ($removalResult.Failed -gt 0) {
                $errorPreview = @($removalResult.Errors | Select-Object -First 5) -join '; '
                Write-Warning "Failed to remove $($removalResult.Failed) external share(s). $errorPreview"
            }
        }
        else {
            Confirm-KeeperExternalShareRemoval -PreviewRows $previewRows -ExternalShareData $externalShareData -ShareType $ShareType
        }
        return
    }

    $reportRows = Get-KeeperExternalShareRows -ExternalShareData $externalShareData
    if ($reportRows.Count -eq 0) {
        Write-Host "No external shares found."
        return
    }

    Write-KeeperReportOutput -Rows $reportRows -DisplayRows $reportRows -Format $Format -Output $Output -JsonDepth 4 `
        -TableColumns @('uid', 'name', 'type', 'shared_to', 'permissions')
}
New-Alias -Name external-shares-report -Value Get-KeeperExternalSharesReport
