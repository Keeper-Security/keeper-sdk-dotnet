function script:Read-KeeperEpmPolicyJsonText {
    Param (
        [string] $Json,
        [string] $FilePath
    )
    if (-not [string]::IsNullOrEmpty($Json)) { return $Json }
    if (-not [string]::IsNullOrEmpty($FilePath)) {
        if (-not (Test-Path -LiteralPath $FilePath)) {
            throw "File not found: $FilePath"
        }
        return [System.IO.File]::ReadAllText($FilePath)
    }
    return $null
}

function script:Get-KeeperEpmPolicyListStatus {
    Param ($Policy)
    $status = 'off'
    if (-not $Policy.Disabled) {
        try {
            if ($null -ne $Policy.Data) {
                $d = $Policy.Data
                if ($null -ne $d.Status -and $d.Status -ne '') {
                    $status = [string]$d.Status
                }
                else {
                    $status = 'off'
                }
            }
            elseif ($Policy.PolicyData -and $Policy.PolicyData.Length -gt 0) {
                $jsonText = [System.Text.Encoding]::UTF8.GetString($Policy.PolicyData)
                $jo = $jsonText | ConvertFrom-Json -ErrorAction Stop
                if ($null -ne $jo -and $jo.PSObject.Properties['Status']) {
                    $status = [string]$jo.Status
                }
                else {
                    $status = 'on'
                }
            }
            else {
                $status = 'on'
            }
        }
        catch {
            $status = 'on'
        }
    }
    return $status
}

function script:Get-KeeperEpmPolicyDataInfo {
    Param (
        [Parameter(Mandatory = $true)] $Policy,
        [Parameter(Mandatory = $true)] $Plugin
    )
    $name = ''
    $type = ''
    $controls = [System.Collections.Generic.List[string]]::new()
    $users = ''
    $machines = ''
    $applications = ''
    $collections = ''

    $data = $Policy.Data
    if ($null -eq $data) {
        return [PSCustomObject]@{
            Name           = $name
            Type           = $type
            Controls       = $controls
            Users          = $users
            Machines       = $machines
            Applications   = $applications
            Collections    = $collections
        }
    }

    if ($null -ne $data.PolicyName) { $name = [string]$data.PolicyName }
    if ($null -ne $data.PolicyType) { $type = [string]$data.PolicyType }

    if ($null -ne $data.Actions -and $null -ne $data.Actions.OnSuccess -and $data.Actions.OnSuccess.Controls) {
        foreach ($control in $data.Actions.OnSuccess.Controls) {
            if ($null -eq $control) { continue }
            $controlStr = [string]$control
            if ([string]::IsNullOrEmpty($controlStr)) { continue }
            $upper = $controlStr.ToUpperInvariant()
            if ($upper -eq 'APPROVAL' -or $upper.Contains('APPROVAL')) { [void]$controls.Add('APPROVAL') }
            elseif ($upper -eq 'JUSTIFY' -or $upper.Contains('JUSTIFY')) { [void]$controls.Add('JUSTIFY') }
            elseif ($upper -eq 'MFA' -or $upper.Contains('MFA')) { [void]$controls.Add('MFA') }
            else { [void]$controls.Add($upper) }
        }
    }

    if ($data.UserCheck -and $data.UserCheck.Count -gt 0) {
        $users = $data.UserCheck -join ', '
    }
    if ($data.MachineCheck -and $data.MachineCheck.Count -gt 0) {
        $machines = $data.MachineCheck -join ', '
    }
    if ($data.ApplicationCheck -and $data.ApplicationCheck.Count -gt 0) {
        $applications = $data.ApplicationCheck -join ', '
    }

    try {
        $allAgentsUid = $Plugin.AllAgentsCollectionUid
        $policyLinks = @($Plugin.GetCollectionLinksForObject($Policy.PolicyUid))
        $collectionUids = [System.Collections.Generic.List[string]]::new()
        foreach ($link in $policyLinks) {
            $collUid = $link.Item1
            if (-not [string]::IsNullOrEmpty($collUid)) {
                if ($null -ne $allAgentsUid -and $collUid -eq $allAgentsUid) {
                    [void]$collectionUids.Add('*')
                }
                else {
                    [void]$collectionUids.Add($collUid)
                }
            }
        }
        $collectionUids.Sort()
        $collections = $collectionUids -join ', '
    }
    catch {
        Write-Debug "GetCollectionLinksForObject: $($_.Exception.Message)"
    }

    return [PSCustomObject]@{
        Name         = $name
        Type         = $type
        Controls     = $controls
        Users        = $users
        Machines     = $machines
        Applications = $applications
        Collections  = $collections
    }
}

function script:Resolve-KeeperEpmPolicy {
    Param (
        [Parameter(Mandatory = $true)]
        [string] $Identifier,
        [Parameter(Mandatory = $true)]
        $Plugin
    )
    $id = $Identifier.Trim()
    if ([string]::IsNullOrEmpty($id)) { return $null }

    $policy = $Plugin.Policies.GetEntity($id)
    if ($null -ne $policy) { return $policy }

    $nameMatchPolicies = @($Plugin.Policies.GetAll() | ForEach-Object {
            $info = Get-KeeperEpmPolicyDataInfo -Policy $_ -Plugin $Plugin
            if (-not [string]::IsNullOrEmpty($info.Name) -and $info.Name.Equals($id, [System.StringComparison]::OrdinalIgnoreCase)) {
                $_
            }
        })
    if ($nameMatchPolicies.Count -eq 1) { return $nameMatchPolicies[0] }
    if ($nameMatchPolicies.Count -gt 1) {
        Write-Warning "Multiple policies match name `"$id`". Please specify Policy UID."
    }
    return $null
}

function script:Write-EpmPolicyModifyStatus {
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

function script:GetPedmPolicyAgentsResponse {
    Param (
        [Parameter(Mandatory = $true)]
        [KeeperSecurity.Authentication.IAuthentication] $Auth,
        [Parameter(Mandatory = $true)]
        [string[]] $PolicyUids
    )
    $rq = New-Object PEDM.PolicyAgentRequest
    $rq.SummaryOnly = $false
    foreach ($uid in $PolicyUids) {
        $b = [KeeperSecurity.Utils.CryptoUtils]::Base64UrlDecode($uid)
        [void]$rq.PolicyUid.Add([Google.Protobuf.ByteString]::CopyFrom($b))
    }
    $methods = [KeeperSecurity.Authentication.AuthExtensions].GetMethods([System.Reflection.BindingFlags]'Public,Static') | Where-Object {
        $_.Name -eq 'ExecuteRouter' -and $_.IsGenericMethodDefinition -and $_.GetGenericArguments().Count -eq 1 -and $_.GetParameters().Count -eq 3
    }
    if ($methods.Count -lt 1) {
        throw 'ExecuteRouter(IAuthentication, string, IMessage) not found on AuthExtensions.'
    }
    $gm = $methods[0].MakeGenericMethod([PEDM.PolicyAgentResponse])
    $task = $gm.Invoke($null, @($Auth, 'pedm/get_policy_agents', $rq))
    return $task.GetAwaiter().GetResult()
}

function Get-KeeperEpmPolicyList {
    <#
    .Synopsis
        List EPM/PEDM policies.
    .Description
        Takes no parameters; returns a table of policies with status, controls, and scope fields.
    #>
    [CmdletBinding()]
    Param ()

    $plugin = ensureEpmPlugin
    if (-not $plugin) {
        Write-Error -Message 'EPM plugin is not available. Enterprise admin access is required.' -ErrorAction Stop
    }

    $policies = @($plugin.Policies.GetAll())
    if ($policies.Count -eq 0) {
        Write-Output 'No policies found.'
        return
    }

    $rows = foreach ($pol in ($policies | Sort-Object -Property PolicyUid)) {
        $policyInfo = Get-KeeperEpmPolicyDataInfo -Policy $pol -Plugin $plugin
        $status = Get-KeeperEpmPolicyListStatus -Policy $pol
        $controls = ($policyInfo.Controls | ForEach-Object { $_ }) -join "`n"
        $controls = $controls.Trim()
        [PSCustomObject]@{
            'Policy UID'     = $pol.PolicyUid
            'Policy Name'    = $policyInfo.Name
            'Policy Type'    = $policyInfo.Type
            'Status'         = $status
            'Controls'       = $controls
            'Users'          = $policyInfo.Users
            'Machines'       = $policyInfo.Machines
            'Applications'   = $policyInfo.Applications
            'Collections'    = $policyInfo.Collections
        }
    }
    $rows | Format-Table -AutoSize -Wrap
}

function Get-KeeperEpmPolicy {
    <#
    .Synopsis
        View an EPM policy by UID or name.
    .Parameter PolicyUidOrName
        Policy UID or policy display name (case-insensitive match on name).
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $PolicyUidOrName
    )

    $plugin = ensureEpmPlugin
    if (-not $plugin) {
        Write-Error -Message 'EPM plugin is not available. Enterprise admin access is required.' -ErrorAction Stop
    }

    $uid = $PolicyUidOrName.Trim()
    $policy = $plugin.Policies.GetEntity($uid)
    if ($null -eq $policy) {
        $nameMatchPolicies = @($plugin.Policies.GetAll() | ForEach-Object {
                $info = Get-KeeperEpmPolicyDataInfo -Policy $_ -Plugin $plugin
                if (-not [string]::IsNullOrEmpty($info.Name) -and $info.Name.Equals($uid, [System.StringComparison]::OrdinalIgnoreCase)) { $_ }
            })
        if ($nameMatchPolicies.Count -gt 1) {
            Write-Error -Message "Multiple policies match name `"$uid`". Please specify Policy UID." -ErrorAction Stop
        }
        if ($nameMatchPolicies.Count -eq 1) { $policy = $nameMatchPolicies[0] }
    }

    if ($null -eq $policy) {
        Write-Error -Message "Policy '$uid' not found." -ErrorAction Stop
    }

    $policyInfo = Get-KeeperEpmPolicyDataInfo -Policy $policy -Plugin $plugin
    Write-Output "Policy: $($policyInfo.Name)"
    Write-Output "  UID: $($policy.PolicyUid)"
    Write-Output "  Type: $($policyInfo.Type)"
    Write-Output "  Disabled: $($policy.Disabled)"

    $d = $policy.Data
    if ($null -ne $d) {
        Write-Output "  Status: $(if ($null -ne $d.Status -and $d.Status -ne '') { $d.Status } else { 'off' })"
        if (-not [string]::IsNullOrEmpty($d.PolicyId)) {
            Write-Output "  Policy ID: $($d.PolicyId)"
        }
        if (-not [string]::IsNullOrEmpty($d.NotificationMessage)) {
            Write-Output "  Notification Message: $($d.NotificationMessage)"
        }
        if ($d.NotificationRequiresAcknowledge) {
            Write-Output "  Notification Requires Acknowledge: $($d.NotificationRequiresAcknowledge)"
        }
        if ($d.RiskLevel -gt 0) {
            Write-Output "  Risk Level: $($d.RiskLevel)"
        }
        if (-not [string]::IsNullOrEmpty($d.Operator)) {
            Write-Output "  Operator: $($d.Operator)"
        }
        if ($d.Rules -and $d.Rules.Count -gt 0) {
            Write-Output "  Rules ($($d.Rules.Count)):"
            foreach ($rule in $d.Rules) {
                Write-Output "    - $($rule.RuleName): $($rule.Expression) ($($rule.RuleExpressionType))"
                if (-not [string]::IsNullOrEmpty($rule.ErrorMessage)) {
                    Write-Output "      Error: $($rule.ErrorMessage)"
                }
            }
        }
        if ($null -ne $d.Actions) {
            if ($d.Actions.OnSuccess -and $d.Actions.OnSuccess.Controls -and $d.Actions.OnSuccess.Controls.Count -gt 0) {
                Write-Output "  On Success Controls: $($d.Actions.OnSuccess.Controls -join ', ')"
            }
            if ($d.Actions.OnFailure -and -not [string]::IsNullOrEmpty($d.Actions.OnFailure.Command)) {
                Write-Output "  On Failure Command: $($d.Actions.OnFailure.Command)"
            }
        }
    }

    if ($policyInfo.Controls.Count -gt 0) {
        Write-Output "  Controls: $($policyInfo.Controls -join ', ')"
    }
    if (-not [string]::IsNullOrEmpty($policyInfo.Users)) {
        Write-Output "  Users: $($policyInfo.Users)"
    }
    if (-not [string]::IsNullOrEmpty($policyInfo.Machines)) {
        Write-Output "  Machines: $($policyInfo.Machines)"
    }
    if (-not [string]::IsNullOrEmpty($policyInfo.Applications)) {
        Write-Output "  Applications: $($policyInfo.Applications)"
    }
    if (-not [string]::IsNullOrEmpty($policyInfo.Collections)) {
        Write-Output "  Collections: $($policyInfo.Collections)"
    }

    if ($null -ne $d) {
        if ($d.DayCheck -and $d.DayCheck.Count -gt 0) {
            $dayNames = @('Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday')
            $days = foreach ($x in $d.DayCheck) { $dayNames[$x % 7] }
            Write-Output "  Allowed Days: $($days -join ', ')"
        }
        if ($d.DateCheck -and $d.DateCheck.Count -gt 0) {
            Write-Output "  Date Ranges ($($d.DateCheck.Count)):"
            foreach ($dateRange in $d.DateCheck) {
                $start = [DateTimeOffset]::FromUnixTimeMilliseconds($dateRange.StartDate).ToString('yyyy-MM-dd')
                $end = [DateTimeOffset]::FromUnixTimeMilliseconds($dateRange.EndDate).ToString('yyyy-MM-dd')
                Write-Output "    - $start to $end"
            }
        }
        if ($d.TimeCheck -and $d.TimeCheck.Count -gt 0) {
            Write-Output "  Time Ranges ($($d.TimeCheck.Count)):"
            foreach ($timeRange in $d.TimeCheck) {
                Write-Output "    - $($timeRange.StartTime) to $($timeRange.EndTime)"
            }
        }
        if ($d.CertificationCheck -and $d.CertificationCheck.Count -gt 0) {
            Write-Output "  Certification Checks: $($d.CertificationCheck -join ', ')"
        }
        if ($d.Extension -and $d.Extension.Count -gt 0) {
            Write-Output "  Extensions ($($d.Extension.Count) custom fields)"
        }
    }

    Write-Output "  Created: $([DateTimeOffset]::FromUnixTimeMilliseconds($policy.Created).ToString('yyyy-MM-dd HH:mm:ss'))"
    Write-Output "  Updated: $([DateTimeOffset]::FromUnixTimeMilliseconds($policy.Updated).ToString('yyyy-MM-dd HH:mm:ss'))"
}

function Add-KeeperEpmPolicy {
    <#
    .Synopsis
        Add an EPM policy.
    .Parameter NewPolicyUid
        Optional policy UID; omit to let the server assign one.
    .Parameter PlainDataJson
        Plain policy JSON (template/admin data).
    .Parameter PlainDataFile
        Path to a file containing plain policy JSON.
    .Parameter PolicyDataJson
        Policy JSON payload to encrypt.
    .Parameter PolicyDataFile
        Path to a file containing policy JSON to encrypt.
    #>
    [CmdletBinding()]
    Param (
        [Parameter()]
        [string] $NewPolicyUid,
        [Parameter()]
        [string] $PlainDataJson,
        [Parameter()]
        [string] $PlainDataFile,
        [Parameter()]
        [string] $PolicyDataJson,
        [Parameter()]
        [string] $PolicyDataFile
    )

    $plugin = ensureEpmPlugin
    if (-not $plugin) {
        Write-Error -Message 'EPM plugin is not available. Enterprise admin access is required.' -ErrorAction Stop
    }

    $plainJson = Read-KeeperEpmPolicyJsonText -Json $PlainDataJson -FilePath $PlainDataFile
    $policyJson = Read-KeeperEpmPolicyJsonText -Json $PolicyDataJson -FilePath $PolicyDataFile

    if ([string]::IsNullOrEmpty($plainJson) -or [string]::IsNullOrEmpty($policyJson)) {
        Write-Error -Message "Both -PlainDataJson/-PlainDataFile and -PolicyDataJson/-PolicyDataFile are required for 'add'." -ErrorAction Stop
    }

    $pi = New-Object KeeperSecurity.Plugins.EPM.EpmPlugin+PolicyInput
    if (-not [string]::IsNullOrEmpty($NewPolicyUid)) { $pi.PolicyUid = $NewPolicyUid.Trim() }
    $pi.PlainDataJson = $plainJson
    $pi.PolicyDataJson = $policyJson

    $addStatus = $plugin.ModifyPolicies(@($pi), $null, $null).GetAwaiter().GetResult()

    if ($addStatus.AddErrors -and $addStatus.AddErrors.Count -gt 0) {
        foreach ($err in $addStatus.AddErrors) {
            if (-not $err.Success) {
                Write-Error -Message "Failed to add policy `"$($err.EntityUid)`": $($err.Message)" -ErrorAction Continue
            }
        }
        return
    }

    Write-Output 'Policy added.'
    if (($addStatus.Add -and $addStatus.Add.Count -gt 0) -or ($addStatus.Update -and $addStatus.Update.Count -gt 0) -or ($addStatus.Remove -and $addStatus.Remove.Count -gt 0)) {
        Write-EpmPolicyModifyStatus -Status $addStatus
    }
    $plugin.SyncDown($false).GetAwaiter().GetResult() | Out-Null
}

function Update-KeeperEpmPolicy {
    <#
    .Synopsis
        Update an EPM policy.
    .Parameter PolicyUidOrName
        Policy UID or policy display name (case-insensitive match on name).
    .Parameter PlainDataJson
        Plain policy JSON.
    .Parameter PlainDataFile
        Path to a file containing plain policy JSON.
    .Parameter PolicyDataJson
        Policy JSON payload to encrypt.
    .Parameter PolicyDataFile
        Path to a file containing policy JSON to encrypt.
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $PolicyUidOrName,
        [Parameter()]
        [string] $PlainDataJson,
        [Parameter()]
        [string] $PlainDataFile,
        [Parameter()]
        [string] $PolicyDataJson,
        [Parameter()]
        [string] $PolicyDataFile
    )

    $plugin = ensureEpmPlugin
    if (-not $plugin) {
        Write-Error -Message 'EPM plugin is not available. Enterprise admin access is required.' -ErrorAction Stop
    }

    $policyUidValue = $PolicyUidOrName.Trim()
    if ([string]::IsNullOrEmpty($policyUidValue)) {
        Write-Error -Message "Policy UID or name is required for 'update'." -ErrorAction Stop
    }

    $policy = Resolve-KeeperEpmPolicy -Identifier $policyUidValue -Plugin $plugin
    if ($null -eq $policy) {
        Write-Error -Message "Policy `"$policyUidValue`" does not exist" -ErrorAction Stop
    }

    $plainJson = Read-KeeperEpmPolicyJsonText -Json $PlainDataJson -FilePath $PlainDataFile
    $policyJson = Read-KeeperEpmPolicyJsonText -Json $PolicyDataJson -FilePath $PolicyDataFile

    if ([string]::IsNullOrEmpty($plainJson) -and [string]::IsNullOrEmpty($policyJson)) {
        Write-Error -Message "At least one of -PlainDataJson/-PlainDataFile or -PolicyDataJson/-PolicyDataFile is required for 'update'." -ErrorAction Stop
    }

    $pi = New-Object KeeperSecurity.Plugins.EPM.EpmPlugin+PolicyInput
    $pi.PolicyUid = $policy.PolicyUid
    if (-not [string]::IsNullOrEmpty($plainJson)) { $pi.PlainDataJson = $plainJson }
    if (-not [string]::IsNullOrEmpty($policyJson)) { $pi.PolicyDataJson = $policyJson }

    $updateStatus = $plugin.ModifyPolicies($null, @($pi), $null).GetAwaiter().GetResult()

    if ($updateStatus.UpdateErrors -and $updateStatus.UpdateErrors.Count -gt 0) {
        foreach ($err in $updateStatus.UpdateErrors) {
            if (-not $err.Success) {
                Write-Error -Message "Failed to update policy `"$($err.EntityUid)`": $($err.Message)" -ErrorAction Continue
            }
        }
        return
    }

    Write-Output "Policy '$($policy.PolicyUid)' updated."
    if (($updateStatus.Add -and $updateStatus.Add.Count -gt 0) -or ($updateStatus.Update -and $updateStatus.Update.Count -gt 0) -or ($updateStatus.Remove -and $updateStatus.Remove.Count -gt 0)) {
        Write-EpmPolicyModifyStatus -Status $updateStatus
    }
    $plugin.SyncDown($false).GetAwaiter().GetResult() | Out-Null
}

function Remove-KeeperEpmPolicy {
    <#
    .Synopsis
        Remove an EPM policy by UID or name.
    .Parameter PolicyUidOrName
        Policy UID or policy display name (case-insensitive match on name).
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $PolicyUidOrName
    )

    $plugin = ensureEpmPlugin
    if (-not $plugin) {
        Write-Error -Message 'EPM plugin is not available. Enterprise admin access is required.' -ErrorAction Stop
    }

    $uid = $PolicyUidOrName.Trim()
    if ([string]::IsNullOrEmpty($uid)) {
        Write-Error -Message "Policy UID or name is required for 'remove'." -ErrorAction Stop
    }

    $policy = Resolve-KeeperEpmPolicy -Identifier $uid -Plugin $plugin
    if ($null -eq $policy) {
        Write-Error -Message "Policy `"$uid`" does not exist" -ErrorAction Stop
    }

    $removeStatus = $plugin.ModifyPolicies($null, $null, @($policy.PolicyUid)).GetAwaiter().GetResult()

    if ($removeStatus.RemoveErrors -and $removeStatus.RemoveErrors.Count -gt 0) {
        foreach ($err in $removeStatus.RemoveErrors) {
            if (-not $err.Success) {
                Write-Error -Message "Failed to remove policy `"$($err.EntityUid)`": $($err.Message)" -ErrorAction Continue
            }
        }
        return
    }

    Write-Output "Policy '$($policy.PolicyUid)' removed."
    if (($removeStatus.Add -and $removeStatus.Add.Count -gt 0) -or ($removeStatus.Update -and $removeStatus.Update.Count -gt 0) -or ($removeStatus.Remove -and $removeStatus.Remove.Count -gt 0)) {
        Write-EpmPolicyModifyStatus -Status $removeStatus
    }
    $plugin.SyncDown($false).GetAwaiter().GetResult() | Out-Null
}

function Get-KeeperEpmPolicyAgent {
    <#
    .Synopsis
        List agents for one or more policies by policy UID or name.
    .Parameter PolicyUidOrNames
        One or more policy UIDs or policy names, separated by spaces or commas.
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $PolicyUidOrNames
    )

    $ent = getEnterprise
    $plugin = ensureEpmPlugin
    if (-not $plugin) {
        Write-Error -Message 'EPM plugin is not available. Enterprise admin access is required.' -ErrorAction Stop
    }

    $auth = $ent.loader.Auth
    if ($null -eq $auth) {
        Write-Error -Message 'Authentication context is not available.' -ErrorAction Stop
    }

    $policyIdentifiers = $PolicyUidOrNames.Trim()
    if ([string]::IsNullOrEmpty($policyIdentifiers)) {
        Write-Error -Message "Policy UID or name is required for 'agents'." -ErrorAction Stop
    }

    $identifiers = $policyIdentifiers.Split(@(' ', ','), [System.StringSplitOptions]::RemoveEmptyEntries)
    $policyUids = [System.Collections.Generic.List[string]]::new()
    foreach ($identifier in $identifiers) {
        $p = Resolve-KeeperEpmPolicy -Identifier $identifier.Trim() -Plugin $plugin
        if ($null -eq $p) {
            Write-Warning "Policy '$identifier' not found."
            continue
        }
        [void]$policyUids.Add($p.PolicyUid)
    }

    if ($policyUids.Count -eq 0) { return }

    try {
        $rs = GetPedmPolicyAgentsResponse -Auth $auth -PolicyUids ($policyUids.ToArray())
        if ($null -eq $rs) { return }

        $activeAgentUids = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
        foreach ($agentUidBytes in $rs.AgentUid) {
            $b = $agentUidBytes.ToByteArray()
            [void]$activeAgentUids.Add([KeeperSecurity.Utils.CryptoUtils]::Base64UrlEncode($b))
        }

        $rows = [System.Collections.Generic.List[object]]::new()
        foreach ($policyUid in $policyUids) {
            $policy = $plugin.Policies.GetEntity($policyUid)
            if ($null -ne $policy) {
                $policyInfo = Get-KeeperEpmPolicyDataInfo -Policy $policy -Plugin $plugin
                $status = if ($policy.Disabled) { 'off' } else { if ($null -ne $policy.Data -and $null -ne $policy.Data.Status -and $policy.Data.Status -ne '') { $policy.Data.Status } else { 'on' } }
                [void]$rows.Add([PSCustomObject]@{
                        Key    = 'Policy'
                        UID    = $policyUid
                        Name   = $policyInfo.Name
                        Status = $status
                    })
            }
        }
        foreach ($agentUid in $activeAgentUids) {
            $agent = $plugin.Agents.GetEntity($agentUid)
            $machineName = ''
            $st = ''
            if ($null -ne $agent) {
                $machineName = if ($agent.MachineId) { $agent.MachineId } else { '' }
                $st = if ($agent.Disabled) { 'off' } else { 'on' }
            }
            [void]$rows.Add([PSCustomObject]@{
                    Key    = 'Agent'
                    UID    = $agentUid
                    Name   = $machineName
                    Status = $st
                })
        }
        $rows | Format-Table -Property Key, UID, Name, Status -AutoSize
    }
    catch {
        Write-Error -Message "Error getting policy agents: $($_.Exception.Message)" -ErrorAction Stop
    }
}

function Add-KeeperEpmPolicyCollection {
    <#
    .Synopsis
        Assign one or more collections to one or more policies.
    .Parameter PolicyUidOrNames
        One or more policy UIDs or policy names, separated by spaces or commas.
    .Parameter CollectionUid
        One or more collection UIDs. Use '*' or 'all' for the all-agents collection.
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $PolicyUidOrNames,
        [Parameter(Mandatory = $true)]
        [string[]] $CollectionUid
    )

    $plugin = ensureEpmPlugin
    if (-not $plugin) {
        Write-Error -Message 'EPM plugin is not available. Enterprise admin access is required.' -ErrorAction Stop
    }

    $policyIdentifiers = $PolicyUidOrNames.Trim()
    if ([string]::IsNullOrEmpty($policyIdentifiers)) {
        Write-Error -Message "Policy UID or name is required for 'assign'." -ErrorAction Stop
    }

    $identifiers = $policyIdentifiers.Split(@(' ', ','), [System.StringSplitOptions]::RemoveEmptyEntries)
    $policies = [System.Collections.Generic.List[object]]::new()
    foreach ($identifier in $identifiers) {
        $p = Resolve-KeeperEpmPolicy -Identifier $identifier.Trim() -Plugin $plugin
        if ($null -eq $p) {
            Write-Warning "Policy '$identifier' not found."
            continue
        }
        [void]$policies.Add($p)
    }

    if ($policies.Count -eq 0) { return }

    $collectionUids = [System.Collections.Generic.List[byte[]]]::new()
    foreach ($collUid in $CollectionUid) {
        $c = $collUid.Trim()
        if ($c -eq '*' -or $c -eq 'all') {
            $allAgentsUid = $plugin.AllAgentsCollectionUid
            if (-not [string]::IsNullOrEmpty($allAgentsUid)) {
                try {
                    [void]$collectionUids.Add([KeeperSecurity.Utils.CryptoUtils]::Base64UrlDecode($allAgentsUid))
                }
                catch {
                    Write-Warning 'Invalid all-agents collection UID. Skipped.'
                }
            }
        }
        else {
            try {
                $collUidBytes = [KeeperSecurity.Utils.CryptoUtils]::Base64UrlDecode($c)
                if ($collUidBytes.Length -eq 16) {
                    [void]$collectionUids.Add($collUidBytes)
                }
                else {
                    Write-Warning "Invalid collection UID: $c. Skipped."
                }
            }
            catch {
                Write-Warning "Invalid collection UID: $c. Skipped."
            }
        }
    }

    if ($collectionUids.Count -eq 0) {
        Write-Error -Message 'No collections to assign.' -ErrorAction Stop
    }

    $setLinks = [System.Collections.Generic.List[KeeperSecurity.Plugins.EPM.CollectionLink]]::new()
    foreach ($policy in $policies) {
        foreach ($collUidBytes in $collectionUids) {
            $link = New-Object KeeperSecurity.Plugins.EPM.CollectionLink
            $link.CollectionUid = [KeeperSecurity.Utils.CryptoUtils]::Base64UrlEncode($collUidBytes)
            $link.LinkUid = $policy.PolicyUid
            $link.LinkType = [PEDM.CollectionLinkType]::CltPolicy
            [void]$setLinks.Add($link)
        }
    }

    $status = $plugin.SetCollectionLinks($setLinks, $null).GetAwaiter().GetResult()

    if ($status.AddErrors -and $status.AddErrors.Count -gt 0) {
        foreach ($err in $status.AddErrors) {
            if (-not $err.Success) {
                Write-Warning "Failed to add to policy: $($err.Message)"
            }
        }
    }
    if ($status.RemoveErrors -and $status.RemoveErrors.Count -gt 0) {
        foreach ($err in $status.RemoveErrors) {
            if (-not $err.Success) {
                Write-Warning "Failed to remove from policy: $($err.Message)"
            }
        }
    }

    if (($status.Add -and $status.Add.Count -gt 0) -or ($status.Update -and $status.Update.Count -gt 0) -or ($status.Remove -and $status.Remove.Count -gt 0)) {
        Write-EpmPolicyModifyStatus -Status $status
    }

    $plugin.SyncDown($false).GetAwaiter().GetResult() | Out-Null
}

New-Alias -Name kepm-policy-list     -Value Get-KeeperEpmPolicyList        -ErrorAction SilentlyContinue
New-Alias -Name kepm-policy-view     -Value Get-KeeperEpmPolicy            -ErrorAction SilentlyContinue
New-Alias -Name kepm-policy-add      -Value Add-KeeperEpmPolicy           -ErrorAction SilentlyContinue
New-Alias -Name kepm-policy-edit     -Value Update-KeeperEpmPolicy        -ErrorAction SilentlyContinue
New-Alias -Name kepm-policy-delete   -Value Remove-KeeperEpmPolicy       -ErrorAction SilentlyContinue
New-Alias -Name kepm-policy-remove   -Value Remove-KeeperEpmPolicy       -ErrorAction SilentlyContinue
New-Alias -Name kepm-policy-agents   -Value Get-KeeperEpmPolicyAgent      -ErrorAction SilentlyContinue
New-Alias -Name kepm-policy-assign   -Value Add-KeeperEpmPolicyCollection -ErrorAction SilentlyContinue
