function script:Get-KeeperEpmPolicyListStatus {
    Param ($Policy)
    if ($Policy.Disabled) {
        return [KeeperSecurity.Plugins.EPM.EpmPolicyStatus]::Off
    }
    try {
        if ($null -ne $Policy.Data) {
            $d = $Policy.Data
            if ($null -ne $d.Status -and $d.Status -ne '') {
                return [string]$d.Status
            }
        }
        elseif ($Policy.PolicyData -and $Policy.PolicyData.Length -gt 0) {
            $jsonText = [System.Text.Encoding]::UTF8.GetString($Policy.PolicyData)
            $jo = $jsonText | ConvertFrom-Json -ErrorAction Stop
            if ($null -ne $jo -and $jo.PSObject.Properties['Status']) {
                return [string]$jo.Status
            }
        }
    }
    catch {
        Write-Debug "Get-KeeperEpmPolicyListStatus: $($_.Exception.Message)"
    }
    return [KeeperSecurity.Plugins.EPM.EpmPolicyStatus]::Enforce
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
            if ($upper -eq [KeeperSecurity.Plugins.EPM.EpmPolicyControl]::Approval) { [void]$controls.Add([KeeperSecurity.Plugins.EPM.EpmPolicyControl]::Approval) }
            elseif ($upper -eq [KeeperSecurity.Plugins.EPM.EpmPolicyControl]::Justify) { [void]$controls.Add([KeeperSecurity.Plugins.EPM.EpmPolicyControl]::Justify) }
            elseif ($upper -eq [KeeperSecurity.Plugins.EPM.EpmPolicyControl]::Mfa) { [void]$controls.Add([KeeperSecurity.Plugins.EPM.EpmPolicyControl]::Mfa) }
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
    if ([string]::IsNullOrEmpty($id)) { return @() }

    $policy = $Plugin.Policies.GetEntity($id)
    if ($null -ne $policy) { return @($policy) }

    return @($Plugin.Policies.GetAll() | ForEach-Object {
            $info = Get-KeeperEpmPolicyDataInfo -Policy $_ -Plugin $Plugin
            if (-not [string]::IsNullOrEmpty($info.Name) -and $info.Name.Equals($id, [System.StringComparison]::OrdinalIgnoreCase)) {
                $_
            }
        })
}

function script:Resolve-KeeperEpmSinglePolicy {
    Param (
        [Parameter(Mandatory = $true)][string] $Identifier,
        [Parameter(Mandatory = $true)][object] $Plugin
    )
    $policies = @(Resolve-KeeperEpmPolicy -Identifier $Identifier -Plugin $Plugin)
    if ($policies.Count -eq 0) {
        Write-Error -Message "Policy '$Identifier' not found." -ErrorAction Stop
    }
    if ($policies.Count -gt 1) {
        Write-Warning "Multiple policies match name `"$Identifier`":"
        foreach ($p in $policies) {
            $info = Get-KeeperEpmPolicyDataInfo -Policy $p -Plugin $Plugin
            Write-Warning "  UID: $($p.PolicyUid)  Name: $($info.Name)"
        }
        Write-Error -Message "Policy name `"$Identifier`" is not unique. Use Policy UID." -ErrorAction Stop
    }
    return $policies[0]
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
    try {
        $task = $gm.Invoke($null, @($Auth, 'pedm/get_policy_agents', [Google.Protobuf.IMessage]$rq))
        return $task.GetAwaiter().GetResult()
    }
    catch [System.Reflection.TargetInvocationException] {
        throw $_.Exception.InnerException
    }
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
        $controls = ($policyInfo.Controls -join "`n").Trim()
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

    $policy = Resolve-KeeperEpmSinglePolicy -Identifier $PolicyUidOrName -Plugin $plugin

    $policyInfo = Get-KeeperEpmPolicyDataInfo -Policy $policy -Plugin $plugin
    Write-Output "Policy: $($policyInfo.Name)"
    Write-Output "  UID: $($policy.PolicyUid)"
    Write-Output "  Type: $($policyInfo.Type)"
    $d = $policy.Data
    if ($null -eq $d) {
        $displayStatus = if ($policy.Disabled) { [KeeperSecurity.Plugins.EPM.EpmPolicyStatus]::Off } else { [KeeperSecurity.Plugins.EPM.EpmPolicyStatus]::Enforce }
        Write-Output "  Status: $displayStatus"
        Write-Output "  (Policy data could not be decrypted)"
    }
    if ($null -ne $d) {
        $displayStatus = if ($policy.Disabled) { [KeeperSecurity.Plugins.EPM.EpmPolicyStatus]::Off } elseif ($null -ne $d.Status -and $d.Status -ne '') { $d.Status } else { [KeeperSecurity.Plugins.EPM.EpmPolicyStatus]::Enforce }
        Write-Output "  Status: $displayStatus"
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
    .Parameter PolicyName
        Name for the policy (required).
    .Parameter PolicyType
        Policy type: PrivilegeElevation, FileAccess, CommandLine, LeastPrivilege.
    .Parameter Status
        Policy status: enforce, monitor, monitor_and_notify, off.
    .Parameter Control
        Policy controls (can specify multiple): APPROVAL, JUSTIFY, MFA.
    .Parameter UserFilter
        User collection UID(s) or '*' for all users.
    .Parameter MachineFilter
        Machine collection UID(s).
    .Parameter AppFilter
        Application collection UID(s).
    .Parameter RiskLevel
        Risk level (0-100).
    .Parameter NotificationMessage
        Notification message displayed to users.
    .Parameter NotificationRequiresAcknowledge
        Whether notification requires user acknowledgement.
    .Parameter DayFilter
        Allowed days of the week (can specify multiple): Sunday, Monday, Tuesday, Wednesday, Thursday, Friday, Saturday.
    .Parameter DateFilter
        Date range(s) in format YYYY-MM-DD:YYYY-MM-DD (can specify multiple).
    .Parameter TimeFilter
        Time range(s) in 24-hour format HH-HH, e.g. "09-17" (can specify multiple).
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $PolicyName,
        [Parameter(Mandatory = $true)]
        [ValidateSet('PrivilegeElevation', 'FileAccess', 'CommandLine', 'LeastPrivilege')]
        [string] $PolicyType,
        [Parameter()]
        [ValidateSet('enforce', 'monitor', 'monitor_and_notify', 'off')]
        [string] $Status = [KeeperSecurity.Plugins.EPM.EpmPolicyStatus]::Enforce,
        [Parameter()]
        [ValidateSet('APPROVAL', 'JUSTIFY', 'MFA')]
        [string[]] $Control,
        [Parameter()]
        [string[]] $UserFilter,
        [Parameter()]
        [string[]] $MachineFilter,
        [Parameter()]
        [string[]] $AppFilter,
        [Parameter()]
        [ValidateRange(0, 100)]
        [int] $RiskLevel = 50,
        [Parameter()]
        [string] $NotificationMessage,
        [Parameter()]
        [bool] $NotificationRequiresAcknowledge = $false,
        [Parameter()]
        [ValidateSet('Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday')]
        [string[]] $DayFilter,
        [Parameter()]
        [string[]] $DateFilter,
        [Parameter()]
        [string[]] $TimeFilter
    )

    $plugin = ensureEpmPlugin
    if (-not $plugin) {
        Write-Error -Message 'EPM plugin is not available. Enterprise admin access is required.' -ErrorAction Stop
    }

    $policyUid = [KeeperSecurity.Utils.CryptoUtils]::GenerateUid()

    $controls = @()
    if ($Control) {
        $controls = @($Control | ForEach-Object { $_.ToUpperInvariant() })
    }

    $rules = @(
        @{ RuleName = 'UserCheck'; ErrorMessage = 'This user is not included in this policy'; RuleExpressionType = 'BuiltInAction'; Expression = 'CheckUser()' }
        @{ RuleName = 'MachineCheck'; ErrorMessage = 'This Machine is not included in this policy'; RuleExpressionType = 'BuiltInAction'; Expression = 'CheckMachine()' }
        @{ RuleName = 'ApplicationCheck'; ErrorMessage = 'This application is not included in this policy'; RuleExpressionType = 'BuiltInAction'; Expression = 'CheckFile(false)' }
        @{ RuleName = 'DateCheck'; ErrorMessage = 'Current date is not covered by this policy'; RuleExpressionType = 'BuiltInAction'; Expression = 'CheckDate()' }
        @{ RuleName = 'TimeCheck'; ErrorMessage = 'Current time is not covered by this policy'; RuleExpressionType = 'BuiltInAction'; Expression = 'CheckTime()' }
        @{ RuleName = 'DayCheck'; ErrorMessage = 'Today is not included in this policy'; RuleExpressionType = 'BuiltInAction'; Expression = 'CheckDay()' }
    )

    $policyData = [ordered]@{
        PolicyName                     = $PolicyName
        PolicyType                     = $PolicyType
        PolicyId                       = $policyUid
        Status                         = $Status
        Actions                        = @{
            OnSuccess = @{ Controls = $controls }
            OnFailure = @{ Command = '' }
        }
        NotificationMessage            = if ($NotificationMessage) { $NotificationMessage } else { '' }
        NotificationRequiresAcknowledge = $NotificationRequiresAcknowledge
        RiskLevel                      = $RiskLevel
        Operator                       = 'And'
        Rules                          = $rules
    }

    if ($UserFilter)    { $policyData['UserCheck'] = @($UserFilter) }
    if ($MachineFilter) { $policyData['MachineCheck'] = @($MachineFilter) }
    if ($AppFilter)     { $policyData['ApplicationCheck'] = @($AppFilter) }

    if ($DayFilter) {
        $dayMap = @{ Sunday = 0; Monday = 1; Tuesday = 2; Wednesday = 3; Thursday = 4; Friday = 5; Saturday = 6 }
        $policyData['DayCheck'] = @($DayFilter | ForEach-Object { $dayMap[$_] })
    }
    if ($DateFilter) {
        $dateRanges = @()
        foreach ($df in $DateFilter) {
            $parts = $df -split ':'
            if ($parts.Count -ne 2) {
                Write-Error -Message "Invalid date filter format '$df'. Use YYYY-MM-DD:YYYY-MM-DD." -ErrorAction Stop
            }
            $startDate = [DateTimeOffset]::Parse($parts[0]).ToUnixTimeMilliseconds()
            $endDate = [DateTimeOffset]::Parse($parts[1]).ToUnixTimeMilliseconds()
            $dateRanges += @{ StartDate = $startDate; EndDate = $endDate }
        }
        $policyData['DateCheck'] = $dateRanges
    }
    if ($TimeFilter) {
        $timeRanges = @()
        foreach ($tf in $TimeFilter) {
            $parts = $tf -split '-'
            if ($parts.Count -ne 2) {
                Write-Error -Message "Invalid time filter format '$tf'. Use HH-HH (e.g. 09-17)." -ErrorAction Stop
            }
            $startHour = 0; $endHour = 0
            if (-not [int]::TryParse($parts[0], [ref]$startHour) -or -not [int]::TryParse($parts[1], [ref]$endHour)) {
                Write-Error -Message "Invalid time filter '$tf'. Hours must be numeric." -ErrorAction Stop
            }
            if ($startHour -lt 0 -or $startHour -gt 23 -or $endHour -lt 0 -or $endHour -gt 23) {
                Write-Error -Message "Invalid time filter '$tf'. Hours must be between 0 and 23." -ErrorAction Stop
            }
            $timeRanges += @{ StartTime = $parts[0]; EndTime = $parts[1] }
        }
        $policyData['TimeCheck'] = $timeRanges
    }

    $policyJson = $policyData | ConvertTo-Json -Depth 10 -Compress
    $plainData = [ordered]@{
        PolicyName = $PolicyName
        PolicyType = $PolicyType
        Status     = $Status
    }
    $plainJson = $plainData | ConvertTo-Json -Depth 5 -Compress

    $pi = New-Object KeeperSecurity.Plugins.EPM.EpmPlugin+PolicyInput
    $pi.PolicyUid = $policyUid
    $pi.PlainDataJson = $plainJson
    $pi.PolicyDataJson = $policyJson
    if ($Status -eq [KeeperSecurity.Plugins.EPM.EpmPolicyStatus]::Off) {
        $pi.Disabled = $true
    }

    try {
        $addStatus = $plugin.ModifyPolicies([KeeperSecurity.Plugins.EPM.EpmPlugin+PolicyInput[]]@($pi), $null, $null).GetAwaiter().GetResult()

        if ($addStatus.AddErrors -and $addStatus.AddErrors.Count -gt 0) {
            $err = $addStatus.AddErrors[0]
            Write-Error -Message "Failed to add policy `"$($err.EntityUid)`": $($err.Message)" -ErrorAction Stop
        }
        if ($addStatus.Add -and $addStatus.Add.Count -gt 0) {
            Write-Output "Policy added. UID: $policyUid"
        } else {
            Write-Warning "No policy was added. Check server response."
        }
        writeEpmModifyStatus -Status $addStatus
        $plugin.SyncDown($false).GetAwaiter().GetResult() | Out-Null
    } catch {
        Write-Error -Message "Error adding policy: $($_.Exception.Message)" -ErrorAction Stop
    }
}

function Update-KeeperEpmPolicy {
    <#
    .Synopsis
        Update an EPM policy.
    .Parameter PolicyUidOrName
        Policy UID or policy display name (case-insensitive match on name).
    .Parameter PolicyName
        New policy name.
    .Parameter Status
        Policy status: enforce, monitor, monitor_and_notify, off.
    .Parameter Control
        Policy controls (can specify multiple): APPROVAL, JUSTIFY, MFA.
    .Parameter UserFilter
        User collection UID(s) or '*' for all users.
    .Parameter MachineFilter
        Machine collection UID(s).
    .Parameter AppFilter
        Application collection UID(s).
    .Parameter RiskLevel
        Risk level (0-100).
    .Parameter NotificationMessage
        Notification message displayed to users.
    .Parameter NotificationRequiresAcknowledge
        Whether notification requires user acknowledgement.
    .Parameter DayFilter
        Allowed days of the week (can specify multiple): Sunday, Monday, Tuesday, Wednesday, Thursday, Friday, Saturday.
    .Parameter DateFilter
        Date range(s) in format YYYY-MM-DD:YYYY-MM-DD (can specify multiple).
    .Parameter TimeFilter
        Time range(s) in 24-hour format HH-HH, e.g. "09-17" (can specify multiple).
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $PolicyUidOrName,
        [Parameter()]
        [string] $PolicyName,
        [Parameter()]
        [ValidateSet('enforce', 'monitor', 'monitor_and_notify', 'off')]
        [string] $Status,
        [Parameter()]
        [ValidateSet('APPROVAL', 'JUSTIFY', 'MFA')]
        [string[]] $Control,
        [Parameter()]
        [string[]] $UserFilter,
        [Parameter()]
        [string[]] $MachineFilter,
        [Parameter()]
        [string[]] $AppFilter,
        [Parameter()]
        [ValidateRange(0, 100)]
        [int] $RiskLevel = -1,
        [Parameter()]
        [string] $NotificationMessage,
        [Parameter()]
        [Nullable[bool]] $NotificationRequiresAcknowledge,
        [Parameter()]
        [ValidateSet('Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday')]
        [string[]] $DayFilter,
        [Parameter()]
        [string[]] $DateFilter,
        [Parameter()]
        [string[]] $TimeFilter
    )

    $plugin = ensureEpmPlugin
    if (-not $plugin) {
        Write-Error -Message 'EPM plugin is not available. Enterprise admin access is required.' -ErrorAction Stop
    }

    $policy = Resolve-KeeperEpmSinglePolicy -Identifier $PolicyUidOrName -Plugin $plugin

    $hasChanges = $false
    $policyData = $null
    if ($null -ne $policy.Data) {
        $existingJson = $policy.Data | ConvertTo-Json -Depth 10
        $policyData = $existingJson | ConvertFrom-Json
    }
    if ($null -eq $policyData) {
        $policyData = [PSCustomObject]@{}
    }

    if (-not [string]::IsNullOrEmpty($PolicyName)) {
        $policyData | Add-Member -MemberType NoteProperty -Name 'PolicyName' -Value $PolicyName -Force
        $hasChanges = $true
    }
    if (-not [string]::IsNullOrEmpty($Status)) {
        $policyData | Add-Member -MemberType NoteProperty -Name 'Status' -Value $Status -Force
        $hasChanges = $true
    }
    if ($null -ne $Control) {
        $controls = @($Control | ForEach-Object { $_.ToUpperInvariant() })
        $actions = if ($policyData.PSObject.Properties['Actions']) { $policyData.Actions } else { @{} }
        if ($null -eq $actions) { $actions = @{} }
        $onSuccess = if ($actions.PSObject -and $actions.PSObject.Properties['OnSuccess']) { $actions.OnSuccess } else { @{} }
        if ($null -eq $onSuccess) { $onSuccess = @{} }
        $onSuccess | Add-Member -MemberType NoteProperty -Name 'Controls' -Value $controls -Force
        $actions | Add-Member -MemberType NoteProperty -Name 'OnSuccess' -Value $onSuccess -Force
        $policyData | Add-Member -MemberType NoteProperty -Name 'Actions' -Value $actions -Force
        $hasChanges = $true
    }
    if ($null -ne $UserFilter) {
        $policyData | Add-Member -MemberType NoteProperty -Name 'UserCheck' -Value @($UserFilter) -Force
        $hasChanges = $true
    }
    if ($null -ne $MachineFilter) {
        $policyData | Add-Member -MemberType NoteProperty -Name 'MachineCheck' -Value @($MachineFilter) -Force
        $hasChanges = $true
    }
    if ($null -ne $AppFilter) {
        $policyData | Add-Member -MemberType NoteProperty -Name 'ApplicationCheck' -Value @($AppFilter) -Force
        $hasChanges = $true
    }
    if ($RiskLevel -ge 0) {
        $policyData | Add-Member -MemberType NoteProperty -Name 'RiskLevel' -Value $RiskLevel -Force
        $hasChanges = $true
    }
    if (-not [string]::IsNullOrEmpty($NotificationMessage)) {
        $policyData | Add-Member -MemberType NoteProperty -Name 'NotificationMessage' -Value $NotificationMessage -Force
        $hasChanges = $true
    }
    if ($null -ne $NotificationRequiresAcknowledge) {
        $policyData | Add-Member -MemberType NoteProperty -Name 'NotificationRequiresAcknowledge' -Value $NotificationRequiresAcknowledge -Force
        $hasChanges = $true
    }
    if ($null -ne $DayFilter) {
        $dayMap = @{ Sunday = 0; Monday = 1; Tuesday = 2; Wednesday = 3; Thursday = 4; Friday = 5; Saturday = 6 }
        $policyData | Add-Member -MemberType NoteProperty -Name 'DayCheck' -Value @($DayFilter | ForEach-Object { $dayMap[$_] }) -Force
        $hasChanges = $true
    }
    if ($null -ne $DateFilter) {
        $dateRanges = @()
        foreach ($df in $DateFilter) {
            $parts = $df -split ':'
            if ($parts.Count -ne 2) {
                Write-Error -Message "Invalid date filter format '$df'. Use YYYY-MM-DD:YYYY-MM-DD." -ErrorAction Stop
            }
            $startDate = [DateTimeOffset]::Parse($parts[0]).ToUnixTimeMilliseconds()
            $endDate = [DateTimeOffset]::Parse($parts[1]).ToUnixTimeMilliseconds()
            $dateRanges += @{ StartDate = $startDate; EndDate = $endDate }
        }
        $policyData | Add-Member -MemberType NoteProperty -Name 'DateCheck' -Value $dateRanges -Force
        $hasChanges = $true
    }
    if ($null -ne $TimeFilter) {
        $timeRanges = @()
        foreach ($tf in $TimeFilter) {
            $parts = $tf -split '-'
            if ($parts.Count -ne 2) {
                Write-Error -Message "Invalid time filter format '$tf'. Use HH-HH (e.g. 09-17)." -ErrorAction Stop
            }
            $startHour = 0; $endHour = 0
            if (-not [int]::TryParse($parts[0], [ref]$startHour) -or -not [int]::TryParse($parts[1], [ref]$endHour)) {
                Write-Error -Message "Invalid time filter '$tf'. Hours must be numeric." -ErrorAction Stop
            }
            if ($startHour -lt 0 -or $startHour -gt 23 -or $endHour -lt 0 -or $endHour -gt 23) {
                Write-Error -Message "Invalid time filter '$tf'. Hours must be between 0 and 23." -ErrorAction Stop
            }
            $timeRanges += @{ StartTime = $parts[0]; EndTime = $parts[1] }
        }
        $policyData | Add-Member -MemberType NoteProperty -Name 'TimeCheck' -Value $timeRanges -Force
        $hasChanges = $true
    }

    if (-not $hasChanges) {
        Write-Error -Message 'No changes specified. Provide at least one parameter to update.' -ErrorAction Stop
    }

    $policyJson = $policyData | ConvertTo-Json -Depth 10 -Compress

    $plainData = [ordered]@{}
    $pName = if (-not [string]::IsNullOrEmpty($PolicyName)) { $PolicyName } elseif ($policyData.PSObject.Properties['PolicyName']) { $policyData.PolicyName } else { '' }
    $pType = if ($policyData.PSObject.Properties['PolicyType']) { $policyData.PolicyType } else { '' }
    $pStatus = if (-not [string]::IsNullOrEmpty($Status)) { $Status } elseif ($policyData.PSObject.Properties['Status']) { $policyData.Status } else { '' }
    if (-not [string]::IsNullOrEmpty($pName)) { $plainData['PolicyName'] = $pName }
    if (-not [string]::IsNullOrEmpty($pType)) { $plainData['PolicyType'] = $pType }
    if (-not [string]::IsNullOrEmpty($pStatus)) { $plainData['Status'] = $pStatus }
    $plainJson = $plainData | ConvertTo-Json -Depth 5 -Compress

    $pi = New-Object KeeperSecurity.Plugins.EPM.EpmPlugin+PolicyInput
    $pi.PolicyUid = $policy.PolicyUid
    $pi.PlainDataJson = $plainJson
    $pi.PolicyDataJson = $policyJson
    if (-not [string]::IsNullOrEmpty($Status)) {
        if ($Status -eq [KeeperSecurity.Plugins.EPM.EpmPolicyStatus]::Off) {
            $pi.Disabled = $true
        } else {
            $pi.Disabled = $false
        }
    }

    try {
        $updateStatus = $plugin.ModifyPolicies($null, [KeeperSecurity.Plugins.EPM.EpmPlugin+PolicyInput[]]@($pi), $null).GetAwaiter().GetResult()

        if ($updateStatus.UpdateErrors -and $updateStatus.UpdateErrors.Count -gt 0) {
            $err = $updateStatus.UpdateErrors[0]
            Write-Error -Message "Failed to update policy `"$($err.EntityUid)`": $($err.Message)" -ErrorAction Stop
        }
        if ($updateStatus.Update -and $updateStatus.Update.Count -gt 0) {
            Write-Output "Policy '$($policy.PolicyUid)' updated."
        } else {
            Write-Warning "No policy was updated. Check server response."
        }
        writeEpmModifyStatus -Status $updateStatus
        $plugin.SyncDown($false).GetAwaiter().GetResult() | Out-Null
    } catch {
        Write-Error -Message "Error updating policy: $($_.Exception.Message)" -ErrorAction Stop
    }
}

function Remove-KeeperEpmPolicy {
    <#
    .Synopsis
        Remove an EPM policy by UID or name.
    .Parameter PolicyUidOrName
        Policy UID or policy display name (case-insensitive match on name).
    .Parameter Force
        If set, skip confirmation prompt before delete.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    Param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $PolicyUidOrName,
        [Parameter()]
        [switch] $Force
    )

    $plugin = ensureEpmPlugin
    if (-not $plugin) {
        Write-Error -Message 'EPM plugin is not available. Enterprise admin access is required.' -ErrorAction Stop
    }

    $policy = Resolve-KeeperEpmSinglePolicy -Identifier $PolicyUidOrName -Plugin $plugin

    $policyInfo = Get-KeeperEpmPolicyDataInfo -Policy $policy -Plugin $plugin
    $label = if (-not [string]::IsNullOrEmpty($policyInfo.Name)) { $policyInfo.Name } else { $policy.PolicyUid }
    if (-not $Force -and -not $PSCmdlet.ShouldProcess("policy '$label'", "Remove")) {
        return
    }

    try {
        $removeStatus = $plugin.ModifyPolicies($null, $null, [string[]]@($policy.PolicyUid)).GetAwaiter().GetResult()

        if ($removeStatus.RemoveErrors -and $removeStatus.RemoveErrors.Count -gt 0) {
            $err = $removeStatus.RemoveErrors[0]
            Write-Error -Message "Failed to remove policy `"$($err.EntityUid)`": $($err.Message)" -ErrorAction Stop
        }
        if ($removeStatus.Remove -and $removeStatus.Remove.Count -gt 0) {
            Write-Output "Policy '$($policy.PolicyUid)' removed."
        } else {
            Write-Warning "No policy was removed. Check server response."
        }
        writeEpmModifyStatus -Status $removeStatus
        $plugin.SyncDown($false).GetAwaiter().GetResult() | Out-Null
    } catch {
        Write-Error -Message "Error removing policy: $($_.Exception.Message)" -ErrorAction Stop
    }
}

function Get-KeeperEpmPolicyAgent {
    <#
    .Synopsis
        List agents for one or more policies by policy UID or name.
    .Parameter PolicyUidOrNames
        One or more policy UIDs or policy names.
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [string[]] $PolicyUidOrNames
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

    $identifiers = @($PolicyUidOrNames | ForEach-Object { $_.Trim() } | Where-Object { -not [string]::IsNullOrEmpty($_) })
    if ($identifiers.Count -eq 0) {
        Write-Error -Message "Policy UID or name is required for 'agents'." -ErrorAction Stop
    }

    $policyUids = [System.Collections.Generic.List[string]]::new()
    foreach ($identifier in $identifiers) {
        $matches = @(Resolve-KeeperEpmPolicy -Identifier $identifier -Plugin $plugin)
        if ($matches.Count -eq 0) {
            Write-Warning "Policy '$identifier' not found."
            continue
        }
        if ($matches.Count -gt 1) {
            Write-Warning "Multiple policies match name '$identifier'. Use Policy UID."
            continue
        }
        [void]$policyUids.Add($matches[0].PolicyUid)
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
                $status = Get-KeeperEpmPolicyListStatus -Policy $policy
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
                $st = if ($agent.Disabled) { [KeeperSecurity.Plugins.EPM.EpmPolicyStatus]::Off } else { 'on' }
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
        One or more policy UIDs or policy names.
    .Parameter CollectionUid
        One or more collection UIDs. Use '*' or 'all' for the all-agents collection.
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [string[]] $PolicyUidOrNames,
        [Parameter(Mandatory = $true)]
        [string[]] $CollectionUid
    )

    $plugin = ensureEpmPlugin
    if (-not $plugin) {
        Write-Error -Message 'EPM plugin is not available. Enterprise admin access is required.' -ErrorAction Stop
    }

    $identifiers = @($PolicyUidOrNames | ForEach-Object { $_.Trim() } | Where-Object { -not [string]::IsNullOrEmpty($_) })
    if ($identifiers.Count -eq 0) {
        Write-Error -Message "Policy UID or name is required for 'assign'." -ErrorAction Stop
    }

    $policies = [System.Collections.Generic.List[object]]::new()
    foreach ($identifier in $identifiers) {
        $matches = @(Resolve-KeeperEpmPolicy -Identifier $identifier -Plugin $plugin)
        if ($matches.Count -eq 0) {
            Write-Warning "Policy '$identifier' not found."
            continue
        }
        if ($matches.Count -gt 1) {
            Write-Warning "Multiple policies match name '$identifier'. Use Policy UID."
            continue
        }
        [void]$policies.Add($matches[0])
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
                if ($collUidBytes.Length -ne 16) {
                    Write-Warning "Invalid collection UID: $c. Skipped."
                    continue
                }
                $existing = $plugin.Collections.GetEntity($c)
                if ($null -eq $existing) {
                    Write-Warning "Collection '$c' not found. Skipped."
                    continue
                }
                [void]$collectionUids.Add($collUidBytes)
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

    try {
        $status = $plugin.SetCollectionLinks($setLinks, $null).GetAwaiter().GetResult()

        $hasErrors = $false
        if ($status.AddErrors -and $status.AddErrors.Count -gt 0) {
            foreach ($err in $status.AddErrors) {
                if (-not $err.Success) {
                    Write-Error -Message "Failed to assign collection to policy `"$($err.EntityUid)`": $($err.Message)" -ErrorAction Continue
                    $hasErrors = $true
                }
            }
        }
        if ($status.RemoveErrors -and $status.RemoveErrors.Count -gt 0) {
            foreach ($err in $status.RemoveErrors) {
                if (-not $err.Success) {
                    Write-Error -Message "Failed to remove collection from policy `"$($err.EntityUid)`": $($err.Message)" -ErrorAction Continue
                    $hasErrors = $true
                }
            }
        }
        if ($status.Add -and $status.Add.Count -gt 0) {
            Write-Output "$($status.Add.Count) collection(s) assigned to policy."
        } elseif (-not $hasErrors) {
            Write-Warning "No collections were assigned. Check server response."
        }
        writeEpmModifyStatus -Status $status
        $plugin.SyncDown($false).GetAwaiter().GetResult() | Out-Null
    } catch {
        Write-Error -Message "Error assigning collections to policy: $($_.Exception.Message)" -ErrorAction Stop
    }
}

New-Alias -Name kepm-policy-list     -Value Get-KeeperEpmPolicyList        -ErrorAction SilentlyContinue
New-Alias -Name kepm-policy-view     -Value Get-KeeperEpmPolicy            -ErrorAction SilentlyContinue
New-Alias -Name kepm-policy-add      -Value Add-KeeperEpmPolicy           -ErrorAction SilentlyContinue
New-Alias -Name kepm-policy-edit     -Value Update-KeeperEpmPolicy        -ErrorAction SilentlyContinue
New-Alias -Name kepm-policy-delete   -Value Remove-KeeperEpmPolicy       -ErrorAction SilentlyContinue
New-Alias -Name kepm-policy-remove   -Value Remove-KeeperEpmPolicy       -ErrorAction SilentlyContinue
New-Alias -Name kepm-policy-agents   -Value Get-KeeperEpmPolicyAgent      -ErrorAction SilentlyContinue
New-Alias -Name kepm-policy-assign   -Value Add-KeeperEpmPolicyCollection -ErrorAction SilentlyContinue
