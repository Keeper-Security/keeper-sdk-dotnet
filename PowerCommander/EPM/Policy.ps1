class EpmPolicyDataInfo {
    [string]$Name
    [string]$Type
    [System.Collections.Generic.List[string]]$Controls
    [string]$Users
    [string]$Machines
    [string]$Applications
    [string]$Collections

    EpmPolicyDataInfo() {
        $this.Name = ''
        $this.Type = ''
        $this.Controls = [System.Collections.Generic.List[string]]::new()
        $this.Users = ''
        $this.Machines = ''
        $this.Applications = ''
        $this.Collections = ''
    }
}

class EpmDateRange {
    [long]$StartDate
    [long]$EndDate

    EpmDateRange([long]$start, [long]$end) {
        $this.StartDate = $start
        $this.EndDate = $end
    }
}

class EpmTimeRange {
    [string]$StartTime
    [string]$EndTime

    EpmTimeRange([string]$start, [string]$end) {
        $this.StartTime = $start
        $this.EndTime = $end
    }
}

class EpmPolicyFilterResult {
    [int[]]$DayCheck
    [EpmDateRange[]]$DateCheck
    [EpmTimeRange[]]$TimeCheck

    EpmPolicyFilterResult() {
        $this.DayCheck = $null
        $this.DateCheck = $null
        $this.TimeCheck = $null
    }
}

class EpmPolicyRule {
    [string]$RuleName
    [string]$ErrorMessage
    [string]$RuleExpressionType
    [string]$Expression

    EpmPolicyRule([string]$name, [string]$error, [string]$exprType, [string]$expr) {
        $this.RuleName = $name
        $this.ErrorMessage = $error
        $this.RuleExpressionType = $exprType
        $this.Expression = $expr
    }
}

class EpmPolicyListRow {
    [string]$PolicyUid
    [string]$PolicyName
    [string]$PolicyType
    [string]$Status
    [string]$Controls
    [string]$Users
    [string]$Machines
    [string]$Applications
    [string]$Collections
}

class EpmPolicyAgentRow {
    [string]$Key
    [string]$UID
    [string]$Name
    [string]$Status
}

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
            if ([string]::IsNullOrWhiteSpace($jsonText)) {
                Write-Warning "Get-KeeperEpmPolicyListStatus: PolicyData decoded to empty string for policy '$($Policy.PolicyUid)'."
            }
            else {
                $jo = $jsonText | ConvertFrom-Json -ErrorAction Stop
                if ($null -ne $jo -and $jo.PSObject.Properties['Status']) {
                    return [string]$jo.Status
                }
            }
        }
    }
    catch {
        Write-Warning "Get-KeeperEpmPolicyListStatus: Failed to parse policy data for '$($Policy.PolicyUid)': $($_.Exception.Message)"
    }
    return [KeeperSecurity.Plugins.EPM.EpmPolicyStatus]::Enforce
}

function script:Get-KeeperEpmPolicyDataInfo {
    Param (
        [Parameter(Mandatory = $true)] $Policy,
        [Parameter(Mandatory = $true)] $Plugin
    )
    $info = [EpmPolicyDataInfo]::new()

    $data = $Policy.Data
    if ($null -eq $data) {
        return $info
    }

    if ($null -ne $data.PolicyName) { $info.Name = [string]$data.PolicyName }
    if ($null -ne $data.PolicyType) { $info.Type = [string]$data.PolicyType }

    if ($null -ne $data.Actions -and $null -ne $data.Actions.OnSuccess -and $data.Actions.OnSuccess.Controls) {
        foreach ($control in $data.Actions.OnSuccess.Controls) {
            if ($null -eq $control) { continue }
            $controlStr = [string]$control
            if ([string]::IsNullOrEmpty($controlStr)) { continue }
            $upper = $controlStr.ToUpperInvariant()
            if ($upper -eq [KeeperSecurity.Plugins.EPM.EpmPolicyControl]::Approval) { [void]$info.Controls.Add([KeeperSecurity.Plugins.EPM.EpmPolicyControl]::Approval) }
            elseif ($upper -eq [KeeperSecurity.Plugins.EPM.EpmPolicyControl]::Justify) { [void]$info.Controls.Add([KeeperSecurity.Plugins.EPM.EpmPolicyControl]::Justify) }
            elseif ($upper -eq [KeeperSecurity.Plugins.EPM.EpmPolicyControl]::Mfa) { [void]$info.Controls.Add([KeeperSecurity.Plugins.EPM.EpmPolicyControl]::Mfa) }
            else { [void]$info.Controls.Add($upper) }
        }
    }

    if ($data.UserCheck -and $data.UserCheck.Count -gt 0) {
        $info.Users = $data.UserCheck -join ', '
    }
    if ($data.MachineCheck -and $data.MachineCheck.Count -gt 0) {
        $info.Machines = $data.MachineCheck -join ', '
    }
    if ($data.ApplicationCheck -and $data.ApplicationCheck.Count -gt 0) {
        $info.Applications = $data.ApplicationCheck -join ', '
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
        $info.Collections = $collectionUids -join ', '
    }
    catch {
        Write-Debug "GetCollectionLinksForObject: $($_.Exception.Message)"
    }

    return $info
}

function script:Resolve-KeeperEpmPolicy {
    Param (
        [Parameter(Mandatory = $true)]
        [string] $Identifier,
        [Parameter(Mandatory = $true)]
        $Plugin
    )
    if ([string]::IsNullOrEmpty($Identifier)) {
        throw "Identifier cannot be null or empty"
    }
    $id = $Identifier.Trim()
    if ([string]::IsNullOrEmpty($id)) {
        throw "Identifier cannot be whitespace-only"
    }

    $policy = $Plugin.Policies.GetEntity($id)
    if ($null -ne $policy) { return @($policy) }

    $matched = [System.Collections.Generic.List[object]]::new()
    foreach ($p in $Plugin.Policies.GetAll()) {
        $pInfo = Get-KeeperEpmPolicyDataInfo -Policy $p -Plugin $Plugin
        if (-not [string]::IsNullOrEmpty($pInfo.Name) -and $pInfo.Name.Equals($id, [System.StringComparison]::OrdinalIgnoreCase)) {
            [void]$matched.Add($p)
        }
    }
    return @($matched)
}

function script:Resolve-KeeperEpmSinglePolicy {
    Param (
        [Parameter(Mandatory = $true)]
        [string] $Identifier,
        [Parameter(Mandatory = $true)]
        [object] $Plugin
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

function script:Confirm-EpmPolicyFilterParams {
    Param (
        [string[]] $DayFilter,
        [string[]] $DateFilter,
        [string[]] $TimeFilter
    )

    $validDays = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    'sunday','monday','tuesday','wednesday','thursday','friday','saturday' | ForEach-Object { [void]$validDays.Add($_) }
    $dayMap = @{ sunday = 0; monday = 1; tuesday = 2; wednesday = 3; thursday = 4; friday = 5; saturday = 6 }

    $result = [EpmPolicyFilterResult]::new()

    if ($DayFilter) {
        foreach ($day in $DayFilter) {
            if (-not $validDays.Contains($day.Trim())) {
                throw "Invalid day '$day'. Allowed values: Sunday, Monday, Tuesday, Wednesday, Thursday, Friday, Saturday."
            }
        }
        $result.DayCheck = @($DayFilter | ForEach-Object { $dayMap[$_.Trim().ToLowerInvariant()] })
    }

    if ($DateFilter) {
        $dateRanges = [System.Collections.Generic.List[EpmDateRange]]::new()
        $dateFmt = 'yyyy-MM-dd'
        $culture = [System.Globalization.CultureInfo]::InvariantCulture
        foreach ($df in $DateFilter) {
            $parts = $df -split ':'
            if ($parts.Count -ne 2) {
                Write-Error -Message "Invalid date filter format '$df'. Use YYYY-MM-DD:YYYY-MM-DD." -ErrorAction Stop
            }
            try {
                $startDate = [DateTimeOffset]::ParseExact($parts[0].Trim(), $dateFmt, $culture).ToUnixTimeMilliseconds()
            } catch {
                Write-Error -Message "Invalid start date '$($parts[0])'. Use format YYYY-MM-DD." -ErrorAction Stop
            }
            try {
                $endDate = [DateTimeOffset]::ParseExact($parts[1].Trim(), $dateFmt, $culture).ToUnixTimeMilliseconds()
            } catch {
                Write-Error -Message "Invalid end date '$($parts[1])'. Use format YYYY-MM-DD." -ErrorAction Stop
            }
            if ($endDate -lt $startDate) {
                Write-Error -Message "Date range end '$($parts[1])' is before start '$($parts[0])'." -ErrorAction Stop
            }
            [void]$dateRanges.Add([EpmDateRange]::new($startDate, $endDate))
        }
        $result.DateCheck = @($dateRanges)
    }

    if ($TimeFilter) {
        $timeRanges = [System.Collections.Generic.List[EpmTimeRange]]::new()
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
            if ($startHour -eq $endHour) {
                Write-Error -Message "Invalid time filter '$tf'. Start and end hours cannot be equal (zero-width range)." -ErrorAction Stop
            }
            [void]$timeRanges.Add([EpmTimeRange]::new($parts[0], $parts[1]))
        }
        $result.TimeCheck = @($timeRanges)
    }

    return $result
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
        try {
            $b = [KeeperSecurity.Utils.CryptoUtils]::Base64UrlDecode($uid)
        } catch {
            Write-Error -Message "Invalid policy UID '$uid': $($_.Exception.Message)" -ErrorAction Stop
        }
        [void]$rq.PolicyUid.Add([Google.Protobuf.ByteString]::CopyFrom($b))
    }
    $task = [KeeperSecurity.Authentication.AuthExtensions]::ExecuteRouter[PEDM.PolicyAgentResponse]($Auth, 'pedm/get_policy_agents', [Google.Protobuf.IMessage]$rq)
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

    $rows = [System.Collections.Generic.List[EpmPolicyListRow]]::new()
    foreach ($pol in ($policies | Sort-Object -Property PolicyUid)) {
        $policyInfo = Get-KeeperEpmPolicyDataInfo -Policy $pol -Plugin $plugin
        $status = Get-KeeperEpmPolicyListStatus -Policy $pol
        $row = [EpmPolicyListRow]::new()
        $row.PolicyUid = $pol.PolicyUid
        $row.PolicyName = $policyInfo.Name
        $row.PolicyType = $policyInfo.Type
        $row.Status = $status
        $row.Controls = ($policyInfo.Controls -join "`n").Trim()
        $row.Users = $policyInfo.Users
        $row.Machines = $policyInfo.Machines
        $row.Applications = $policyInfo.Applications
        $row.Collections = $policyInfo.Collections
        [void]$rows.Add($row)
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
    $displayStatus = Get-KeeperEpmPolicyListStatus -Policy $policy
    Write-Output "  Status: $displayStatus"
    if ($null -eq $d) {
        Write-Output "  (Policy data could not be decrypted)"
    }
    else {
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
        [EpmPolicyRule]::new('UserCheck', 'This user is not included in this policy', 'BuiltInAction', 'CheckUser()')
        [EpmPolicyRule]::new('MachineCheck', 'This Machine is not included in this policy', 'BuiltInAction', 'CheckMachine()')
        [EpmPolicyRule]::new('ApplicationCheck', 'This application is not included in this policy', 'BuiltInAction', 'CheckFile(false)')
        [EpmPolicyRule]::new('DateCheck', 'Current date is not covered by this policy', 'BuiltInAction', 'CheckDate()')
        [EpmPolicyRule]::new('TimeCheck', 'Current time is not covered by this policy', 'BuiltInAction', 'CheckTime()')
        [EpmPolicyRule]::new('DayCheck', 'Today is not included in this policy', 'BuiltInAction', 'CheckDay()')
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

    $validated = Confirm-EpmPolicyFilterParams -DayFilter $DayFilter -DateFilter $DateFilter -TimeFilter $TimeFilter

    if ($UserFilter)    { $policyData['UserCheck'] = @($UserFilter) }
    if ($MachineFilter) { $policyData['MachineCheck'] = @($MachineFilter) }
    if ($AppFilter)     { $policyData['ApplicationCheck'] = @($AppFilter) }

    if ($null -ne $validated.DayCheck)  { $policyData['DayCheck'] = $validated.DayCheck }
    if ($null -ne $validated.DateCheck) { $policyData['DateCheck'] = $validated.DateCheck }
    if ($null -ne $validated.TimeCheck) { $policyData['TimeCheck'] = $validated.TimeCheck }

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
        [Nullable[int]] $RiskLevel,
        [Parameter()]
        [string] $NotificationMessage,
        [Parameter()]
        [Nullable[bool]] $NotificationRequiresAcknowledge,
        [Parameter()]
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
        # Deep-clone via JSON round-trip to avoid mutating the cached SDK object
        try {
            $existingJson = $policy.Data | ConvertTo-Json -Depth 10
            $policyData = $existingJson | ConvertFrom-Json
        } catch {
            Write-Error -Message "Failed to clone existing policy data for '$($policy.PolicyUid)': $($_.Exception.Message)" -ErrorAction Stop
        }
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
    $validated = Confirm-EpmPolicyFilterParams -DayFilter $DayFilter -DateFilter $DateFilter -TimeFilter $TimeFilter

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
    if ($null -ne $RiskLevel) {
        $policyData | Add-Member -MemberType NoteProperty -Name 'RiskLevel' -Value $RiskLevel.Value -Force
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
    if ($null -ne $validated.DayCheck) {
        $policyData | Add-Member -MemberType NoteProperty -Name 'DayCheck' -Value $validated.DayCheck -Force
        $hasChanges = $true
    }
    if ($null -ne $validated.DateCheck) {
        $policyData | Add-Member -MemberType NoteProperty -Name 'DateCheck' -Value $validated.DateCheck -Force
        $hasChanges = $true
    }
    if ($null -ne $validated.TimeCheck) {
        $policyData | Add-Member -MemberType NoteProperty -Name 'TimeCheck' -Value $validated.TimeCheck -Force
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
        $resolvedPolicies = @(Resolve-KeeperEpmPolicy -Identifier $identifier -Plugin $plugin)
        if ($resolvedPolicies.Count -eq 0) {
            Write-Warning "Policy '$identifier' not found."
            continue
        }
        if ($resolvedPolicies.Count -gt 1) {
            Write-Warning "Multiple policies match name '$identifier'. Use Policy UID."
            continue
        }
        [void]$policyUids.Add($resolvedPolicies[0].PolicyUid)
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

        $rows = [System.Collections.Generic.List[EpmPolicyAgentRow]]::new()
        foreach ($policyUid in $policyUids) {
            $policy = $plugin.Policies.GetEntity($policyUid)
            if ($null -ne $policy) {
                $policyInfo = Get-KeeperEpmPolicyDataInfo -Policy $policy -Plugin $plugin
                $status = Get-KeeperEpmPolicyListStatus -Policy $policy
                $row = [EpmPolicyAgentRow]::new()
                $row.Key = 'Policy'
                $row.UID = $policyUid
                $row.Name = $policyInfo.Name
                $row.Status = $status
                [void]$rows.Add($row)
            }
        }
        foreach ($agentUid in $activeAgentUids) {
            $agent = $plugin.Agents.GetEntity($agentUid)
            $machineName = ''
            $st = ''
            if ($null -ne $agent) {
                $machineName = if ($agent.MachineId) { $agent.MachineId } else { '' }
                $st = if ($agent.Disabled) { [KeeperSecurity.Plugins.EPM.EpmPolicyStatus]::Off } else { [KeeperSecurity.Plugins.EPM.EpmPolicyStatus]::Enforce }
            }
            $row = [EpmPolicyAgentRow]::new()
            $row.Key = 'Agent'
            $row.UID = $agentUid
            $row.Name = $machineName
            $row.Status = $st
            [void]$rows.Add($row)
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
        $resolvedPolicies = @(Resolve-KeeperEpmPolicy -Identifier $identifier -Plugin $plugin)
        if ($resolvedPolicies.Count -eq 0) {
            Write-Warning "Policy '$identifier' not found."
            continue
        }
        if ($resolvedPolicies.Count -gt 1) {
            Write-Warning "Multiple policies match name '$identifier'. Use Policy UID."
            continue
        }
        [void]$policies.Add($resolvedPolicies[0])
    }

    if ($policies.Count -eq 0) { return }

    $collectionUids = [System.Collections.Generic.List[byte[]]]::new()
    foreach ($collUid in $CollectionUid) {
        if ([string]::IsNullOrWhiteSpace($collUid)) {
            Write-Warning "Empty collection UID. Skipped."
            continue
        }
        $c = $collUid.Trim()
        if ($c -eq '*' -or $c -eq 'all') {
            $allAgentsUid = $plugin.AllAgentsCollectionUid
            if (-not [string]::IsNullOrEmpty($allAgentsUid)) {
                try {
                    $allBytes = [KeeperSecurity.Utils.CryptoUtils]::Base64UrlDecode($allAgentsUid)
                    if ($null -eq $allBytes -or $allBytes.Length -ne 16) {
                        Write-Warning "Invalid all-agents collection UID (expected 16 bytes, got $($allBytes.Length)). Skipped."
                    } else {
                        [void]$collectionUids.Add($allBytes)
                    }
                }
                catch {
                    Write-Warning "Invalid all-agents collection UID: $($_.Exception.Message). Skipped."
                }
            }
        }
        else {
            if ($c -notmatch '^[A-Za-z0-9_\-]+=*$') {
                Write-Warning "Collection UID '$c' is not valid Base64Url. Skipped."
                continue
            }
            try {
                $collUidBytes = [KeeperSecurity.Utils.CryptoUtils]::Base64UrlDecode($c)
                if ($null -eq $collUidBytes -or $collUidBytes.Length -ne 16) {
                    Write-Warning "Invalid collection UID: $c (expected 16 bytes, got $($collUidBytes.Length)). Skipped."
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
