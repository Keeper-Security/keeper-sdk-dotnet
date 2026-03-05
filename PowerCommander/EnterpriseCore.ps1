function getEnterprise {
    [KeeperSecurity.Authentication.IAuthentication] $auth = $Script:Context.Auth
    if (-not $auth) {
        Write-Error -Message "Not Connected" -ErrorAction Stop
    }
    if (-not $auth.AuthContext.IsEnterpriseAdmin) {
        Write-Error -Message "Not an Enterprise Administrator" -ErrorAction Stop
    }
    $enterprise = $Script:Context.Enterprise
    if (-not $enterprise) {
        $enterprise = New-Object Enterprise

        $enterprise.enterpriseData = New-Object KeeperSecurity.Enterprise.EnterpriseData
        $enterprise.roleData = New-Object KeeperSecurity.Enterprise.RoleData
        $enterprise.queuedTeamData = New-Object KeeperSecurity.Enterprise.QueuedTeamData
        $enterprise.mspData = New-Object KeeperSecurity.Enterprise.ManagedCompanyData
        $enterprise.deviceApproval = New-Object KeeperSecurity.Enterprise.DeviceApprovalData

        [KeeperSecurity.Enterprise.EnterpriseDataPlugin[]] $plugins = $enterprise.enterpriseData, $enterprise.roleData, $enterprise.queuedTeamData, $enterprise.mspData, $enterprise.deviceApproval

        $enterprise.loader = New-Object KeeperSecurity.Enterprise.EnterpriseLoader($auth, $plugins)
        $enterprise.loader.Load().GetAwaiter().GetResult() | Out-Null

        if ($enterprise.enterpriseData.EnterpriseLicense.licenseStatus.StartsWith("msp")) {
            $enterprise.ManagedCompanies = @{}
        }

        $Script:Context.Enterprise = $enterprise
        $Script:Context.ManagedCompanyId = 0
    }

    if ($Script:Context.ManagedCompanyId -le 0) {
        return $enterprise
    }

    if ($null -eq $enterprise.ManagedCompanies) {
        $Script:Context.ManagedCompanyId = 0
        return $enterprise
    }

    $enterpriseMc = $enterprise.ManagedCompanies[$Script:Context.ManagedCompanyId]
    if ($null -eq $enterpriseMc) {
        $authMc = New-Object KeeperSecurity.Enterprise.ManagedCompanyAuth
        $authMc.LoginToManagedCompany($Script:Context.Enterprise.loader, $Script:Context.ManagedCompanyId).GetAwaiter().GetResult() | Out-Null

        $enterpriseMc = New-Object Enterprise
        $enterpriseMc.enterpriseData = New-Object KeeperSecurity.Enterprise.EnterpriseData
        $enterpriseMc.roleData = New-Object KeeperSecurity.Enterprise.RoleData
        $enterpriseMc.queuedTeamData = New-Object KeeperSecurity.Enterprise.QueuedTeamData
        $enterpriseMc.deviceApproval = New-Object KeeperSecurity.Enterprise.DeviceApprovalData

        [KeeperSecurity.Enterprise.EnterpriseDataPlugin[]] $plugins = $enterpriseMc.enterpriseData, $enterpriseMc.roleData, $enterpriseMc.queuedTeamData, $enterpriseMc.deviceApproval

        $enterpriseMc.loader = New-Object KeeperSecurity.Enterprise.EnterpriseLoader($authMc, $plugins)
        $enterpriseMc.loader.Load().GetAwaiter().GetResult() | Out-Null
        $enterprise.ManagedCompanies[$Script:Context.ManagedCompanyId] = $enterpriseMc
    }
    $enterprise = $enterpriseMc

    return $enterprise
}

function Sync-KeeperEnterprise {
    <#
        .Synopsis
        Sync Keeper Enterprise Information
    #>

    [CmdletBinding()]
    [Enterprise]$enterprise = getEnterprise
    $task = $enterprise.loader.Load()
    $task.GetAwaiter().GetResult() | Out-Null
}
New-Alias -Name ked -Value Sync-KeeperEnterprise

function Get-EnterpriseUser {
    <#
        .Synopsis
    	Get a list of enterprise users
    #>
    [CmdletBinding()]

    $enterprise = getEnterprise
    return $enterprise.enterpriseData.Users
}

function Get-KeeperEnterpriseUser {
    <#
        .SYNOPSIS
    	Get a list of enterprise users

        .PARAMETER Email
        User email address or user ID (exact match). Returns the single matching user.

        .PARAMETER Filter
        Search filter applied across all user properties (case-insensitive regex match).

        .PARAMETER Format
        Output format: table (default) or json.

        .PARAMETER Output
        File path to export results when Format is 'json'. Ignored for 'table' format.

        .EXAMPLE
        Get-KeeperEnterpriseUser
        Lists all enterprise users in table format.

        .EXAMPLE
        Get-KeeperEnterpriseUser -Email "user@example.com"
        Returns the enterprise user with the specified email address.

        .EXAMPLE
        Get-KeeperEnterpriseUser -Filter "admin"
        Returns all enterprise users whose properties match "admin".

        .EXAMPLE
        Get-KeeperEnterpriseUser -Format json -Output "users.json"
        Exports all enterprise users to a JSON file.
    #>
    [CmdletBinding()]
    Param (
        [Parameter()][string] $Email,
        [Parameter()][string] $Filter,
        [Parameter()][ValidateSet('table', 'json')][string] $Format = 'table',
        [Parameter()][string] $Output
    )

    if ($Email) { $Email = $Email.Trim() }
    if ($Filter) { $Filter = $Filter.Trim() }

    $users = Get-EnterpriseUser
    if (-not $users) {
        Write-Warning "No enterprise users found."
        return @()
    }

    if ($Email) {
        $users = $users | Where-Object { ($_.Email -eq $Email) -or ($_.Id.ToString() -eq $Email) }
    }

    if ($Filter) {
        $filterLower = $Filter.ToLower()
        $users = $users | Where-Object {
            $text = ($_.PSObject.Properties.Value | ForEach-Object { "$_" }) -join ' '
            $text -match [regex]::Escape($filterLower)
        }
    }

    $result = @($users)
    if ($result.Count -eq 0 -and ($Email -or $Filter)) {
        Write-Host "No matching enterprise users found." -ForegroundColor Yellow
        return @()
    }

    if ($Format -eq 'json') {
        $json = $result | ConvertTo-Json -Depth 5
        if ($Output) {
            Set-Content -Path $Output -Value $json -Encoding utf8
            Write-Host "Results exported to: $Output" -ForegroundColor Green
        } else {
            return $json
        }
    } else {
        return $result
    }
}
New-Alias -Name keu -Value Get-KeeperEnterpriseUser

function Get-EnterpriseTeam {
    <#
        .Synopsis
    	Get a list of enterprise teams
    #>
    [CmdletBinding()]

    $enterprise = getEnterprise
    return $enterprise.enterpriseData.Teams
}

function Get-KeeperEnterpriseTeam {
    <#
        .SYNOPSIS
    	Get a list of enterprise teams

        .PARAMETER Name
        Team name or Team UID (exact match). Returns the single matching team.

        .PARAMETER Filter
        Search filter applied across all team properties (case-insensitive regex match).

        .PARAMETER Format
        Output format: table (default) or json.

        .PARAMETER Output
        File path to export results when Format is 'json'. Ignored for 'table' format.

        .EXAMPLE
        Get-KeeperEnterpriseTeam
        Lists all enterprise teams in table format.

        .EXAMPLE
        Get-KeeperEnterpriseTeam -Name "Engineering"
        Returns the enterprise team named "Engineering".

        .EXAMPLE
        Get-KeeperEnterpriseTeam -Filter "dev"
        Returns all enterprise teams whose properties match "dev".

        .EXAMPLE
        Get-KeeperEnterpriseTeam -Format json -Output "teams.json"
        Exports all enterprise teams to a JSON file.
    #>
    [CmdletBinding()]
    Param (
        [Parameter()][string] $Name,
        [Parameter()][string] $Filter,
        [Parameter()][ValidateSet('table', 'json')][string] $Format = 'table',
        [Parameter()][string] $Output
    )

    if ($Name) { $Name = $Name.Trim() }
    if ($Filter) { $Filter = $Filter.Trim() }

    $teams = Get-EnterpriseTeam
    if (-not $teams) {
        Write-Warning "No enterprise teams found."
        return @()
    }

    if ($Name) {
        $teams = $teams | Where-Object { ($_.Name -eq $Name) -or ($_.Uid -eq $Name) }
    }

    if ($Filter) {
        $filterLower = $Filter.ToLower()
        $teams = $teams | Where-Object {
            $text = ($_.PSObject.Properties.Value | ForEach-Object { "$_" }) -join ' '
            $text -match [regex]::Escape($filterLower)
        }
    }

    $result = @($teams)
    if ($result.Count -eq 0 -and ($Name -or $Filter)) {
        Write-Host "No matching enterprise teams found." -ForegroundColor Yellow
        return @()
    }

    if ($Format -eq 'json') {
        $json = $result | ConvertTo-Json -Depth 5
        if ($Output) {
            Set-Content -Path $Output -Value $json -Encoding utf8
            Write-Host "Results exported to: $Output" -ForegroundColor Green
        } else {
            return $json
        }
    } else {
        return $result
    }
}
New-Alias -Name ket -Value Get-KeeperEnterpriseTeam

function Get-EnterpriseNode {
    <#
        .Synopsis
    	Get a list of enterprise nodes
    #>
    [CmdletBinding()]

    $enterprise = getEnterprise
    return $enterprise.enterpriseData.Nodes
}

function Get-KeeperEnterpriseNode {
    <#
        .SYNOPSIS
    	Get a list of enterprise nodes

        .PARAMETER Name
        Node display name or node ID (exact match). Returns the single matching node.

        .PARAMETER Filter
        Search filter applied across all node properties (case-insensitive regex match).

        .PARAMETER Format
        Output format: table (default) or json.

        .PARAMETER Output
        File path to export results when Format is 'json'. Ignored for 'table' format.

        .EXAMPLE
        Get-KeeperEnterpriseNode
        Lists all enterprise nodes in table format.

        .EXAMPLE
        Get-KeeperEnterpriseNode -Name "Sales"
        Returns the enterprise node named "Sales".

        .EXAMPLE
        Get-KeeperEnterpriseNode -Filter "marketing"
        Returns all enterprise nodes whose properties match "marketing".

        .EXAMPLE
        Get-KeeperEnterpriseNode -Format json -Output "nodes.json"
        Exports all enterprise nodes to a JSON file.
    #>
    [CmdletBinding()]
    Param (
        [Parameter()][string] $Name,
        [Parameter()][string] $Filter,
        [Parameter()][ValidateSet('table', 'json')][string] $Format = 'table',
        [Parameter()][string] $Output
    )

    if ($Name) { $Name = $Name.Trim() }
    if ($Filter) { $Filter = $Filter.Trim() }

    $nodes = Get-EnterpriseNode
    if (-not $nodes) {
        Write-Warning "No enterprise nodes found."
        return @()
    }

    if ($Name) {
        $nodes = $nodes | Where-Object { ($_.DisplayName -eq $Name) -or ($_.Id.ToString() -eq $Name) }
    }

    if ($Filter) {
        $filterLower = $Filter.ToLower()
        $nodes = $nodes | Where-Object {
            $text = ($_.PSObject.Properties.Value | ForEach-Object { "$_" }) -join ' '
            $text -match [regex]::Escape($filterLower)
        }
    }

    $result = @($nodes)
    if ($result.Count -eq 0 -and ($Name -or $Filter)) {
        Write-Host "No matching enterprise nodes found." -ForegroundColor Yellow
        return @()
    }

    if ($Format -eq 'json') {
        $json = $result | ConvertTo-Json -Depth 5
        if ($Output) {
            Set-Content -Path $Output -Value $json -Encoding utf8
            Write-Host "Results exported to: $Output" -ForegroundColor Green
        } else {
            return $json
        }
    } else {
        return $result
    }
}
New-Alias -Name ken -Value Get-KeeperEnterpriseNode

function Get-KeeperAuditReport {
    <#
    .SYNOPSIS
    Run an enterprise audit trail report.

    .DESCRIPTION
    Retrieves audit event reports from the Keeper enterprise.
    Supports raw events, consolidated reports (span/day/week/month/hour),
    and dimension lookups. Results can be filtered by event type, username,
    date range, record UID, shared folder UID, node, or IP address.

    .PARAMETER ReportType
    Report type: raw (default), span, day, week, month, hour, dim.

    .PARAMETER Limit
    Maximum number of returned events (default 100).

    .PARAMETER Order
    Sort order: desc (default) or asc.

    .PARAMETER Created
    Date filter. Predefined: today, yesterday, last_7_days, last_30_days,
    month_to_date, last_month, year_to_date, last_year.
    Custom: ">2025-01-01", "<2025-06-01", "between 2025-01-01 and 2025-06-01",
    or an exact date like "2025-03-15".

    .PARAMETER EventType
    Filter by one or more audit event type names (e.g. login, logout).

    .PARAMETER Username
    Filter by one or more usernames (event originator).

    .PARAMETER ToUsername
    Filter by target username.

    .PARAMETER RecordUid
    Filter by one or more record UIDs.

    .PARAMETER SharedFolderUid
    Filter by one or more shared folder UIDs.

    .PARAMETER NodeId
    Filter by one or more node names or IDs.

    .PARAMETER IpAddress
    Filter by one or more IP addresses.

    .PARAMETER Aggregate
    Aggregate columns for consolidated reports: occurrences, first_created, last_created.

    .PARAMETER Columns
    Group-by columns: audit_event_type, username, ip_address, keeper_version,
    to_username, record_uid, shared_folder_uid, team_uid.

    .PARAMETER Format
    Output format: table (default), csv, json.

    .EXAMPLE
    Get-KeeperAuditReport
    Returns the last 100 raw audit events.

    .EXAMPLE
    Get-KeeperAuditReport -EventType login -Username user@company.com -Created last_7_days
    Returns login events for a specific user in the last 7 days.

    .EXAMPLE
    Get-KeeperAuditReport -ReportType span -Columns username,audit_event_type -Aggregate occurrences -Created last_30_days
    Returns a consolidated report of event counts per user per event type over 30 days.

    .EXAMPLE
    Get-KeeperAuditReport -ReportType dim
    Lists all available audit event dimensions (event types, versions, IPs, etc.).

    .EXAMPLE
    Get-KeeperAuditReport -Created "between 2025-01-01 and 2025-06-01" -Format csv
    Returns raw events in a date range, formatted as CSV.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Position=0, ValueFromRemainingArguments=$true)]
        [string[]] $FilterPattern,

        [Parameter()][ValidateSet('raw','span','day','week','month','hour','dim')]
        [string] $ReportType = 'raw',

        [Parameter()][int] $Limit = 100,

        [Parameter()][ValidateSet('asc','desc')]
        [string] $Order,

        [Parameter()][string] $Created,

        [Parameter()][string[]] $EventType,

        [Parameter()][string[]] $Username,

        [Parameter()][string] $ToUsername,

        [Parameter()][string[]] $RecordUid,

        [Parameter()][string[]] $SharedFolderUid,

        [Parameter()][string[]] $NodeId,

        [Parameter()][string[]] $IpAddress,

        [Parameter()][string[]] $Aggregate,

        [Parameter()][string[]] $Columns,

        [Parameter()][switch] $MatchAll,

        [Parameter()][switch] $UseRegex,

        [Parameter()][ValidateSet('table','csv','json')]
        [string] $Format = 'table'
    )

    try {
        [Enterprise]$enterprise = getEnterprise
        $auth = $enterprise.loader.Auth
    }
    catch {
        Write-Error "Failed to load enterprise context: $($_.Exception.Message)" -ErrorAction Stop
    }

    if ($Limit -le 0) {
        Write-Error "Limit must be greater than 0." -ErrorAction Stop
    }

    function TryParseUtcDate([string] $text, [ref] $epochInSec) {
        $epochInSec.Value = 0
        $parsed = 0L
        if ([long]::TryParse($text, [ref]$parsed)) {
            $nowInCentis = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() / 10
            if ($parsed -gt $nowInCentis) {
                $epochInSec.Value = [long]($parsed / 1000)
            } else {
                $epochInSec.Value = $parsed
            }
            return $true
        }
        $dtStyle = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
        $dto = [DateTimeOffset]::MinValue
        if ([DateTimeOffset]::TryParse($text, [System.Globalization.CultureInfo]::InvariantCulture, $dtStyle, [ref]$dto)) {
            $epochInSec.Value = $dto.ToUnixTimeSeconds()
            return $true
        }
        return $false
    }

    function ParsePattern([string] $pattern, [bool] $useRegex = $false) {
        if ([string]::IsNullOrEmpty($pattern)) { return $null }

        $filter = [PSCustomObject]@{
            Type          = $null
            Pattern       = $null
            IsNegated     = $false
            CompiledRegex = $null
        }
        $workingPattern = $pattern

        if ($workingPattern.StartsWith('not:', [System.StringComparison]::OrdinalIgnoreCase)) {
            $filter.IsNegated = $true
            $workingPattern = $workingPattern.Substring(4)
        }

        if ($workingPattern.StartsWith('regex:', [System.StringComparison]::OrdinalIgnoreCase)) {
            $filter.Type = 'Regex'
            $filter.Pattern = $workingPattern.Substring(6)
        }
        elseif ($workingPattern.StartsWith('exact:', [System.StringComparison]::OrdinalIgnoreCase)) {
            $filter.Type = 'Exact'
            $filter.Pattern = $workingPattern.Substring(6)
        }
        elseif ($useRegex) {
            $filter.Type = 'Regex'
            $filter.Pattern = $workingPattern
        }
        else {
            $filter.Type = 'Substring'
            $filter.Pattern = $workingPattern
        }

        if ($filter.Type -eq 'Regex') {
            try {
                $filter.CompiledRegex = [regex]::new($filter.Pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
            } catch {
                Write-Host "Error: Invalid regex pattern '$($filter.Pattern)', skipping this filter"
                return $null
            }
        }

        return $filter
    }

    function MatchesPattern([System.Collections.Generic.Dictionary[string,object]] $eventData, $filter) {
        if ($null -eq $filter)    { return $true }
        if ($null -eq $eventData) { return $false }

        $matched = $false
        foreach ($kvp in $eventData.GetEnumerator()) {
            $value = if ($null -ne $kvp.Value) { $kvp.Value.ToString() } else { '' }

            switch ($filter.Type) {
                'Regex' {
                    if ($null -ne $filter.CompiledRegex -and $filter.CompiledRegex.IsMatch($value)) {
                        $matched = $true
                    }
                }
                'Exact' {
                    if ([string]::Equals($value, $filter.Pattern, [System.StringComparison]::OrdinalIgnoreCase)) {
                        $matched = $true
                    }
                }
                'Substring' {
                    if ($value.IndexOf($filter.Pattern, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                        $matched = $true
                    }
                }
            }
            if ($matched) { break }
        }
        if ($filter.IsNegated) {
            return (-not $matched)
        }
        return $matched
    }

    function ApplyFilters([System.Collections.Generic.Dictionary[string,object]] $eventData, $filters, [bool] $matchAll) {
        if (-not $filters -or $filters.Count -eq 0) { return $true }
        if ($matchAll) {
            foreach ($f in $filters) {
                if (-not (MatchesPattern $eventData $f)) { return $false }
            }
            return $true
        } else {
            foreach ($f in $filters) {
                if (MatchesPattern $eventData $f) { return $true }
            }
            return $false
        }
    }

    function FormatEpochValue($value, [string] $format) {
        if ($null -eq $value) { return $value }
        $epoch = 0L
        if ([long]::TryParse($value.ToString(), [ref]$epoch)) {
            try {
                return [DateTimeOffset]::FromUnixTimeSeconds($epoch).ToString($format)
            } catch {
                return $value
            }
        }
        return $value
    }

    $filter = New-Object KeeperSecurity.Enterprise.AuditLogCommands.ReportFilter

    if ($Created) {
        $predefinedFilters = @('today','yesterday','last_7_days','last_30_days','month_to_date','last_month','year_to_date','last_year')
        $createdLower = $Created.Trim().ToLowerInvariant()

        if ($createdLower -in $predefinedFilters) {
            $filter.Created = $createdLower
        }
        elseif ($Created.StartsWith('>') -or $Created.StartsWith('<')) {
            $isGreater = $Created[0] -eq '>'
            $rest = $Created.Substring(1)
            $hasEqual = $rest.StartsWith('=')
            if ($hasEqual) { $rest = $rest.Substring(1) }

            $dt = 0L
            if (TryParseUtcDate $rest.Trim() ([ref]$dt)) {
                $cf = New-Object KeeperSecurity.Enterprise.AuditLogCommands.CreatedFilter
                if ($isGreater) {
                    $cf.Min = $dt
                    $cf.ExcludeMin = -not $hasEqual
                } else {
                    $cf.Max = $dt
                    $cf.ExcludeMax = -not $hasEqual
                }
                $filter.Created = $cf
            } else {
                Write-Error "Could not parse date: $rest" -ErrorAction Stop
            }
        }
        elseif ($Created -match '(?i)^\s*between\s+(\S+)\s+and\s+(.+)$') {
            $fromEpoch = 0L; $toEpoch = 0L
            $fromOk = TryParseUtcDate $Matches[1] ([ref]$fromEpoch)
            $toOk   = TryParseUtcDate $Matches[2].Trim() ([ref]$toEpoch)
            if ($fromOk -and $toOk) {
                $cf = New-Object KeeperSecurity.Enterprise.AuditLogCommands.CreatedFilter
                $cf.Min = $fromEpoch
                $cf.Max = $toEpoch
                $cf.ExcludeMin = $false
                $cf.ExcludeMax = $true
                $filter.Created = $cf
            } else {
                Write-Error "Could not parse date range: $Created" -ErrorAction Stop
            }
        }
        else {
            if ($Created -match '^\d{4}-\d{2}-\d{2}$') {
                $exactDate = [DateTimeOffset]::MinValue
                $dtStyle = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
                if ([DateTimeOffset]::TryParseExact($Created, 'yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture, $dtStyle, [ref]$exactDate)) {
                    $dayStart = [DateTimeOffset]::new($exactDate.Year, $exactDate.Month, $exactDate.Day, 0, 0, 0, [TimeSpan]::Zero)
                    $nextDay = $dayStart.AddDays(1)
                    $cf = New-Object KeeperSecurity.Enterprise.AuditLogCommands.CreatedFilter
                    $cf.Min = $dayStart.ToUnixTimeSeconds()
                    $cf.Max = $nextDay.ToUnixTimeSeconds()
                    $cf.ExcludeMin = $false
                    $cf.ExcludeMax = $true
                    $filter.Created = $cf
                } else {
                    Write-Error "Could not parse date: $Created" -ErrorAction Stop
                }
            } else {
                $exactEpoch = 0L
                if (TryParseUtcDate $Created ([ref]$exactEpoch)) {
                    $cf = New-Object KeeperSecurity.Enterprise.AuditLogCommands.CreatedFilter
                    $cf.Min = $exactEpoch
                    $cf.Max = $exactEpoch + 1
                    $cf.ExcludeMin = $false
                    $cf.ExcludeMax = $true
                    $filter.Created = $cf
                } else {
                    Write-Error "Could not parse date: $Created" -ErrorAction Stop
                }
            }
        }
    }

    if ($EventType)       { $filter.EventTypes      = $EventType }
    if ($Username)        { $filter.Username        = $Username }
    if ($ToUsername)      { $filter.ToUsername      = @($ToUsername) }
    if ($RecordUid)       { $filter.RecordUid       = $RecordUid }
    if ($SharedFolderUid) { $filter.SharedFolderUid = $SharedFolderUid }
    if ($IpAddress) {
        $ipProp = $filter.GetType().GetProperty('IpAddress')
        if ($ipProp) {
            $ipProp.SetValue($filter, [string[]]$IpAddress)
        } else {
            Write-Warning "Failed to apply IpAddress filter."
        }
    }

    if ($NodeId) {
        $nodeProp = $filter.GetType().GetProperty('NodeId')
        if ($nodeProp) {
            $resolvedNodeIds = [System.Collections.Generic.List[long]]::new()
            foreach ($n in $NodeId) {
                try {
                    $resolved = $null
                    if ($n -match '^\d+$') {
                        $nodeIdLong = [long]$n
                        $outNode = $null
                        if ($enterprise.enterpriseData.TryGetNode($nodeIdLong, [ref]$outNode)) {
                            $resolved = $outNode
                        }
                    }
                    if ($null -eq $resolved) {
                        $nodeMatches = @($enterprise.enterpriseData.Nodes | Where-Object {
                            [string]::Equals($_.DisplayName, $n, [System.StringComparison]::OrdinalIgnoreCase)
                        })
                        if ($nodeMatches.Count -eq 1) {
                            $resolved = $nodeMatches[0]
                        } elseif ($nodeMatches.Count -gt 1) {
                            throw [System.Exception]::new("There are $($nodeMatches.Count) nodes with name `"$n`". Use Node ID instead of Node name.")
                        } else {
                            throw [System.Exception]::new("Node `"$n`" is not found.")
                        }
                    }
                    if (-not $resolvedNodeIds.Contains($resolved.Id)) {
                        $resolvedNodeIds.Add($resolved.Id)
                    }
                } catch {
                    Write-Warning "Could not resolve node '$n': $($_.Exception.Message)"
                }
            }
            if ($resolvedNodeIds.Count -gt 0) {
                $nodeProp.SetValue($filter, [long[]]$resolvedNodeIds.ToArray())
            } else {
                Write-Error "No valid node IDs found." -ErrorAction Stop
            }
        } else {
            Write-Warning "Failed to apply NodeId filter."
        }
    }

    if ($ReportType -eq 'dim') {
        $results = [System.Collections.Generic.List[PSCustomObject]]::new()
        if (-not $Columns -or $Columns.Count -eq 0) {
            Write-Error "ReportType 'dim' requires at least one value in -Columns." -ErrorAction Stop
        }

        $dimRq = New-Object KeeperSecurity.Commands.GetAuditEventDimensionsCommand
        $columnsProp = $dimRq.GetType().GetProperty('Columns')
        if ($null -eq $columnsProp) {
            Write-Error "Loaded KeeperSdk version does not support audit dimension column selection." -ErrorAction Stop
        }
        $columnsProp.SetValue($dimRq, [string[]]$Columns)

        try {
            $dimResponse = $auth.ExecuteAuthCommand($dimRq, [KeeperSecurity.Commands.GetAuditEventDimensionsResponse], $true).GetAwaiter().GetResult()
            $dimRs = [KeeperSecurity.Commands.GetAuditEventDimensionsResponse]$dimResponse
        } catch {
            Write-Error "Failed to retrieve audit dimensions: $($_.Exception.Message)" -ErrorAction Stop
        }

        $dims = $dimRs.Dimensions
        if ($null -eq $dims) {
            Write-Host "No dimension data returned."
            return
        }

        $hasData = $false
        $dimensionLimit = $Limit
        $dimensionSections = @(
            @{ Property = 'AuditEventTypes'; Title = 'Audit Event Types';   Selector = { param($d) $d | Select-Object @{N='ID';E={$_.Id}}, @{N='Name';E={$_.Name}}, @{N='Category';E={$_.Category}}, @{N='Critical';E={if($_.Critical){'Yes'}else{''}}} } },
            @{ Property = 'KeeperVersions';  Title = 'Keeper Versions';     Selector = { param($d) $d | Select-Object @{N='VersionID';E={$_.VersionId}}, @{N='TypeID';E={$_.TypeId}}, @{N='TypeName';E={$_.TypeName}}, @{N='Category';E={$_.TypeCategory}} } },
            @{ Property = 'IpAddresses';     Title = 'IP Addresses';        Selector = { param($d) $d | Select-Object @{N='IP';E={$_.IpAddress}}, City, Region, Country, @{N='CountryName';E={$_.CountryName}} } },
            @{ Property = 'GeoLocation';     Title = 'Geo Locations';       Selector = { param($d) $d | Select-Object @{N='GeoLocation';E={$_.GeoLocation}}, City, Region, @{N='CountryCode';E={$_.CountryCode}}, @{N='IpCount';E={$_.IpCount}} } },
            @{ Property = 'Usernames';       Title = 'Usernames';           Selector = { param($d) $d | ForEach-Object { [PSCustomObject]@{ Username = $_ } } } },
            @{ Property = 'NodeIds';         Title = 'Node IDs';            Selector = { param($d) $d | ForEach-Object { [PSCustomObject]@{ NodeID = $_ } } } },
            @{ Property = 'ToUsername';      Title = 'To Usernames';        Selector = { param($d) $d | ForEach-Object { [PSCustomObject]@{ ToUsername = $_ } } } },
            @{ Property = 'FromUsername';    Title = 'From Usernames';      Selector = { param($d) $d | ForEach-Object { [PSCustomObject]@{ FromUsername = $_ } } } },
            @{ Property = 'Channel';         Title = 'Channels';            Selector = { param($d) $d | ForEach-Object { [PSCustomObject]@{ Channel = $_ } } } },
            @{ Property = 'RecordUid';       Title = 'Record UIDs';         Selector = { param($d) $d | ForEach-Object { [PSCustomObject]@{ RecordUID = $_ } } } },
            @{ Property = 'SharedFolderUid'; Title = 'Shared Folder UIDs';  Selector = { param($d) $d | ForEach-Object { [PSCustomObject]@{ SharedFolderUID = $_ } } } },
            @{ Property = 'TeamUid';         Title = 'Team UIDs';           Selector = { param($d) $d | ForEach-Object { [PSCustomObject]@{ TeamUID = $_ } } } }
        )

        foreach ($section in $dimensionSections) {
            $data = $dims.($section.Property)
            if ($data -and $data.Count -gt 0) {
                $hasData = $true
                $items = @(& $section.Selector $data | Select-Object -First $dimensionLimit)
                foreach ($item in $items) {
                    $row = [ordered]@{ Section = $section.Title }
                    foreach ($prop in $item.PSObject.Properties) {
                        $row[$prop.Name] = $prop.Value
                    }
                    $results.Add([PSCustomObject]$row)
                }
            }
        }

        if (-not $hasData) {
            Write-Host "No dimension data returned."
            return
        }

        switch ($Format) {
            'json' { $results | ConvertTo-Json -Depth 5 }
            'csv'  { $results | ConvertTo-Csv -NoTypeInformation }
            default { $results | Format-Table -AutoSize }
        }
        return
    }

    $rq = New-Object KeeperSecurity.Enterprise.AuditLogCommands.GetAuditEventReportsCommand
    $rq.Filter = $filter
    $rq.ReportType = $ReportType
    $rq.Limit = $Limit
    if ($Order -eq 'asc') {
        $rq.Order = 'ascending'
    }
    if ($Aggregate -and $Aggregate.Count -gt 0) { $rq.Aggregate = $Aggregate }
    if ($Columns -and $Columns.Count -gt 0)     { $rq.Columns   = $Columns }

    try {
        $response = $auth.ExecuteAuthCommand($rq, [KeeperSecurity.Enterprise.AuditLogCommands.GetAuditEventReportsResponse], $true).GetAwaiter().GetResult()
        $rs = [KeeperSecurity.Enterprise.AuditLogCommands.GetAuditEventReportsResponse]$response
    } catch {
        Write-Error "Failed to retrieve audit report: $($_.Exception.Message)" -ErrorAction Stop
    }

    if (-not $rs.Events -or $rs.Events.Count -eq 0) {
        Write-Host "No audit events found."
        return
    }

    $allEvents = $rs.Events

    function getEventValue([System.Collections.Generic.Dictionary[string,object]] $evt, [string] $key) {
        if ($evt -is [System.Collections.IDictionary] -and $evt.ContainsKey($key) -and $null -ne $evt[$key]) { return $evt[$key].ToString() }
        return ''
    }

    $filteredEvents = $allEvents
    if ($FilterPattern -and $FilterPattern.Count -gt 0) {
        $patternFilters = [System.Collections.Generic.List[PSCustomObject]]::new()
        foreach ($fp in $FilterPattern) {
            $pf = ParsePattern $fp $UseRegex.IsPresent
            if ($null -ne $pf) { $patternFilters.Add($pf) }
        }
        if ($patternFilters.Count -eq 0) {
            Write-Warning "No valid filter patterns were provided. Showing unfiltered results."
        }
        else {
        $filteredEvents = [System.Collections.Generic.List[System.Collections.Generic.Dictionary[string,object]]]::new()
        foreach ($evt in $allEvents) {
            if (ApplyFilters $evt $patternFilters $MatchAll.IsPresent) {
                $filteredEvents.Add($evt)
            }
        }
        if ($filteredEvents.Count -eq 0) {
            Write-Host "No events matched the filter pattern(s)."
            return
        }
        }
    }

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    if ($ReportType -eq 'raw') {
        $auditEventTypes = @{}
        try {
            $evtTypes = [KeeperSecurity.Enterprise.AuditLogExtensions]::GetAvailableEvents($auth).GetAwaiter().GetResult()
            if ($evtTypes) {
                foreach ($e in $evtTypes) { $auditEventTypes[$e.Name] = $e }
            }
        } catch {
            Write-Verbose "Could not load audit event type definitions: $($_.Exception.Message)"
        }

        foreach ($evt in $filteredEvents) {
            $eventName = getEventValue $evt 'audit_event_type'
            if (-not $eventName) { continue }

            $message = ''
            if ($auditEventTypes.ContainsKey($eventName) -and $auditEventTypes[$eventName].SyslogMessage) {
                $message = $auditEventTypes[$eventName].SyslogMessage
                while ($message -match '\$\{(\w+)\}') {
                    $paramName = $Matches[1]
                    $paramValue = getEventValue $evt $paramName
                    $message = $message.Replace('${' + $paramName + '}', $paramValue)
                }
            }

            $createdRaw = getEventValue $evt 'created'
            $createdStr = if ($createdRaw) { FormatEpochValue $createdRaw 'G' } else { '' }

            $results.Add([PSCustomObject]@{
                Created  = $createdStr
                Username = getEventValue $evt 'username'
                Event    = $eventName
                Message  = $message
            })
        }
    } else {
        $reportColumns = @()
        if ($Aggregate) { $reportColumns += $Aggregate }
        if ($Columns)   { $reportColumns += $Columns }

        if ($reportColumns.Count -eq 0) {
            $reportColumns = @('occurrences')
        }

        $dateColumns = @('last_created', 'first_created')
        foreach ($evt in $filteredEvents) {
            $row = [ordered]@{}
            foreach ($col in $reportColumns) {
                $val = $null
                if ($evt.ContainsKey($col)) {
                    $val = $evt[$col]
                    if ($col -in $dateColumns -and $null -ne $val) {
                        $val = FormatEpochValue $val 'g'
                    }
                }
                $row[$col] = $val
            }
            $results.Add([PSCustomObject]$row)
        }
    }

    switch ($Format) {
        'json' { $results | ConvertTo-Json -Depth 5 }
        'csv'  { $results | ConvertTo-Csv -NoTypeInformation }
        default { $results | Format-Table -AutoSize }
    }
}
New-Alias -Name kar -Value Get-KeeperAuditReport

