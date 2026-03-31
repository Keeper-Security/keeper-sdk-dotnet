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

function Export-KeeperAuditLog {
    <#
    .SYNOPSIS
    Export the enterprise audit log to an external target.

    .DESCRIPTION
    Exports enterprise audit events to external targets such as JSON files,
    Syslog files, Splunk HEC, Sumo Logic, Azure Log Analytics, or Syslog
    over network (TCP/UDP). Supports incremental export using the
    -LastEventTime parameter and anonymization of usernames.

    Events are fetched in ascending chronological order and deduplicated
    to ensure no event is exported more than once.

    .PARAMETER Target
    Export target: json, syslog, splunk, sumo, azure-la, syslog-port.

    .PARAMETER Record
    Keeper record title or UID used to store export configuration and
    incremental state. If omitted, the cmdlet looks for the default record
    title for the selected target.

    .PARAMETER FilePath
    Output file path. Required for json and syslog targets.
    For syslog, if the path ends with .gz, output is gzip-compressed.

    .PARAMETER Url
    Endpoint URL. Required for splunk (HEC endpoint, e.g.
    https://splunk.company.com:8088/services/collector) and sumo
    (HTTP Collector URL).

    .PARAMETER Token
    Authentication token. Required for splunk (HEC token).

    .PARAMETER SyslogHost
    Syslog server hostname. Required for syslog-port target.

    .PARAMETER SyslogPort
    Syslog server port number. Required for syslog-port target.

    .PARAMETER SyslogProtocol
    Transport protocol for syslog-port: tcp (default) or udp.

    .PARAMETER UseSsl
    Use SSL/TLS for syslog-port TCP connections.

    .PARAMETER OctetCounting
    Use octet counting framing for syslog-port (RFC 5425).

    .PARAMETER WorkspaceId
    Azure Log Analytics workspace ID. Required for azure-la target.

    .PARAMETER WorkspaceKey
    Azure Log Analytics primary or secondary key. Required for azure-la target.

    .PARAMETER SharedFolderUid
    Filter by one or more shared folder UIDs.

    .PARAMETER NodeId
    Filter by one or more node IDs.

    .PARAMETER Days
    Maximum event age in days. Overrides LastEventTime.

    .PARAMETER LastEventTime
    Unix epoch timestamp of last exported event for incremental export.
    Use the LastEventTime from a previous export result to continue
    from where you left off. Default is 0 (export all available events).

    .PARAMETER Anonymize
    Replace email and username with enterprise user ID in exported events.
    Users not found are shown as DELETED-<md5hash>.

    .PARAMETER IgnoreCertificateErrors
    Ignore SSL/TLS certificate validation errors. Useful for Splunk
    deployments with self-signed certificates.

    .EXAMPLE
    Export-KeeperAuditLog -Target json
    Uses the default JSON audit-log record if it exists, or prompts to create
    one and stores the JSON file path for subsequent incremental exports.

    .EXAMPLE
    $result = Export-KeeperAuditLog -Target json -FilePath 'events.json' -Days 7
    Export-KeeperAuditLog -Target json -FilePath 'events.json' -LastEventTime $result.LastEventTime
    First exports last 7 days, then incrementally exports new events.

    .EXAMPLE
    Export-KeeperAuditLog -Target splunk -Url 'https://splunk:8088/services/collector' -Token 'hec-token' -IgnoreCertificateErrors
    Exports audit events to Splunk HEC with self-signed certificate support.

    .EXAMPLE
    Export-KeeperAuditLog -Target syslog -FilePath 'audit.log.gz'
    Exports audit events to a gzip-compressed syslog file.

    .EXAMPLE
    Export-KeeperAuditLog -Target azure-la -WorkspaceId 'ws-id' -WorkspaceKey 'ws-key'
    Exports audit events to Azure Log Analytics.

    .EXAMPLE
    Export-KeeperAuditLog -Target syslog-port -SyslogHost 'syslog.company.com' -SyslogPort 514 -UseSsl
    Exports audit events to a syslog server over TCP with TLS.

    .EXAMPLE
    Export-KeeperAuditLog -Target json -FilePath 'anon_audit.json' -Anonymize
    Exports anonymized audit events to a JSON file.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [ValidateSet('json','syslog','splunk','sumo','azure-la','syslog-port')]
        [string] $Target,

        [Parameter()][string] $Record,

        [Parameter()][string] $FilePath,

        [Parameter()][string] $Url,

        [Parameter()][string] $Token,

        [Parameter()][string] $SyslogHost,

        [Parameter()][int] $SyslogPort,

        [Parameter()][ValidateSet('tcp','udp')]
        [string] $SyslogProtocol = 'tcp',

        [Parameter()][switch] $UseSsl,

        [Parameter()][switch] $OctetCounting,

        [Parameter()][string] $WorkspaceId,

        [Parameter()][string] $WorkspaceKey,

        [Parameter()][string[]] $SharedFolderUid,

        [Parameter()][long[]] $NodeId,

        [Parameter()][int] $Days,

        [Parameter()][long] $LastEventTime = 0,

        [Parameter()][switch] $Anonymize,

        [Parameter()][switch] $IgnoreCertificateErrors
    )

    try {
        [Enterprise]$enterprise = getEnterprise
        $auth = $enterprise.loader.Auth
    }
    catch {
        Write-Error "Failed to load Keeper context: $($_.Exception.Message)" -ErrorAction Stop
    }

    function getDefaultRecordTitle([string] $exportTarget) {
        switch ($exportTarget) {
            'splunk'     { 'Audit Log: Splunk' }
            'syslog'     { 'Audit Log: Syslog' }
            'syslog-port' { 'Audit Log: Syslog Port' }
            'sumo'       { 'Audit Log: Sumologic' }
            'azure-la'   { 'Audit Log: Azure Log Analytics' }
            default      { 'Audit Log: JSON' }
        }
    }

    function getRecordField($keeperRecord, [string] $fieldName, [string] $fieldLabel = '') {
        if ($null -eq $keeperRecord) { return $null }

        if ($keeperRecord -is [KeeperSecurity.Vault.PasswordRecord]) {
            switch ($fieldName) {
                'login'    { return $keeperRecord.Login }
                'password' { return $keeperRecord.Password }
                'url'      { return $keeperRecord.Link }
                default {
                    $customName = if ($fieldLabel) { $fieldLabel } else { $fieldName }
                    $cf = $keeperRecord.Custom | Where-Object { $_.Name -ieq $customName } | Select-Object -First 1
                    if ($cf) { return $cf.Value }
                }
            }
            return $null
        }

        if ($keeperRecord -is [KeeperSecurity.Vault.TypedRecord]) {
            $searchFieldName = $fieldName
            $searchFieldLabel = $fieldLabel
            if (-not $searchFieldLabel -and $fieldName -notin @('login','password','url')) {
                $searchFieldName = 'text'
                $searchFieldLabel = $fieldName
            }

            $field = $keeperRecord.Fields |
                Where-Object { $_.FieldName -ieq $searchFieldName -and ([string]::IsNullOrEmpty($searchFieldLabel) -or $_.FieldLabel -ieq $searchFieldLabel) } |
                Select-Object -First 1
            if (-not $field) {
                $field = $keeperRecord.Custom |
                    Where-Object { $_.FieldName -ieq $searchFieldName -and ([string]::IsNullOrEmpty($searchFieldLabel) -or $_.FieldLabel -ieq $searchFieldLabel) } |
                    Select-Object -First 1
            }
            if ($field) {
                $value = $field.ObjectValue
                if ($value -is [System.Collections.IEnumerable] -and $value -isnot [string]) {
                    return ($value | ForEach-Object { $_.ToString() }) -join ', '
                }
                return $value
            }
        }

        return $null
    }

    function setRecordField($keeperRecord, [string] $fieldName, $fieldValue, [string] $fieldLabel = '') {
        if ($null -eq $keeperRecord) { return $false }

        $currentValue = getRecordField $keeperRecord $fieldName $fieldLabel
        $newValue = if ($null -eq $fieldValue) { '' } else { [string]$fieldValue }
        $oldValue = if ($null -eq $currentValue) { '' } else { [string]$currentValue }
        if ($oldValue -ceq $newValue) {
            return $false
        }

        if ($keeperRecord -is [KeeperSecurity.Vault.PasswordRecord]) {
            switch ($fieldName) {
                'login'    { $keeperRecord.Login = $fieldValue; return $true }
                'password' { $keeperRecord.Password = $fieldValue; return $true }
                'url'      { $keeperRecord.Link = $fieldValue; return $true }
                default {
                    $customName = if ($fieldLabel) { $fieldLabel } else { $fieldName }
                    if ([string]::IsNullOrEmpty([string]$fieldValue)) {
                        $keeperRecord.DeleteCustomField($customName) | Out-Null
                    }
                    else {
                        $keeperRecord.SetCustomField($customName, [string]$fieldValue) | Out-Null
                    }
                    return $true
                }
            }
        }

        if ($keeperRecord -is [KeeperSecurity.Vault.TypedRecord]) {
            $typedFieldName = $fieldName
            $typedFieldLabel = $fieldLabel
            if (-not $typedFieldLabel -and $fieldName -notin @('login','password','url')) {
                $typedFieldName = 'text'
                $typedFieldLabel = $fieldName
            }

            $recordTypeField = New-Object KeeperSecurity.Vault.RecordTypeField $typedFieldName, $typedFieldLabel
            [KeeperSecurity.Vault.ITypedField]$typedField = $null
            if (-not [KeeperSecurity.Vault.VaultDataExtensions]::FindTypedField($keeperRecord, $recordTypeField, [ref]$typedField)) {
                if (-not [string]::IsNullOrEmpty([string]$fieldValue)) {
                    $typedField = [KeeperSecurity.Vault.VaultDataExtensions]::CreateTypedField($typedFieldName, $typedFieldLabel)
                    if ($typedField) {
                        $keeperRecord.Custom.Add($typedField)
                    }
                }
            }

            if ($typedField) {
                if ([string]::IsNullOrEmpty([string]$fieldValue)) {
                    $typedField.DeleteValueAt(0)
                }
                else {
                    if ($typedFieldName -eq 'text') {
                        $typedField.ObjectValue = [string]$fieldValue
                    }
                    else {
                        $typedField.ObjectValue = $fieldValue
                    }
                }
            }
            return $true
        }

        return $false
    }

    function resolveAuditLogRecord([string] $recordIdentifier) {
        if ([string]::IsNullOrWhiteSpace($recordIdentifier)) { return $null }

        [KeeperSecurity.Vault.KeeperRecord]$keeperRecord = $null
        if ($vault.TryGetKeeperRecord($recordIdentifier, [ref]$keeperRecord)) {
            return $keeperRecord
        }

        $exactMatches = @($vault.KeeperRecords | Where-Object { $_.Title -eq $recordIdentifier })
        if ($exactMatches.Count -gt 0) {
            return $exactMatches[0]
        }

        return $null
    }

    function createAuditLogRecord([string] $recordTitle) {
        $keeperRecord = New-Object KeeperSecurity.Vault.TypedRecord 'login'
        try {
            [KeeperSecurity.Utils.RecordTypesUtils]::AdjustTypedRecord($vault, $keeperRecord)
        }
        catch {}

        $keeperRecord.Title = $recordTitle
        return $keeperRecord
    }

    function saveAuditLogRecord($keeperRecord) {
        if ($null -eq $keeperRecord) { return $null }
        if ([string]::IsNullOrEmpty($keeperRecord.Uid)) {
            return $vault.CreateRecord($keeperRecord, $Script:Context.CurrentFolder).GetAwaiter().GetResult()
        }
        $vault.UpdateRecord($keeperRecord).GetAwaiter().GetResult() | Out-Null
        return $keeperRecord
    }

    function normalizeSplunkUrl([string] $inputUrl) {
        if ([string]::IsNullOrWhiteSpace($inputUrl)) { return $inputUrl }
        $trimmed = $inputUrl.Trim()
        if ($trimmed -match '^https?://') {
            if ($trimmed -match '/services/collector/?$') {
                return $trimmed.TrimEnd('/')
            }
            return ($trimmed.TrimEnd('/') + '/services/collector')
        }
        return "https://$($trimmed.TrimEnd('/'))/services/collector"
    }

    $hasDirectTargetConfig = switch ($Target) {
        'json'        { -not [string]::IsNullOrWhiteSpace($FilePath) }
        'syslog'      { -not [string]::IsNullOrWhiteSpace($FilePath) }
        'splunk'      { -not [string]::IsNullOrWhiteSpace($Url) -and -not [string]::IsNullOrWhiteSpace($Token) }
        'sumo'        { -not [string]::IsNullOrWhiteSpace($Url) }
        'azure-la'    { -not [string]::IsNullOrWhiteSpace($WorkspaceId) -and -not [string]::IsNullOrWhiteSpace($WorkspaceKey) }
        'syslog-port' { -not [string]::IsNullOrWhiteSpace($SyslogHost) -and $SyslogPort -gt 0 }
    }

    $useRecordFlow = $PSBoundParameters.ContainsKey('Record') -or (-not $hasDirectTargetConfig)
    $configRecord = $null
    $pendingRecordSave = $false
    $resolvedUseSsl = $UseSsl.IsPresent
    $resolvedOctetCounting = $OctetCounting.IsPresent
    if ($useRecordFlow) {
        try {
            [KeeperSecurity.Vault.VaultOnline]$vault = getVault
        }
        catch {
            Write-Error "Failed to load Keeper vault context: $($_.Exception.Message)" -ErrorAction Stop
        }

        $defaultRecordTitle = getDefaultRecordTitle $Target
        $recordIdentifier = if ($Record) { $Record } else { $defaultRecordTitle }
        $configRecord = resolveAuditLogRecord $recordIdentifier

        if (-not $configRecord -and -not $PSBoundParameters.ContainsKey('Record')) {
            $answer = Read-Host 'Do you want to create a Keeper record to store audit log settings? [y/n]'
            if ($answer -match '^(y|yes)$') {
                $recordTitle = Read-Host "Choose the title for audit log record [Default: $defaultRecordTitle]"
                if ([string]::IsNullOrWhiteSpace($recordTitle)) {
                    $recordTitle = $defaultRecordTitle
                }
                $configRecord = createAuditLogRecord $recordTitle
                $pendingRecordSave = $true
            }
        }
        elseif (-not $configRecord -and $PSBoundParameters.ContainsKey('Record')) {
            $answer = Read-Host 'Do you want to create a Keeper record to store audit log settings? [y/n]'
            if ($answer -match '^(y|yes)$') {
                $recordTitle = Read-Host "Choose the title for audit log record [Default: $defaultRecordTitle]"
                if ([string]::IsNullOrWhiteSpace($recordTitle)) {
                    $recordTitle = if ($Record) { $Record } else { $defaultRecordTitle }
                }
                $configRecord = createAuditLogRecord $recordTitle
                $pendingRecordSave = $true
            }
            else {
                Write-Error "Record not found: $Record" -ErrorAction Stop
            }
        }
    }

    if ($configRecord) {
        switch ($Target) {
            'json' {
                if ([string]::IsNullOrWhiteSpace($FilePath)) {
                    $FilePath = [string](getRecordField $configRecord 'login')
                }
                if ([string]::IsNullOrWhiteSpace($FilePath)) {
                    $FilePath = Read-Host 'JSON file name'
                }
            }
            'syslog' {
                if ([string]::IsNullOrWhiteSpace($FilePath)) {
                    $FilePath = [string](getRecordField $configRecord 'login')
                }
                if ([string]::IsNullOrWhiteSpace($FilePath)) {
                    Write-Host 'Enter filename for syslog messages.'
                    $FilePath = Read-Host 'Syslog file name'
                    if ($FilePath -and -not $FilePath.EndsWith('.gz', [System.StringComparison]::OrdinalIgnoreCase)) {
                        $gzipAnswer = Read-Host 'Gzip messages? (y/N)'
                        if ($gzipAnswer -match '^(y|yes)$') {
                            $FilePath += '.gz'
                        }
                    }
                }
            }
            'splunk' {
                if ([string]::IsNullOrWhiteSpace($Url)) {
                    $Url = [string](getRecordField $configRecord 'url')
                }
                if ([string]::IsNullOrWhiteSpace($Url)) {
                    Write-Host 'Enter HTTP Event Collector (HEC) endpoint.'
                    Write-Host 'Example: splunk.company.com:8088 or https://splunk.company.com:8088/services/collector'
                    $Url = normalizeSplunkUrl (Read-Host 'Splunk HEC endpoint')
                }
                else {
                    $Url = normalizeSplunkUrl $Url
                }
                if ([string]::IsNullOrWhiteSpace($Token)) {
                    $Token = [string](getRecordField $configRecord 'password')
                }
                if ([string]::IsNullOrWhiteSpace($Token)) {
                    $Token = Read-Host 'Splunk Token'
                }
            }
            'sumo' {
                if ([string]::IsNullOrWhiteSpace($Url)) {
                    $Url = [string](getRecordField $configRecord 'url')
                }
                if ([string]::IsNullOrWhiteSpace($Url)) {
                    Write-Host 'Enter HTTP Logs Collector URL.'
                    $Url = Read-Host 'HTTP Collector URL'
                }
            }
            'azure-la' {
                if ([string]::IsNullOrWhiteSpace($WorkspaceId)) {
                    $WorkspaceId = [string](getRecordField $configRecord 'login')
                }
                if ([string]::IsNullOrWhiteSpace($WorkspaceId)) {
                    Write-Host 'Enter Azure Log Analytics workspace ID.'
                    $WorkspaceId = Read-Host 'Workspace ID'
                }
                if ([string]::IsNullOrWhiteSpace($WorkspaceKey)) {
                    $WorkspaceKey = [string](getRecordField $configRecord 'password')
                }
                if ([string]::IsNullOrWhiteSpace($WorkspaceKey)) {
                    Write-Host 'Enter Azure Log Analytics primary or secondary key.'
                    $WorkspaceKey = Read-Host 'Key'
                }
            }
            'syslog-port' {
                $storedUrl = [string](getRecordField $configRecord 'url')
                if ($storedUrl) {
                    try {
                        $uri = [System.Uri]$storedUrl
                        if ([string]::IsNullOrWhiteSpace($SyslogHost)) {
                            $SyslogHost = $uri.Host
                        }
                        if ($SyslogPort -le 0) {
                            $SyslogPort = $uri.Port
                        }
                        if (-not $PSBoundParameters.ContainsKey('SyslogProtocol')) {
                            if ($uri.Scheme -eq 'syslogu') {
                                $SyslogProtocol = 'udp'
                            }
                            else {
                                $SyslogProtocol = 'tcp'
                            }
                        }
                        if (-not $resolvedUseSsl -and $uri.Scheme -eq 'syslogs') {
                            $resolvedUseSsl = $true
                        }
                    }
                    catch {}
                }
                if (-not $resolvedOctetCounting) {
                    $storedOctetCounting = [string](getRecordField $configRecord 'is_octet_counting')
                    if ($storedOctetCounting) {
                        $resolvedOctetCounting = $storedOctetCounting -in @('1','true','True')
                    }
                }
                if ([string]::IsNullOrWhiteSpace($SyslogHost)) {
                    Write-Host 'Enter Syslog connection parameters:'
                    $SyslogHost = Read-Host 'Syslog host name'
                }
                if (-not $PSBoundParameters.ContainsKey('SyslogProtocol')) {
                    $connType = Read-Host 'Syslog port type [T]cp/[U]dp. Default TCP'
                    if ($connType -match '^(u|udp)$') {
                        $SyslogProtocol = 'udp'
                    }
                }
                if ($SyslogPort -le 0) {
                    $portValue = Read-Host 'Syslog port number'
                    if ($portValue -match '^\d+$') {
                        $SyslogPort = [int]$portValue
                    }
                }
                if ($SyslogProtocol -eq 'tcp' -and -not $resolvedUseSsl -and -not $storedUrl) {
                    $sslAnswer = Read-Host 'Syslog port requires SSL/TLS (y/N)'
                    if ($sslAnswer -match '^(y|yes)$') {
                        $resolvedUseSsl = $true
                    }
                }
            }
        }

        if (-not $PSBoundParameters.ContainsKey('SharedFolderUid')) {
            $storedSharedFolders = [string](getRecordField $configRecord 'shared_folder_uids')
            if ($storedSharedFolders) {
                $SharedFolderUid = $storedSharedFolders.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
            }
        }
        if (-not $PSBoundParameters.ContainsKey('NodeId')) {
            $storedNodeIds = [string](getRecordField $configRecord 'node_ids')
            if ($storedNodeIds) {
                $NodeId = $storedNodeIds.Split(',') |
                    ForEach-Object { $_.Trim() } |
                    Where-Object { $_ -match '^\d+$' } |
                    ForEach-Object { [long]$_ }
            }
        }
        if (-not $PSBoundParameters.ContainsKey('LastEventTime') -and -not $PSBoundParameters.ContainsKey('Days')) {
            $storedLastEventTime = [string](getRecordField $configRecord 'last_event_time')
            if ($storedLastEventTime -match '^\d+$') {
                $LastEventTime = [long]$storedLastEventTime
            }
        }
    }

    switch ($Target) {
        'json' {
            if ([string]::IsNullOrEmpty($FilePath)) {
                Write-Error "-FilePath is required for json target." -ErrorAction Stop
            }
        }
        'syslog' {
            if ([string]::IsNullOrEmpty($FilePath)) {
                Write-Error "-FilePath is required for syslog target." -ErrorAction Stop
            }
        }
        'splunk' {
            if ([string]::IsNullOrEmpty($Url)) {
                Write-Error "-Url is required for splunk target (HEC endpoint)." -ErrorAction Stop
            }
            if ([string]::IsNullOrEmpty($Token)) {
                Write-Error "-Token is required for splunk target (HEC token)." -ErrorAction Stop
            }
        }
        'sumo' {
            if ([string]::IsNullOrEmpty($Url)) {
                Write-Error "-Url is required for sumo target (HTTP Collector URL)." -ErrorAction Stop
            }
        }
        'azure-la' {
            if ([string]::IsNullOrEmpty($WorkspaceId)) {
                Write-Error "-WorkspaceId is required for azure-la target." -ErrorAction Stop
            }
            if ([string]::IsNullOrEmpty($WorkspaceKey)) {
                Write-Error "-WorkspaceKey is required for azure-la target." -ErrorAction Stop
            }
        }
        'syslog-port' {
            if ([string]::IsNullOrEmpty($SyslogHost)) {
                Write-Error "-SyslogHost is required for syslog-port target." -ErrorAction Stop
            }
            if ($SyslogPort -le 0) {
                Write-Error "-SyslogPort must be a positive integer for syslog-port target." -ErrorAction Stop
            }
        }
    }

    if ($configRecord) {
        switch ($Target) {
            'json' {
                $pendingRecordSave = (setRecordField $configRecord 'login' $FilePath) -or $pendingRecordSave
            }
            'syslog' {
                $pendingRecordSave = (setRecordField $configRecord 'login' $FilePath) -or $pendingRecordSave
            }
            'splunk' {
                $pendingRecordSave = (setRecordField $configRecord 'url' $Url) -or $pendingRecordSave
                $pendingRecordSave = (setRecordField $configRecord 'password' $Token) -or $pendingRecordSave
            }
            'sumo' {
                $pendingRecordSave = (setRecordField $configRecord 'url' $Url) -or $pendingRecordSave
            }
            'azure-la' {
                $pendingRecordSave = (setRecordField $configRecord 'login' $WorkspaceId) -or $pendingRecordSave
                $pendingRecordSave = (setRecordField $configRecord 'password' $WorkspaceKey) -or $pendingRecordSave
            }
            'syslog-port' {
                $syslogScheme = if ($SyslogProtocol -eq 'udp') { 'syslogu' } elseif ($resolvedUseSsl) { 'syslogs' } else { 'syslog' }
                $pendingRecordSave = (setRecordField $configRecord 'url' ("{0}://{1}:{2}" -f $syslogScheme, $SyslogHost, $SyslogPort)) -or $pendingRecordSave
                $pendingRecordSave = (setRecordField $configRecord 'is_octet_counting' $(if ($resolvedOctetCounting) { '1' } else { '0' })) -or $pendingRecordSave
            }
        }
        if ($PSBoundParameters.ContainsKey('SharedFolderUid')) {
            $sharedFolderValue = if ($SharedFolderUid -and $SharedFolderUid.Count -gt 0) { $SharedFolderUid -join ', ' } else { '' }
            $pendingRecordSave = (setRecordField $configRecord 'shared_folder_uids' $sharedFolderValue) -or $pendingRecordSave
        }
        if ($PSBoundParameters.ContainsKey('NodeId')) {
            $nodeIdValue = if ($NodeId -and $NodeId.Count -gt 0) { ($NodeId | ForEach-Object { $_.ToString() }) -join ', ' } else { '' }
            $pendingRecordSave = (setRecordField $configRecord 'node_ids' $nodeIdValue) -or $pendingRecordSave
        }
    }

    $syslogTemplates = @{}
    try {
        $evtTypes = [KeeperSecurity.Enterprise.AuditLogExtensions]::GetAvailableEvents($auth).GetAwaiter().GetResult()
        if ($evtTypes) {
            foreach ($e in $evtTypes) {
                if ($e.Name -and $e.SyslogMessage) {
                    $syslogTemplates[$e.Name] = $e.SyslogMessage
                }
            }
        }
    }
    catch {
        Write-Warning "Could not load syslog templates: $($_.Exception.Message)"
    }

    function getEventMessage([System.Collections.Generic.Dictionary[string,object]] $evt) {
        $eventType = ''
        if ($evt.ContainsKey('audit_event_type') -and $null -ne $evt['audit_event_type']) {
            $eventType = $evt['audit_event_type'].ToString()
        }
        if (-not $syslogTemplates.ContainsKey($eventType)) { return '' }
        $info = $syslogTemplates[$eventType]
        while ($info -match '\$\{(\w+)\}') {
            $field = $Matches[1]
            $val = '<missing>'
            if ($evt.ContainsKey($field) -and $null -ne $evt[$field]) {
                $val = $evt[$field].ToString()
            }
            $info = $info.Replace('${' + $field + '}', $val)
        }
        return $info
    }

    function convertEventToTimestampObject([System.Collections.Generic.Dictionary[string,object]] $evt) {
        $obj = [ordered]@{}
        foreach ($key in $evt.Keys) {
            if ($key -eq 'id') { continue }
            if ($key -eq 'created') {
                $epoch = [long]$evt[$key].ToString()
                $dt = [DateTimeOffset]::FromUnixTimeSeconds($epoch)
                $obj['timestamp'] = $dt.ToString('yyyy-MM-ddTHH:mm:ssZ')
                continue
            }
            $obj[$key] = $evt[$key]
        }
        return $obj
    }

    function convertEvent([System.Collections.Generic.Dictionary[string,object]] $evt) {
        switch ($Target) {
            'json' {
                return (convertEventToTimestampObject $evt)
            }
            'splunk' {
                $evtData = [ordered]@{}
                foreach ($key in $evt.Keys) {
                    if ($key -in @('id','created')) { continue }
                    $evtData[$key] = $evt[$key]
                }
                $splunkObj = [ordered]@{
                    time       = $evt['created']
                    host       = $machineName
                    source     = $enterpriseName
                    sourcetype = '_json'
                    event      = $evtData
                }
                return ($splunkObj | ConvertTo-Json -Depth 5 -Compress)
            }
            'sumo' {
                $obj = convertEventToTimestampObject $evt
                $obj['message'] = getEventMessage $evt
                return ($obj | ConvertTo-Json -Depth 5 -Compress)
            }
            'azure-la' {
                return (convertEventToTimestampObject $evt)
            }
            default {
                $pri = 110
                $epoch = [long]$evt['created'].ToString()
                $dt = [DateTimeOffset]::FromUnixTimeSeconds($epoch)
                $ip = '-'
                if ($evt.ContainsKey('ip_address') -and $null -ne $evt['ip_address']) {
                    $ip = $evt['ip_address'].ToString()
                }
                $eventId = $evt['id']
                $header = "<$pri>1 $($dt.ToString('yyyy-MM-ddTHH:mm:ssZ')) $ip Keeper - $eventId"

                $structured = 'Keeper@Commander'
                foreach ($key in $evt.Keys) {
                    if ($key -in @('id','created','ip_address')) { continue }
                    $val = if ($null -ne $evt[$key]) { $evt[$key].ToString() } else { '' }
                    $structured += " $key=`"$val`""
                }
                $structured = "[$structured]"
                $msg = getEventMessage $evt
                return "$header $structured $msg"
            }
        }
    }

    function exportEvents([System.Collections.Generic.List[object]] $chunk) {
        try {
            switch ($Target) {
                'json' {
                    foreach ($item in $chunk) {
                        $jsonEvents.Add($item)
                    }
                    return $true
                }
                'syslog' {
                    if ($isGzipped) {
                        $fs = [System.IO.FileStream]::new($FilePath, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write)
                        try {
                            $gz = [System.IO.Compression.GZipStream]::new($fs, [System.IO.Compression.CompressionMode]::Compress)
                            $writer = [System.IO.StreamWriter]::new($gz, [System.Text.Encoding]::UTF8)
                            foreach ($line in $chunk) {
                                $writer.WriteLine($line.ToString())
                            }
                            $writer.Close()
                        }
                        finally {
                            $fs.Dispose()
                        }
                    }
                    else {
                        $utf8 = [System.Text.UTF8Encoding]::new($false)
                        $sb = [System.Text.StringBuilder]::new()
                        foreach ($line in $chunk) {
                            $sb.AppendLine($line.ToString()) | Out-Null
                        }
                        [System.IO.File]::AppendAllText($FilePath, $sb.ToString(), $utf8)
                    }
                    return $true
                }
                'splunk' {
                    $body = ($chunk | ForEach-Object { $_.ToString() }) -join "`n"
                    $hdrs = @{ 'Authorization' = "Splunk $Token" }
                    Invoke-RestMethod -Uri $Url -Method Post -Body $body -Headers $hdrs -ContentType 'application/json' | Out-Null
                    return $true
                }
                'sumo' {
                    $body = ($chunk | ForEach-Object { $_.ToString() }) -join "`n"
                    $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($body)
                    Invoke-RestMethod -Uri $Url -Method Post -Body $bodyBytes -ContentType 'application/text' | Out-Null
                    return $true
                }
                'azure-la' {
                    $azureUrl = "https://$WorkspaceId.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"
                    $jsonLines = $chunk | ForEach-Object { $_ | ConvertTo-Json -Depth 5 -Compress }
                    $data = '[' + ($jsonLines -join ',') + ']'
                    $dateStr = [DateTime]::UtcNow.ToString('r')
                    $contentLength = [System.Text.Encoding]::UTF8.GetByteCount($data)

                    $stringToHash = "POST`n$contentLength`napplication/json`nx-ms-date:$dateStr`n/api/logs"
                    $bytesToHash = [System.Text.Encoding]::UTF8.GetBytes($stringToHash)
                    $decodedKey = [Convert]::FromBase64String($WorkspaceKey)
                    $hmacSha = [System.Security.Cryptography.HMACSHA256]::new($decodedKey)
                    $encodedHash = [Convert]::ToBase64String($hmacSha.ComputeHash($bytesToHash))
                    $sharedKey = "${WorkspaceId}:${encodedHash}"

                    $hdrs = @{
                        'Authorization' = "SharedKey $sharedKey"
                        'Log-Type'      = 'Keeper'
                        'x-ms-date'     = $dateStr
                    }
                    $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($data)
                    Invoke-RestMethod -Uri $azureUrl -Method Post -Body $bodyBytes -Headers $hdrs -ContentType 'application/json' | Out-Null
                    return $true
                }
                'syslog-port' {
                    $isUdp = $SyslogProtocol -eq 'udp'
                    if ($isUdp) {
                        $udpClient = [System.Net.Sockets.UdpClient]::new()
                        try {
                            $udpClient.Connect($SyslogHost, $SyslogPort)
                            foreach ($line in $chunk) {
                                $lineStr = $line.ToString()
                                $bytes = [System.Text.Encoding]::UTF8.GetBytes("$lineStr`n")
                                $udpClient.Send($bytes, $bytes.Length) | Out-Null
                            }
                        }
                        finally {
                            $udpClient.Close()
                        }
                    }
                    else {
                        $tcpClient = [System.Net.Sockets.TcpClient]::new()
                        try {
                            $tcpClient.SendTimeout = 5000
                            $tcpClient.Connect($SyslogHost, $SyslogPort)
                            $netStream = $tcpClient.GetStream()
                            $writeStream = $netStream
                            if ($resolvedUseSsl) {
                                $sslStream = [System.Net.Security.SslStream]::new($netStream, $false)
                                $sslStream.AuthenticateAsClient($SyslogHost)
                                $writeStream = $sslStream
                            }
                            foreach ($line in $chunk) {
                                $lineStr = $line.ToString()
                                if ($resolvedOctetCounting) {
                                    $msgBytes = [System.Text.Encoding]::UTF8.GetBytes($lineStr)
                                    $framedMsg = "$($msgBytes.Length) $lineStr"
                                }
                                else {
                                    $framedMsg = "$lineStr`n"
                                }
                                $bytes = [System.Text.Encoding]::UTF8.GetBytes($framedMsg)
                                $writeStream.Write($bytes, 0, $bytes.Length)
                            }
                            $writeStream.Flush()
                        }
                        finally {
                            $tcpClient.Close()
                        }
                    }
                    return $true
                }
            }
        }
        catch {
            Write-Warning "Export failed: $($_.Exception.Message)"
            return $false
        }
    }

    function resolveAnonymousUid([string] $username) {
        if ([string]::IsNullOrEmpty($username)) { return '' }
        if ($entUserIds.ContainsKey($username)) {
            return $entUserIds[$username].ToString()
        }
        $md5Algo = [System.Security.Cryptography.MD5]::Create()
        $hashBytes = $md5Algo.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($username))
        $hex = ($hashBytes | ForEach-Object { $_.ToString('x2') }) -join ''
        return "DELETED-$hex"
    }

    $machineName = [System.Net.Dns]::GetHostName()

    $enterpriseName = $enterprise.loader.EnterpriseName

    $entUserIds = @{}
    if ($Anonymize.IsPresent) {
        try {
            foreach ($user in $enterprise.enterpriseData.Users) {
                if ($user.Email) {
                    $entUserIds[$user.Email] = $user.Id
                }
            }
        }
        catch {
            Write-Warning "Could not build user ID lookup for anonymization."
        }
    }

    $previousCallback = $null
    if ($IgnoreCertificateErrors.IsPresent -and $Target -in @('splunk','sumo','azure-la')) {
        $previousCallback = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {
            param($senderObj, $certificate, $chain, $sslPolicyErrors)
            return $true
        }
    }

    try {
        $nowTs = [long][DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        $currentEventTime = $LastEventTime

        if ($Days -gt 0) {
            $lastEventDt = [DateTimeOffset]::UtcNow.AddDays(-$Days)
            $currentEventTime = [long]$lastEventDt.ToUnixTimeSeconds()
        }

        $jsonEvents = $null
        if ($Target -eq 'json') {
            $jsonEvents = [System.Collections.Generic.List[object]]::new()
        }

        $isGzipped = ($Target -eq 'syslog' -and $FilePath -and $FilePath.EndsWith('.gz', [StringComparison]::OrdinalIgnoreCase))

        $createdFilter = New-Object KeeperSecurity.Enterprise.AuditLogCommands.CreatedFilter
        $createdFilter.Max = $nowTs

        $filter = New-Object KeeperSecurity.Enterprise.AuditLogCommands.ReportFilter
        $filter.Created = $createdFilter
        if ($SharedFolderUid -and $SharedFolderUid.Count -gt 0) {
            $filter.SharedFolderUid = $SharedFolderUid
        }
        if ($NodeId -and $NodeId.Count -gt 0) {
            $filter.NodeId = $NodeId
        }

        $totalEvents = 0
        try {
            $spanFilter = New-Object KeeperSecurity.Enterprise.AuditLogCommands.ReportFilter
            $spanCreated = New-Object KeeperSecurity.Enterprise.AuditLogCommands.CreatedFilter
            $spanCreated.Max = $nowTs
            if ($currentEventTime -gt 0) { $spanCreated.Min = $currentEventTime }
            $spanFilter.Created = $spanCreated
            if ($SharedFolderUid -and $SharedFolderUid.Count -gt 0) {
                $spanFilter.SharedFolderUid = $SharedFolderUid
            }
            if ($NodeId -and $NodeId.Count -gt 0) {
                $spanFilter.NodeId = $NodeId
            }

            $spanRq = New-Object KeeperSecurity.Enterprise.AuditLogCommands.GetAuditEventReportsCommand
            $spanRq.Filter = $spanFilter
            $spanRq.ReportType = 'span'

            $spanResponse = $auth.ExecuteAuthCommand($spanRq, [KeeperSecurity.Enterprise.AuditLogCommands.GetAuditEventReportsResponse], $true).GetAwaiter().GetResult()
            $spanRs = [KeeperSecurity.Enterprise.AuditLogCommands.GetAuditEventReportsResponse]$spanResponse
            if ($spanRs.Events -and $spanRs.Events.Count -gt 0 -and $spanRs.Events[0].ContainsKey('occurrences')) {
                $totalEvents = [int]$spanRs.Events[0]['occurrences'].ToString()
            }
        }
        catch {
            Write-Warning "Failed to determine total events: $($_.Exception.Message)"
            return
        }

        if ($totalEvents -eq 0) {
            if ($configRecord -and $pendingRecordSave) {
                $configRecord = saveAuditLogRecord $configRecord
            }
            Write-Host 'No events to export.'
            return
        }

        $rq = New-Object KeeperSecurity.Enterprise.AuditLogCommands.GetAuditEventReportsCommand
        $rq.Filter = $filter
        $rq.ReportType = 'raw'
        $rq.Limit = 1000
        $rq.Order = 'ascending'

        $loggedIds = [System.Collections.Generic.HashSet[string]]::new()
        $events = [System.Collections.Generic.List[object]]::new()
        $numExported = 0
        $finished = $false
        $runSucceeded = $true
        $lastSuccessfulEventTime = $LastEventTime
        $reportedExportedCount = 0
        $reportedLastEventTime = $LastEventTime
        $chunkSize = switch ($Target) {
            'sumo'     { 250 }
            'azure-la' { 250 }
            default    { 1000 }
        }

        while (-not $finished) {
            $finished = $true

            if ($currentEventTime -gt 0) {
                $createdFilter.Min = $currentEventTime
            }

            try {
                $response = $auth.ExecuteAuthCommand($rq, [KeeperSecurity.Enterprise.AuditLogCommands.GetAuditEventReportsResponse], $true).GetAwaiter().GetResult()
                $rs = [KeeperSecurity.Enterprise.AuditLogCommands.GetAuditEventReportsResponse]$response
            }
            catch {
                Write-Warning "Failed to fetch audit events: $($_.Exception.Message)"
                $runSucceeded = $false
                break
            }

            if ($rs.Events -and $rs.Events.Count -gt 0) {
                $auditEvents = $rs.Events
                $currentEventTime = [long]$auditEvents[$auditEvents.Count - 1]['created'].ToString()

                $hasNewEvents = $false
                foreach ($evt in $auditEvents) {
                    $evtId = $evt['id'].ToString()
                    if ($loggedIds.Contains($evtId)) { continue }
                    $loggedIds.Add($evtId) | Out-Null
                    $hasNewEvents = $true

                    if ($Anonymize.IsPresent) {
                        $uname = ''
                        if ($evt.ContainsKey('email') -and $null -ne $evt['email']) {
                            $uname = $evt['email'].ToString()
                        }
                        elseif ($evt.ContainsKey('username') -and $null -ne $evt['username']) {
                            $uname = $evt['username'].ToString()
                        }
                        if ($uname) {
                            $anonId = resolveAnonymousUid $uname
                            if ($evt.ContainsKey('username')) { $evt['username'] = $anonId }
                            if ($evt.ContainsKey('email')) { $evt['email'] = $anonId }
                        }
                        if ($evt.ContainsKey('to_username') -and $null -ne $evt['to_username'] -and $evt['to_username'].ToString()) {
                            $evt['to_username'] = resolveAnonymousUid $evt['to_username'].ToString()
                        }
                        if ($evt.ContainsKey('from_username') -and $null -ne $evt['from_username'] -and $evt['from_username'].ToString()) {
                            $evt['from_username'] = resolveAnonymousUid $evt['from_username'].ToString()
                        }
                    }

                    $converted = convertEvent $evt
                    $events.Add([PSCustomObject]@{
                        Payload = $converted
                        Created = [long]$evt['created'].ToString()
                    })
                }

                $finished = $nowTs -le $currentEventTime

                if (-not $hasNewEvents -and -not $finished) {
                    $currentEventTime++
                }
            }

            while ($events.Count -gt 0) {
                $chunkEnd = [Math]::Min($chunkSize, $events.Count)
                $chunk = $events.GetRange(0, $chunkEnd)
                $events.RemoveRange(0, $chunkEnd)

                $payloadChunk = [System.Collections.Generic.List[object]]::new()
                foreach ($chunkItem in $chunk) {
                    $payloadChunk.Add($chunkItem.Payload)
                }

                $success = exportEvents $payloadChunk
                if (-not $success) {
                    $finished = $true
                    $runSucceeded = $false
                    break
                }
                $numExported += $chunk.Count
                if ($chunk.Count -gt 0) {
                    $lastSuccessfulEventTime = [long]$chunk[$chunk.Count - 1].Created
                }

                if ($totalEvents -gt 0) {
                    $pctDone = [Math]::Min(100, [int]($numExported / $totalEvents * 100))
                    Write-Progress -Activity 'Exporting audit events' -PercentComplete $pctDone -Status "$numExported of $totalEvents events exported"
                }
            }
        }

        Write-Progress -Activity 'Exporting audit events' -Completed

        if ($Target -eq 'json' -and $numExported -gt 0) {
            try {
                $utf8 = [System.Text.UTF8Encoding]::new($false)
                $jsonLines = $jsonEvents | ForEach-Object { $_ | ConvertTo-Json -Depth 5 -Compress }
                $jsonContent = '[' + ($jsonLines -join ',') + ']'
                [System.IO.File]::WriteAllText($FilePath, $jsonContent, $utf8)
            }
            catch {
                Write-Warning "Failed to write JSON file: $($_.Exception.Message)"
                $runSucceeded = $false
            }
        }

        if ($runSucceeded) {
            $reportedExportedCount = $numExported
            $reportedLastEventTime = if ($numExported -gt 0) { $lastSuccessfulEventTime } else { $LastEventTime }
        }
        elseif ($Target -eq 'json') {
            $reportedExportedCount = 0
            $reportedLastEventTime = $LastEventTime
        }
        else {
            $reportedExportedCount = $numExported
            $reportedLastEventTime = if ($numExported -gt 0) { $lastSuccessfulEventTime } else { $LastEventTime }
        }

        if ($configRecord -and $runSucceeded -and $numExported -gt 0) {
            $pendingRecordSave = (setRecordField $configRecord 'last_event_time' $lastSuccessfulEventTime) -or $pendingRecordSave
        }
        if ($configRecord -and $runSucceeded -and $pendingRecordSave) {
            $configRecord = saveAuditLogRecord $configRecord
        }

        if ($runSucceeded) {
            Write-Host "Exported $reportedExportedCount audit event(s)."
        }
        elseif ($reportedExportedCount -gt 0) {
            Write-Warning "Export did not complete successfully. $reportedExportedCount audit event(s) were exported before the failure."
        }
        else {
            Write-Warning 'Export did not complete successfully. No audit events were exported.'
        }

        $result = [ordered]@{
            ExportedCount = $reportedExportedCount
            LastEventTime = $reportedLastEventTime
            Target        = $Target
            Success       = $runSucceeded
        }
        return [PSCustomObject]$result
    }
    finally {
        if ($IgnoreCertificateErrors.IsPresent -and $Target -in @('splunk','sumo','azure-la')) {
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $previousCallback
        }
    }
}
New-Alias -Name kal -Value Export-KeeperAuditLog

