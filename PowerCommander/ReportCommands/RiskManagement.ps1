#requires -Version 5.1

function Script:Write-RiskManagementSyntaxHelp {
    Write-Host @"

Risk Management Report Command Syntax Description:

This command provides risk management reports from Keeper's RMD (Risk Management Dashboard)
APIs. It mirrors the Python Commander 'risk-management' group command.

Actions (-Action):
  enterprise-stat           Enterprise-wide login and record stats (default)
  enterprise-stat-details   Per-user login and record details
  security-alerts-summary   Security alerts summary with 30-day trends
  security-alerts-detail    Detailed per-user breakdown for a specific alert event
  security-benchmarks-get   Get security benchmark statuses
  security-benchmarks-set   Set security benchmark statuses

Options:
  -Action <action>          Action to perform (default: enterprise-stat)
  -AuditEventType <name>    Audit event type name or numeric ID (for security-alerts-detail)
  -BenchmarkFields <list>   Benchmark fields to set as 'NAME:STATUS' pairs (for security-benchmarks-set)
  -Format <format>          Output format: table (default), json, csv
  -Output <path>            Write report to file
  -SyntaxHelp               Display this help text

Audit Event Types (-AuditEventType):
  Accepts an event name or numeric ID. Use 'security-alerts-summary' to see available types.
  Docs: https://docs.keeper.io/en/enterprise-guide/event-reporting

Benchmark Fields (-BenchmarkFields):
  Format: NAME:STATUS. Use 'security-benchmarks-get' to see current values.

  Valid benchmark names:
    SB_DEPLOY_ACROSS_ENTIRE_ORGANIZATION              SB_ENFORCE_STRONG_MASTER_PASSWORD
    SB_PREVENT_INSTALLATION_OF_UNTRUSTED_EXTENSIONS   SB_ENSURE_TWO_FACTOR_AUTHENTICATION_FOR_END_USERS
    SB_ENABLE_ACCOUNT_TRANSFER_POLICY                 SB_CONFIGURE_IP_ALLOWLISTING
    SB_REDUCE_ADMINISTRATOR_PRIVILEGE                 SB_CREATE_ALERTS
    SB_ENSURE_OUTSIDE_SSO_ADMINISTRATOR_EXISTS        SB_DISABLE_BROWSER_PASSWORD_MANAGERS
    SB_LOCK_DOWN_SSO_PROVIDER                         SB_DISABLE_ACCOUNT_RECOVERY
    SB_CREATE_AT_LEAST_TWO_KEEPER_ADMINISTRATORS      SB_ENFORCE_LEAST_PRIVILEGE_POLICY
    SB_ENSURE_TWO_FACTOR_AUTHENTICATION_ADMIN_USERS

  Valid statuses: RESOLVED, IGNORED, UNRESOLVED

Examples:
  Get-KeeperRiskManagementReport
      Enterprise-wide login/record stats

  Get-KeeperRiskManagementReport -Action enterprise-stat-details
      Per-user login details

  Get-KeeperRiskManagementReport -Action security-alerts-summary
      Security alerts summary with trends

  Get-KeeperRiskManagementReport -Action security-alerts-detail -AuditEventType "bw_record_high_risk"
      Details for a specific alert type by name

  Get-KeeperRiskManagementReport -Action security-alerts-detail -AuditEventType 1001
      Details for a specific alert type by numeric ID

  Get-KeeperRiskManagementReport -Action security-benchmarks-get
      Security benchmark statuses

  Get-KeeperRiskManagementReport -Action security-benchmarks-set -BenchmarkFields "SB_ENFORCE_STRONG_MASTER_PASSWORD:RESOLVED"
      Set a benchmark status
"@
}

function Script:Write-RiskManagementOutput {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]] $Rows,

        [Parameter(Mandatory = $true)]
        [ValidateSet('table', 'json', 'csv')]
        [string] $Format,

        [Parameter()]
        [string] $Output,

        [Parameter()]
        [string] $Title
    )

    if ($null -eq $Rows -or $Rows.Count -eq 0) {
        if ($Title) {
            Write-Host ""
            Write-Host $Title
        }
        Write-Host "No results."
        return
    }

    switch ($Format) {
        'json' {
            $jsonText = $Rows | ConvertTo-Json -Depth 5
            if ($Output) {
                Set-Content -Path $Output -Value $jsonText -Encoding utf8
                Write-Host "Output written to $Output"
                return
            }
            return $jsonText
        }
        'csv' {
            $csvText = ($Rows | ConvertTo-Csv -NoTypeInformation)
            if ($Output) {
                Set-Content -Path $Output -Value $csvText -Encoding utf8
                Write-Host "Output written to $Output"
                return
            }
            return $csvText
        }
        default {
            if ($Output) {
                $tableText = @($Rows | Format-Table -Property * -AutoSize | Out-String -Width 8192)
                $content = @()
                if ($Title) { $content += $Title; $content += '' }
                $content += $tableText
                Set-Content -Path $Output -Value $content -Encoding utf8
                Write-Host "Output written to $Output"
                return
            }

            if ($Title) {
                Write-Host ""
                Write-Host $Title
            }
            $Rows | Format-Table -Property * -AutoSize | Out-String -Width 8192
        }
    }
}

$Script:ArrowUp        = [char]0x2191  # ↑
$Script:ArrowDown      = [char]0x2193  # ↓
$Script:ArrowUpRight   = [char]0x2197  # ↗
$Script:ArrowDownRight = [char]0x2198  # ↘

$Script:ValidBenchmarkNames = @(
    'SB_DEPLOY_ACROSS_ENTIRE_ORGANIZATION',
    'SB_PREVENT_INSTALLATION_OF_UNTRUSTED_EXTENSIONS',
    'SB_ENABLE_ACCOUNT_TRANSFER_POLICY',
    'SB_REDUCE_ADMINISTRATOR_PRIVILEGE',
    'SB_ENSURE_OUTSIDE_SSO_ADMINISTRATOR_EXISTS',
    'SB_LOCK_DOWN_SSO_PROVIDER',
    'SB_CREATE_AT_LEAST_TWO_KEEPER_ADMINISTRATORS',
    'SB_ENSURE_TWO_FACTOR_AUTHENTICATION_ADMIN_USERS',
    'SB_ENFORCE_STRONG_MASTER_PASSWORD',
    'SB_ENSURE_TWO_FACTOR_AUTHENTICATION_FOR_END_USERS',
    'SB_CONFIGURE_IP_ALLOWLISTING',
    'SB_CREATE_ALERTS',
    'SB_DISABLE_BROWSER_PASSWORD_MANAGERS',
    'SB_DISABLE_ACCOUNT_RECOVERY',
    'SB_ENFORCE_LEAST_PRIVILEGE_POLICY'
)

$Script:ValidBenchmarkStatuses = @('RESOLVED', 'IGNORED', 'UNRESOLVED')

function Script:Get-TrendIndicator {
    param(
        [int] $Current,
        [int] $Previous
    )
    if ($Current -ne $Previous) {
        if ($Previous -gt 0 -and $Current -gt 0) {
            $rate = ($Current - $Previous) / $Previous
            if ($rate -gt 0) { return "[   $ArrowUpRight ]" } else { return "[ $ArrowDownRight   ]" }
        }
        elseif ($Previous -gt 0) { return "[    $ArrowUp]" }
        else { return "[$ArrowDown    ]" }
    }
    return '[  -  ]'
}

function Get-KeeperRiskManagementReport {
    <#
    .SYNOPSIS
    Generate risk management reports from Keeper's RMD APIs.

    .DESCRIPTION
    This command provides risk management reports from Keeper's Risk Management Dashboard.

    Alias: risk-report

    .PARAMETER Action
    Action to perform:
      enterprise-stat           Enterprise-wide login and record stats (default)
      enterprise-stat-details   Per-user login and record details
      security-alerts-summary   Security alerts summary with 30-day trends
      security-alerts-detail    Per-user breakdown for a specific alert event
      security-benchmarks-get   Get security benchmark statuses
      security-benchmarks-set   Set security benchmark statuses

    .PARAMETER AuditEventType
    Audit event type name (e.g. "bw_record_high_risk") or numeric ID. Required for security-alerts-detail.
    Use 'security-alerts-summary' to see available types.

    .PARAMETER BenchmarkFields
    Benchmark fields to set as 'NAME:STATUS' pairs. Required for security-benchmarks-set.
    Use 'security-benchmarks-get' to see current values. Statuses: RESOLVED, IGNORED, UNRESOLVED.

    .PARAMETER Format
    Output format: table (default), json, csv.

    .PARAMETER Output
    File path to write the report output to.

    .PARAMETER SyntaxHelp
    Display detailed syntax help.

    .EXAMPLE
    Get-KeeperRiskManagementReport
    Enterprise-wide login/record stats.

    .EXAMPLE
    Get-KeeperRiskManagementReport -Action enterprise-stat-details
    Per-user login details.

    .EXAMPLE
    Get-KeeperRiskManagementReport -Action security-alerts-summary
    Security alerts summary with 30-day trends.

    .EXAMPLE
    Get-KeeperRiskManagementReport -Action security-alerts-detail -AuditEventType "bw_record_high_risk"
    Details for a specific alert type.

    .EXAMPLE
    Get-KeeperRiskManagementReport -Action security-benchmarks-get
    Security benchmark statuses.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        [ValidateSet('enterprise-stat', 'enterprise-stat-details', 'security-alerts-summary',
                     'security-alerts-detail', 'security-benchmarks-get', 'security-benchmarks-set')]
        [string] $Action = 'enterprise-stat',

        [Parameter()]
        [string] $AuditEventType,

        [Parameter()]
        [string[]] $BenchmarkFields,

        [Parameter()]
        [ValidateSet('table', 'json', 'csv')]
        [string] $Format = 'table',

        [Parameter()]
        [string] $Output,

        [Parameter()]
        [switch] $SyntaxHelp
    )

    if ($SyntaxHelp) {
        Write-RiskManagementSyntaxHelp
        return
    }

    try {
        [Enterprise]$enterprise = getEnterprise
    }
    catch {
        Write-Error "Failed to load enterprise context: $($_.Exception.Message)" -ErrorAction Stop
    }

    if ($null -eq $enterprise.enterpriseData) {
        Write-Warning "Enterprise data is not available."
        return
    }

    $auth = $enterprise.loader.Auth

    if ($AuditEventType -and $Action -ne 'security-alerts-detail') {
        Write-Warning "-AuditEventType is only used with 'security-alerts-detail'. Ignoring."
    }
    if ($BenchmarkFields -and $Action -ne 'security-benchmarks-set') {
        Write-Warning "-BenchmarkFields is only used with 'security-benchmarks-set'. Ignoring."
    }

    switch ($Action) {
        'enterprise-stat' {
            Write-Verbose "Calling rmd/get_enterprise_stat..."
            $result = [KeeperSecurity.Enterprise.RiskManagementExtensions]::GetRiskManagementEnterpriseStat(
                $auth
            ).GetAwaiter().GetResult()

            $rows = @(
                [PSCustomObject]@{ Metric = 'Logged In (Recent)'; Value = $result.UsersLoggedRecent }
                [PSCustomObject]@{ Metric = 'Has Records';        Value = $result.UsersHasRecords }
            )
            Write-RiskManagementOutput -Rows $rows -Format $Format -Output $Output -Title 'Users Enterprise Stat'
        }

        'enterprise-stat-details' {
            Write-Verbose "Calling rmd/get_enterprise_stat_details..."
            $results = [KeeperSecurity.Enterprise.RiskManagementExtensions]::GetRiskManagementEnterpriseStatDetails(
                $enterprise.enterpriseData, $auth
            ).GetAwaiter().GetResult()

            $rows = foreach ($r in $results) {
                $lastLogin = $null
                if ($r.LastLoggedInMs -gt 0) {
                    $lastLogin = [DateTimeOffset]::FromUnixTimeMilliseconds($r.LastLoggedInMs).LocalDateTime.ToString('yyyy-MM-dd HH:mm:ss')
                }
                [PSCustomObject]@{
                    Username     = $r.Username
                    LastLoggedIn = $lastLogin
                    HasRecords   = $r.HasRecords
                }
            }

            Write-RiskManagementOutput -Rows @($rows) -Format $Format -Output $Output -Title 'Enterprise Stat Details'
        }

        'security-alerts-summary' {
            Write-Verbose "Calling rmd/get_security_alerts_summary..."
            $results = [KeeperSecurity.Enterprise.RiskManagementExtensions]::GetRiskManagementSecurityAlertsSummary(
                $auth
            ).GetAwaiter().GetResult()

            $rows = foreach ($r in $results) {
                $eventDisplay = if ($r.EventName) { $r.EventName } else { $r.AuditEventTypeId.ToString() }

                $row = [PSCustomObject]@{
                    Event            = $eventDisplay
                    EventOccurrences = $r.CurrentCount
                    LastEvents       = $r.PreviousCount
                    UniqueUsers      = $r.CurrentUserCount
                    LastUsers        = $r.PreviousUserCount
                }

                if ($Format -ne 'json') {
                    $row | Add-Member -NotePropertyName EventTrend -NotePropertyValue (Get-TrendIndicator -Current $r.CurrentCount -Previous $r.PreviousCount)
                    $row | Add-Member -NotePropertyName UserTrend  -NotePropertyValue (Get-TrendIndicator -Current $r.CurrentUserCount -Previous $r.PreviousUserCount)
                }

                $row
            }

            Write-RiskManagementOutput -Rows @($rows) -Format $Format -Output $Output -Title 'Security Alerts Summary'
        }

        'security-alerts-detail' {
            if ([string]::IsNullOrEmpty($AuditEventType)) {
                Write-Error "The -AuditEventType parameter is required for security-alerts-detail." -ErrorAction Stop
            }

            $eventTypeId = 0
            if ([int]::TryParse($AuditEventType, [ref]$eventTypeId)) {
                if ($eventTypeId -le 0) {
                    Write-Error "Audit event type ID must be a positive integer. Got: $eventTypeId" -ErrorAction Stop
                }
                Write-Verbose "Using numeric event type ID: $eventTypeId"
            }
            else {
                Write-Verbose "Resolving event type name '$AuditEventType'..."
                $dimensions = [KeeperSecurity.Enterprise.RiskManagementExtensions]::GetAuditEventDimensions(
                    $auth
                ).GetAwaiter().GetResult()

                $found = $false
                foreach ($entry in $dimensions.GetEnumerator()) {
                    if ($entry.Value -eq $AuditEventType) {
                        $eventTypeId = $entry.Key
                        $found = $true
                        break
                    }
                }
                if (-not $found) {
                    Write-Error "Unknown audit event type: '$AuditEventType'. Use security-alerts-summary to find valid event names or numeric IDs." -ErrorAction Stop
                }
            }

            Write-Verbose "Calling rmd/get_security_alerts_detail for event type $eventTypeId..."
            $results = [KeeperSecurity.Enterprise.RiskManagementExtensions]::GetRiskManagementSecurityAlertsDetail(
                $enterprise.enterpriseData, $auth, $eventTypeId
            ).GetAwaiter().GetResult()

            $rows = foreach ($r in $results) {
                $lastOccurrence = $null
                if ($r.LastOccurrenceMs -gt 0) {
                    $lastOccurrence = [DateTimeOffset]::FromUnixTimeMilliseconds($r.LastOccurrenceMs).LocalDateTime.ToString('yyyy-MM-dd HH:mm:ss')
                }
                [PSCustomObject]@{
                    Username       = $r.Username
                    CurrentCount   = $r.CurrentCount
                    PreviousCount  = $r.PreviousCount
                    LastOccurrence = $lastOccurrence
                }
            }

            Write-RiskManagementOutput -Rows @($rows) -Format $Format -Output $Output -Title "Security Alerts Detail (Event Type: $AuditEventType)"
        }

        'security-benchmarks-get' {
            Write-Verbose "Calling rmd/get_security_benchmarks..."
            $results = [KeeperSecurity.Enterprise.RiskManagementExtensions]::GetRiskManagementSecurityBenchmarks(
                $auth
            ).GetAwaiter().GetResult()

            $rows = foreach ($r in $results) {
                $lastUpdated = $null
                if ($r.LastUpdatedMs -gt 0) {
                    $lastUpdated = [DateTimeOffset]::FromUnixTimeMilliseconds($r.LastUpdatedMs).LocalDateTime.ToString('yyyy-MM-dd HH:mm:ss')
                }
                [PSCustomObject]@{
                    Id          = $r.BenchmarkName
                    Status      = $r.Status
                    LastUpdated = $lastUpdated
                    AutoResolve = $r.AutoResolve
                }
            }

            Write-RiskManagementOutput -Rows @($rows) -Format $Format -Output $Output -Title 'Security Benchmarks'
        }

        'security-benchmarks-set' {
            if (-not $BenchmarkFields -or $BenchmarkFields.Count -eq 0) {
                Write-Error "The -BenchmarkFields parameter is required for security-benchmarks-set. Use 'NAME:STATUS' format." -ErrorAction Stop
            }

            $updates = [System.Collections.Generic.Dictionary[string, string]]::new()
            foreach ($field in $BenchmarkFields) {
                $parts = $field.Split(':', 2)
                if ($parts.Count -ne 2) {
                    Write-Warning "Skipping invalid field '$field'. Expected format: NAME:STATUS"
                    continue
                }
                $name   = $parts[0].Trim().ToUpper()
                $status = $parts[1].Trim().ToUpper()

                if ($name -notin $Script:ValidBenchmarkNames) {
                    Write-Error "Invalid benchmark name: '$name'. Valid names: $($Script:ValidBenchmarkNames -join ', ')" -ErrorAction Stop
                }
                if ($status -notin $Script:ValidBenchmarkStatuses) {
                    Write-Error "Invalid benchmark status: '$status'. Valid statuses: $($Script:ValidBenchmarkStatuses -join ', ')" -ErrorAction Stop
                }

                $updates[$name] = $status
            }

            if ($updates.Count -eq 0) {
                Write-Warning "No valid benchmark fields to set."
                return
            }

            Write-Verbose "Calling rmd/set_security_benchmarks..."
            try {
                [KeeperSecurity.Enterprise.RiskManagementExtensions]::SetRiskManagementSecurityBenchmarks(
                    $auth, $updates
                ).GetAwaiter().GetResult()
                Write-Host "Done"
            }
            catch {
                $msg = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message }
                Write-Error $msg -ErrorAction Stop
            }
        }
    }
}

Set-Alias -Name risk-report -Value Get-KeeperRiskManagementReport
