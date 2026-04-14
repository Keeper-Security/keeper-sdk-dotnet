#requires -Version 5.1

$script:AuditAlertSettingsCache = $null
$script:AuditAlertEventTypes = $null
$script:AuditAlertLastUser = $null
$script:AuditAlertLastEnterpriseHint = $null

function Clear-KeeperAuditAlertCache {
    $script:AuditAlertSettingsCache = $null
    $script:AuditAlertEventTypes = $null
    $script:AuditAlertLastUser = $null
    $script:AuditAlertLastEnterpriseHint = $null
}

function Assert-KeeperApiResponse {
    <#
    .SYNOPSIS
    Fail if a Keeper JSON API response is missing or not success (some batch paths return per-item failures without throwing).
    #>
    param(
        $Response,
        [Parameter(Mandatory)][string] $Context
    )
    if ($null -eq $Response) {
        Write-Error "Keeper API returned no response ($Context)." -ErrorAction Stop
    }
    if ($Response.IsSuccess) { return }
    $code = $Response.resultCode
    if ([string]::IsNullOrEmpty($code)) { $code = '(unknown)' }
    $msg = $Response.message
    if ([string]::IsNullOrEmpty($msg)) { $msg = $code }
    Write-Error "Keeper API error ($Context): [$code] $msg" -ErrorAction Stop
}

function Stop-KeeperAuditAlert {
    <#
    .SYNOPSIS
    Terminate with a cmdlet-style error (avoids raw throw strings that show as Exception + script line only).
    #>
    param([Parameter(Mandatory)][string] $Message)
    Write-Error -Message $Message -ErrorAction Stop
}

function Get-KeeperAuditAlertSettingsInternal {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][KeeperSecurity.Authentication.IAuthentication] $Auth,
        [Parameter()][KeeperSecurity.Enterprise.EnterpriseData] $EnterpriseData,
        [switch] $Reload
    )

    $user = $Auth.Username
    $entHint = if ($EnterpriseData) { $EnterpriseData.EnterpriseLicense.EnterpriseLicenseId.ToString() } else { '' }

    if ($null -eq $script:AuditAlertEventTypes) {
        $dimRq = New-Object KeeperSecurity.Commands.GetAuditEventDimensionsCommand
        $dimRq.Columns = @('audit_event_type')
        try {
            $dimRs = $Auth.ExecuteAuthCommand($dimRq, [KeeperSecurity.Commands.GetAuditEventDimensionsResponse], $true).GetAwaiter().GetResult()
        } catch {
            Write-Error "Failed to load audit event types (get_audit_event_dimensions): $($_.Exception.Message)" -ErrorAction Stop
        }
        Assert-KeeperApiResponse -Response $dimRs -Context 'get_audit_event_dimensions'
        $map = @{}
        if ($dimRs.Dimensions -and $dimRs.Dimensions.AuditEventTypes) {
            foreach ($et in $dimRs.Dimensions.AuditEventTypes) {
                if ($et.Name) { $map[$et.Name.ToLowerInvariant()] = $et.Id }
            }
        }
        $script:AuditAlertEventTypes = $map
    }

    $needReload = $Reload.IsPresent -or ($null -eq $script:AuditAlertSettingsCache) -or ($user -ne $script:AuditAlertLastUser) -or ($entHint -ne $script:AuditAlertLastEnterpriseHint)
    if (-not $needReload) {
        return $script:AuditAlertSettingsCache
    }

    $rq = New-Object KeeperSecurity.Enterprise.GetEnterpriseSettingCommand
    $rq.Include = @('AuditAlertContext', 'AuditAlertFilter', 'AuditReportFilter')
    try {
        $rs = $Auth.ExecuteAuthCommand($rq, [KeeperSecurity.Enterprise.GetEnterpriseSettingResponse], $true).GetAwaiter().GetResult()
    } catch {
        Write-Error "Failed to load enterprise alert settings (get_enterprise_setting): $($_.Exception.Message)" -ErrorAction Stop
    }
    Assert-KeeperApiResponse -Response $rs -Context 'get_enterprise_setting'

    $script:AuditAlertSettingsCache = $rs
    $script:AuditAlertLastUser = $user
    $script:AuditAlertLastEnterpriseHint = $entHint
    return $rs
}

function Get-KeeperAuditAlertContext {
    param([Parameter(Mandatory)] $Settings, [Parameter(Mandatory)][int] $AlertId)
    if (-not $Settings -or -not $Settings.AuditAlertContext) { return $null }
    foreach ($ctx in $Settings.AuditAlertContext) {
        if ($ctx.Id -eq $AlertId) { return $ctx }
    }
    return $null
}

function Get-KeeperAuditAlertEventReverseMap {
    $revMap = @{}
    if ($null -eq $script:AuditAlertEventTypes) { return $revMap }
    foreach ($kvp in $script:AuditAlertEventTypes.GetEnumerator()) {
        $revMap[$kvp.Value] = $kvp.Key
    }
    return $revMap
}

function Get-KeeperAuditAlertUserEmailForId {
    param(
        [Parameter(Mandatory)][KeeperSecurity.Enterprise.EnterpriseData] $EnterpriseData,
        [Parameter(Mandatory)][long] $UserId
    )
    $u = $null
    if ($EnterpriseData.TryGetUserById($UserId, [ref]$u)) { return $u.Email }
    return "$UserId"
}

function Set-KeeperAuditFilterIdSelectedEntries {
    param(
        [Parameter(Mandatory)][KeeperSecurity.Enterprise.AuditAlertFilterDetail] $Detail,
        [Parameter(Mandatory)][ValidateSet('RecordUids', 'SharedFolderUids')][string] $Property,
        [Parameter()][string[]] $Chunks
    )
    if (-not $Chunks -or $Chunks.Count -eq 0) { return }
    $set = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($chunk in $Chunks) {
        foreach ($r in $chunk.Split(',')) {
            $x = $r.Trim()
            if ($x) { [void]$set.Add($x) }
        }
    }
    if ($set.Count -eq 0) {
        if ($Property -eq 'RecordUids') { $Detail.RecordUids = $null } else { $Detail.SharedFolderUids = $null }
        return
    }
    $arr = @($set | ForEach-Object {
        $e = New-Object KeeperSecurity.Enterprise.IdSelectedEntry
        $e.Id = $_
        $e.Selected = $true
        $e
    })
    if ($Property -eq 'RecordUids') { $Detail.RecordUids = $arr } else { $Detail.SharedFolderUids = $arr }
}

function ConvertFrom-KeeperAuditAlertFrequencyText {
    param([string] $Text)
    if ([string]::IsNullOrWhiteSpace($Text)) {
        return (New-Object KeeperSecurity.Enterprise.AlertFrequency -Property @{ period = 'event' })
    }
    $num = 0
    $occ = $Text
    $idx = $Text.IndexOf(':')
    if ($idx -ge 0) {
        $left = $Text.Substring(0, $idx).Trim()
        $occ = $Text.Substring($idx + 1).Trim().ToLowerInvariant()
        if ($left) { [int]::TryParse($left, [ref]$num) | Out-Null }
    } else {
        $occ = $Text.Trim().ToLowerInvariant()
    }

    switch -Regex ($occ) {
        '^e(vent)?$' { $occ = 'event' }
        '^m(inute|inutes)?$' { $occ = 'minutes' }
        '^h(our)?$' { $occ = 'hour' }
        '^d(ay)?$' { $occ = 'day' }
        default { Stop-KeeperAuditAlert "Invalid alert frequency `"$occ`". Use event, day, hour, minute, or N:period." }
    }

    if ($num -le 0) {
        if ($occ -eq 'event') { $num = 0 } else { $num = 1 }
    }

    $f = New-Object KeeperSecurity.Enterprise.AlertFrequency
    $f.Period = $occ
    if ($num -gt 0) { $f.Count = $num }
    return $f
}

function ConvertTo-KeeperAuditAlertFrequencyDisplay {
    param($Freq)
    if (-not $Freq) { return $null }
    $period = $Freq.Period
    $count = $Freq.Count
    if ($period -eq 'event') {
        if ($count -and $count -gt 0) { return "$count of Occurrences Triggered" }
        return 'Every Occurrence'
    }
    if ($period -in 'day', 'hour', 'minutes' -and $count -and $count -gt 0) {
        $p = if ($period -eq 'minutes') { 'Minute' } else { (Get-Culture).TextInfo.ToTitleCase($period) }
        return "$count $p(s) from First Occurrence"
    }
    return 'Not supported'
}

function Resolve-KeeperAuditAlertConfiguration {
    param(
        [Parameter(Mandatory)] $Settings,
        [Parameter(Mandatory)][string] $Target
    )
    if ($null -eq $Settings) {
        Stop-KeeperAuditAlert "Enterprise alert settings are not available. Ensure you are an enterprise admin and the server request succeeded."
    }
    if ([string]::IsNullOrWhiteSpace($Target)) { Stop-KeeperAuditAlert "Alert name or ID cannot be empty." }
    $filters = $Settings.AuditAlertFilter
    if (-not $filters -or $filters.Length -eq 0) {
        Stop-KeeperAuditAlert "No audit alerts are configured, or alert `"$Target`" was not found. Run Invoke-KeeperAuditAlert -Action list to see IDs and names."
    }

    $asNum = 0
    if ([int]::TryParse($Target, [ref]$asNum) -and $asNum -gt 0) {
        foreach ($a in $filters) {
            if ($a.Id -eq $asNum) { return $a }
        }
    }

    $matches = [System.Collections.Generic.List[KeeperSecurity.Enterprise.AuditAlertFilterEntry]]::new()
    $want = $Target.ToLowerInvariant()
    foreach ($a in $filters) {
        $n = $a.Name
        if ($n -and $n.ToLowerInvariant() -eq $want) { $matches.Add($a) }
    }
    if ($matches.Count -eq 0) {
        Stop-KeeperAuditAlert "No audit alert matches `"$Target`". Run Invoke-KeeperAuditAlert -Action list and use a real alert name or numeric ID for -Target."
    }
    if ($matches.Count -gt 1) {
        Stop-KeeperAuditAlert "There are $($matches.Count) alerts named `"$Target`". Use the alert ID."
    }
    return $matches[0]
}

function Invoke-KeeperAuditAlert {
    <#
    .SYNOPSIS
    Manage enterprise audit alerts (notifications).

    .DESCRIPTION
    Mirrors Python Commander `audit-alert`: list, view, history, delete, add, edit,
    reset-counts, enable, disable, and recipient management.

    .PARAMETER Action
    list | view | history | delete | add | edit | reset-counts | enable | disable | recipient

    .EXAMPLE
    Invoke-KeeperAuditAlert -Action list

    .EXAMPLE
    Invoke-KeeperAuditAlert -Action view -Target 'My Alert'

    .EXAMPLE
    Invoke-KeeperAuditAlert -Action add -Name 'Logins' -AuditEvent login -Frequency event
    #>
    [CmdletBinding(DefaultParameterSetName = 'list')]
    param(
        [Parameter(Mandatory, Position = 0)]
        [ValidateSet('list', 'view', 'history', 'delete', 'add', 'edit', 'reset-counts', 'enable', 'disable', 'recipient')]
        [string] $Action,

        [Parameter()][string] $Target,
        [Parameter()][switch] $Reload,
        [Parameter()][switch] $All,
        [Parameter()][int] $From,
        [Parameter()][int] $To,
        [Parameter()][switch] $Force,

        [Parameter()][ValidateSet('table', 'csv', 'json', 'pdf')]
        [string] $Format = 'table',

        [Parameter()][string] $Output,

        [Parameter()][string] $Name,
        [Parameter()][string] $Frequency,
        [Parameter()][string[]] $AuditEvent,
        [Parameter()][string[]] $User,
        [Parameter()][string[]] $RecordUid,
        [Parameter()][string[]] $SharedFolderUid,
        [Parameter()][ValidateSet('on', 'off')][string] $Active,

        [Parameter()][ValidateSet('enable', 'disable', 'delete', 'add', 'edit')]
        [string] $RecipientAction,

        [Parameter()][string] $Recipient,
        [Parameter()][string] $RecipientName,
        [Parameter()][string] $Email,
        [Parameter()][string] $Phone,
        [Parameter()][string] $Webhook,
        [Parameter()][string] $HttpBody,
        [Parameter()][ValidateSet('ignore', 'enforce')][string] $CertErrors,
        [Parameter()][switch] $GenerateToken
    )

    try {
        [Enterprise]$enterprise = getEnterprise
        $auth = $enterprise.loader.Auth
        $edata = $enterprise.enterpriseData

    function Write-AuditAlertTable($Objects, $Format, $OutputPath) {
        $eff = $Format
        if ($eff -eq 'pdf') {
            Write-Warning 'PDF format is not supported; using table.'
            $eff = 'table'
        }
        switch ($eff) {
            'json' {
                $j = $Objects | ConvertTo-Json -Depth 8
                if ($OutputPath) { Set-Content -Path $OutputPath -Value $j -Encoding utf8 } else { $j }
            }
            'csv' {
                $c = $Objects | ConvertTo-Csv -NoTypeInformation
                if ($OutputPath) { Set-Content -Path $OutputPath -Value $c -Encoding utf8 } else { $c }
            }
            default {
                if ($OutputPath) {
                    $tableOut = ($Objects | Format-Table -AutoSize -Wrap | Out-String -Width 8192).Trim()
                    Set-Content -Path $OutputPath -Value $tableOut -Encoding utf8
                } else {
                    $Objects | Format-Table -AutoSize -Wrap
                }
            }
        }
    }

    function Apply-AlertOptions([KeeperSecurity.Enterprise.AuditAlertFilterEntry] $Alert) {
        $eventMap = $script:AuditAlertEventTypes
        if ($Name) { $Alert.Name = $Name }
        if ($PSBoundParameters.ContainsKey('Frequency') -and $Frequency) {
            $Alert.Frequency = ConvertFrom-KeeperAuditAlertFrequencyText $Frequency
        }
        if (-not $Alert.Filter) {
            $Alert.Filter = New-Object KeeperSecurity.Enterprise.AuditAlertFilterDetail
        }
        $f = $Alert.Filter

        if ($AuditEvent -and $AuditEvent.Count -gt 0) {
            if (-not $eventMap -or 0 -eq $eventMap.Count) {
                Stop-KeeperAuditAlert "Audit event types are not loaded. Cannot validate -AuditEvent. Try again or sync enterprise data."
            }
            $ids = New-Object 'System.Collections.Generic.HashSet[int]'
            foreach ($chunk in $AuditEvent) {
                foreach ($evName in $chunk.Split(',')) {
                    $en = $evName.Trim().ToLowerInvariant()
                    if ([string]::IsNullOrEmpty($en)) { continue }
                    if (-not $eventMap.ContainsKey($en)) { Stop-KeeperAuditAlert "Event name `"$en`" is invalid." }
                    [void]$ids.Add($eventMap[$en])
                }
            }
            if ($ids.Count -gt 0) {
                $arr = [int[]]@($ids | Sort-Object)
                $f.Events = $arr
            } else {
                $f.Events = $null
            }
        }

        if ($User -and $User.Count -gt 0) {
            $emailLookup = @{}
            foreach ($eu in $edata.Users) {
                if ($eu.Email) { $emailLookup[$eu.Email.ToLowerInvariant()] = $eu }
            }
            $userIds = New-Object 'System.Collections.Generic.HashSet[long]'
            foreach ($chunk in $User) {
                foreach ($un in $chunk.Split(',')) {
                    $u = $un.Trim().ToLowerInvariant()
                    if ([string]::IsNullOrEmpty($u)) { continue }
                    $eu = $emailLookup[$u]
                    if (-not $eu) { Stop-KeeperAuditAlert "Username `"$u`" is unknown." }
                    [void]$userIds.Add([long]$eu.Id)
                }
            }
            if ($userIds.Count -gt 0) {
                $f.UserIds = [long[]]@($userIds)
            } else {
                $f.UserIds = $null
            }
        }

        if ($RecordUid -and $RecordUid.Count -gt 0) {
            Set-KeeperAuditFilterIdSelectedEntries -Detail $f -Property RecordUids -Chunks $RecordUid
        }

        if ($SharedFolderUid -and $SharedFolderUid.Count -gt 0) {
            Set-KeeperAuditFilterIdSelectedEntries -Detail $f -Property SharedFolderUids -Chunks $SharedFolderUid
        }
    }

    function Apply-RecipientOptions([KeeperSecurity.Enterprise.AlertRecipient] $R) {
        if ($PSBoundParameters.ContainsKey('RecipientName') -and $RecipientName) { $R.Name = $RecipientName }
        if ($PSBoundParameters.ContainsKey('Email')) { $R.Email = $Email }
        if ($PSBoundParameters.ContainsKey('Phone')) {
            $ph = $Phone
            if ($ph) {
                if ($ph.StartsWith('+')) {
                    $rest = $ph.Substring(1).Trim()
                    $pc = ''
                    $i = 0
                    while ($i -lt $rest.Length -and [char]::IsDigit($rest[$i])) {
                        $pc += $rest[$i]
                        $i++
                    }
                    $phoneCountry = if ($pc) { [int]$pc } else { 1 }
                    $R.PhoneCountry = $phoneCountry
                    $R.Phone = $rest.Substring($i).Trim()
                } else {
                    $R.PhoneCountry = 1
                    $R.Phone = $ph.Trim()
                }
            } else {
                $R.Phone = $null
                $R.PhoneCountry = $null
            }
        }
        if ($PSBoundParameters.ContainsKey('Webhook')) {
            if ([string]::IsNullOrEmpty($Webhook)) {
                $R.Webhook = $null
            } else {
                if (-not $R.Webhook) {
                    $R.Webhook = New-Object KeeperSecurity.Enterprise.AlertWebhookInfo
                    $R.Webhook.Url = $Webhook
                    $R.Webhook.Token = [KeeperSecurity.Utils.CryptoUtils]::GenerateUid()
                    $R.Webhook.AllowUnverifiedCertificate = $false
                } else {
                    $R.Webhook.Url = $Webhook
                }
            }
        }
        if ($PSBoundParameters.ContainsKey('HttpBody') -and $R.Webhook) {
            $hb = $HttpBody
            if ($hb -and $hb.StartsWith('@')) {
                $path = $hb.Substring(1)
                $path = [Environment]::ExpandEnvironmentVariables($path)
                if (-not (Test-Path -LiteralPath $path)) { Stop-KeeperAuditAlert "File `"$path`" not found." }
                $R.Webhook.Template = [System.IO.File]::ReadAllText($path)
            } elseif ($hb) {
                $R.Webhook.Template = $hb
            } else {
                $R.Webhook.Template = $null
            }
        }
        if ($PSBoundParameters.ContainsKey('CertErrors') -and $R.Webhook) {
            $R.Webhook.AllowUnverifiedCertificate = ($CertErrors -eq 'ignore')
        }
        if ($GenerateToken.IsPresent -and $R.Webhook) {
            $R.Webhook.Token = [KeeperSecurity.Utils.CryptoUtils]::GenerateUid()
        }
    }

    function Find-Recipient([KeeperSecurity.Enterprise.AuditAlertFilterEntry] $Alert, [string] $NameOrId) {
        $recs = $Alert.Recipients
        if (-not $recs) { Stop-KeeperAuditAlert "Recipient `"$NameOrId`" not found on this alert." }
        $rid = 0
        if ([int]::TryParse($NameOrId, [ref]$rid) -and $rid -gt 0) {
            foreach ($r in $recs) { if ($r.Id -eq $rid) { return $r } }
        }
        $want = $NameOrId.ToLowerInvariant()
        $hits = [System.Collections.Generic.List[KeeperSecurity.Enterprise.AlertRecipient]]::new()
        foreach ($r in $recs) {
            $n = $r.Name
            if ($n -and $n.ToLowerInvariant() -eq $want) { $hits.Add($r) }
        }
        if ($hits.Count -eq 0) { Stop-KeeperAuditAlert "Recipient `"$NameOrId`" not found on this alert." }
        if ($hits.Count -gt 1) {
            Stop-KeeperAuditAlert "There are $($hits.Count) recipients named `"$NameOrId`". Use recipient ID."
        }
        return $hits[0]
    }

    function Invoke-KeeperAuditAlertEnableDisable {
        param([Parameter(Mandatory)][bool] $Disabled)
        if ($All.IsPresent -and $Target) { Stop-KeeperAuditAlert "Cannot use -All together with -Target." }
        if ($All.IsPresent) {
            $list = New-Object 'System.Collections.Generic.List[KeeperSecurity.Commands.KeeperApiCommand]'
            foreach ($a in $settings.AuditAlertFilter) {
                if (-not $a.Id) { continue }
                $patch = New-Object KeeperSecurity.Enterprise.AuditAlertContextPatch
                $patch.Id = $a.Id
                $patch.Disabled = $Disabled
                $cmd = New-Object KeeperSecurity.Enterprise.PutAuditAlertContextEnterpriseSettingCommand
                $cmd.Settings = $patch
                [void]$list.Add($cmd)
            }
            if ($list.Count -eq 0) {
                Write-Host "No valid alerts found to $Action."
                return
            }
            try {
                $batchOut = [KeeperSecurity.Authentication.AuthExtensions]::ExecuteBatch($auth, $list).GetAwaiter().GetResult()
            } catch {
                Write-Error "Batch $Action failed (execute): $($_.Exception.Message)" -ErrorAction Stop
            }
            $verb = if ($Disabled) { 'disable' } else { 'enable' }
            $bi = 0
            foreach ($resp in $batchOut) {
                $bi++
                Assert-KeeperApiResponse -Response $resp -Context "$verb all alerts ($bi/$($batchOut.Count))"
            }
            Clear-KeeperAuditAlertCache
            $past = if ($Disabled) { 'Disabled' } else { 'Enabled' }
            Write-Host "$past $($list.Count) alert(s)."
            Invoke-KeeperAuditAlert -Action list -Reload
            return
        }
        if ([string]::IsNullOrWhiteSpace($Target)) { Stop-KeeperAuditAlert "$Action requires -Target or -All." }
        $alert = Resolve-KeeperAuditAlertConfiguration -Settings $settings -Target $Target
        $patch = New-Object KeeperSecurity.Enterprise.AuditAlertContextPatch
        $patch.Id = $alert.Id
        $patch.Disabled = $Disabled
        $put = New-Object KeeperSecurity.Enterprise.PutAuditAlertContextEnterpriseSettingCommand
        $put.Settings = $patch
        $putRs = $auth.ExecuteAuthCommand($put, [KeeperSecurity.Commands.KeeperApiResponse], $true).GetAwaiter().GetResult()
        $ctxLabel = if ($Disabled) { 'put audit alert context (disable)' } else { 'put audit alert context (enable)' }
        Assert-KeeperApiResponse -Response $putRs -Context $ctxLabel
        Clear-KeeperAuditAlertCache
        if ($Disabled) {
            Write-Host "Alert `"$($alert.Name)`" has been disabled."
        } else {
            Write-Host "Alert `"$($alert.Name)`" has been enabled."
        }
        Invoke-KeeperAuditAlert -Action view -Target $Target -Format $Format -Output $Output
    }

    $settings = Get-KeeperAuditAlertSettingsInternal -Auth $auth -EnterpriseData $edata -Reload:$Reload

    switch ($Action) {
        'list' {
            if (-not $settings -or -not $settings.AuditAlertFilter -or $settings.AuditAlertFilter.Length -eq 0) {
                Write-Host "No alerts found."
                return
            }
            $revMap = Get-KeeperAuditAlertEventReverseMap

            $rows = [System.Collections.Generic.List[object]]::new()
            foreach ($alert in $settings.AuditAlertFilter) {
                $ctx = Get-KeeperAuditAlertContext -Settings $settings -AlertId $alert.Id
                $lastSent = $null
                $occCount = $null
                $sentCount = $null
                $disabled = $false
                if ($ctx) {
                    $lastSent = $ctx.LastSent
                    $occCount = $ctx.Counter
                    $sentCount = $ctx.SentCounter
                    $disabled = [bool]$ctx.Disabled
                }

                $evText = ''
                if ($alert.Filter -and $alert.Filter.Events -and $alert.Filter.Events.Length -gt 0) {
                    $names = foreach ($eid in $alert.Filter.Events) {
                        if ($revMap.ContainsKey($eid)) { $revMap[$eid] } else { "$eid" }
                    }
                    $names = @($names)
                    if ($names.Length -eq 1) { $evText = $names[0] }
                    elseif ($names.Length -le 5) { $evText = ($names -join "`n") }
                    else { $evText = (($names[0..3] -join "`n") + "`n+$($names.Length - 4) more") }
                }

                $freq = ConvertTo-KeeperAuditAlertFrequencyDisplay $alert.Frequency
                if ($lastSent) {
                    try {
                        $dto = [DateTimeOffset]::Parse($lastSent, $null, [System.Globalization.DateTimeStyles]::AssumeUniversal)
                        $lastSent = $dto.LocalDateTime.ToString('g')
                    } catch { }
                }

                $rows.Add([PSCustomObject]@{
                    Id           = $alert.Id
                    Name         = $alert.Name
                    Events       = $evText
                    Frequency    = $freq
                    Occurrences  = $occCount
                    AlertsSent   = $sentCount
                    LastSent     = $lastSent
                    Active       = (-not $disabled)
                })
            }
            $out = $rows | Sort-Object Id
            Write-AuditAlertTable $out $Format $Output
            return
        }

        'view' {
            $revMap = Get-KeeperAuditAlertEventReverseMap
            if ($All.IsPresent -or [string]::IsNullOrWhiteSpace($Target)) {
                if (-not $settings -or -not $settings.AuditAlertFilter) { Write-Host 'No alerts found.'; return }
                $rows = foreach ($alert in $settings.AuditAlertFilter) {
                    $ctx = Get-KeeperAuditAlertContext -Settings $settings -AlertId $alert.Id
                    $ctxDisabled = if ($ctx) { [bool]$ctx.Disabled } else { $false }
                    $ls = if ($ctx) { $ctx.LastSent } else { $null }
                    $oc = if ($ctx) { $ctx.Counter } else { $null }
                    $sc = if ($ctx) { $ctx.SentCounter } else { $null }
                    $fd = $alert.Filter
                    $evNames = @()
                    if ($fd -and $fd.Events) {
                        foreach ($eid in $fd.Events) {
                            if ($revMap.ContainsKey($eid)) { $evNames += $revMap[$eid] } else { $evNames += "$eid" }
                        }
                    }
                    $users = @()
                    if ($fd -and $fd.UserIds) {
                        foreach ($uid in $fd.UserIds) {
                            $users += Get-KeeperAuditAlertUserEmailForId -EnterpriseData $edata -UserId ([long]$uid)
                        }
                    }
                    $sf = @()
                    if ($fd -and $fd.SharedFolderUids) { $sf = @($fd.SharedFolderUids | ForEach-Object { $_.Id }) }
                    $rec = @()
                    if ($fd -and $fd.RecordUids) { $rec = @($fd.RecordUids | ForEach-Object { $_.Id }) }
                    $recipJson = (@{
                        SendToOriginator = $alert.SendToOriginator
                        Recipients       = $alert.Recipients
                    } | ConvertTo-Json -Depth 6)

                    [PSCustomObject]@{
                        AlertId      = $alert.Id
                        AlertName    = $alert.Name
                        Status       = if ($ctxDisabled) { 'Disabled' } else { 'Enabled' }
                        Frequency    = (ConvertTo-KeeperAuditAlertFrequencyDisplay $alert.Frequency)
                        Occurrences  = $oc
                        SentCounter  = $sc
                        LastSent     = $ls
                        EventTypes   = ($evNames -join "`n")
                        Users        = ($users -join "`n")
                        SharedFolders = ($sf -join "`n")
                        Records      = ($rec -join "`n")
                        Recipients   = $recipJson
                    }
                }
                Write-AuditAlertTable @($rows) $Format $Output
                return
            }

            $alert = Resolve-KeeperAuditAlertConfiguration -Settings $settings -Target $Target
            $ctx = Get-KeeperAuditAlertContext -Settings $settings -AlertId $alert.Id
            $lines = [System.Collections.Generic.List[object]]::new()
            $lines.Add([PSCustomObject]@{ Name = 'Alert ID'; Value = $alert.Id })
            $lines.Add([PSCustomObject]@{ Name = 'Alert name'; Value = $alert.Name })
            $lines.Add([PSCustomObject]@{ Name = 'Status'; Value = $(if ($ctx -and $ctx.Disabled) { 'Disabled' } else { 'Enabled' }) })
            $ls = if ($ctx) { $ctx.LastSent } else { $null }
            if ($ls) {
                try {
                    $dto = [DateTimeOffset]::Parse($ls, $null, [System.Globalization.DateTimeStyles]::AssumeUniversal)
                    $ls = $dto.LocalDateTime.ToString('o')
                } catch { }
            }
            $lines.Add([PSCustomObject]@{ Name = 'Frequency'; Value = (ConvertTo-KeeperAuditAlertFrequencyDisplay $alert.Frequency) })
            $lines.Add([PSCustomObject]@{ Name = 'Occurrences'; Value = $(if ($ctx) { $ctx.Counter } else { $null }) })
            $lines.Add([PSCustomObject]@{ Name = 'Sent Counter'; Value = $(if ($ctx) { $ctx.SentCounter } else { $null }) })
            $lines.Add([PSCustomObject]@{ Name = 'Last Sent'; Value = $ls })

            $fd = $alert.Filter
            if ($fd) {
                if ($fd.Events -and $fd.Events.Length -gt 0) {
                    $evNames = foreach ($eid in $fd.Events) { if ($revMap.ContainsKey($eid)) { $revMap[$eid] } else { "$eid" } }
                    $lines.Add([PSCustomObject]@{ Name = 'Event Types'; Value = ($evNames -join ', ') })
                }
                if ($fd.UserIds -and $fd.UserIds.Length -gt 0) {
                    $un = foreach ($uid in $fd.UserIds) {
                        Get-KeeperAuditAlertUserEmailForId -EnterpriseData $edata -UserId ([long]$uid)
                    }
                    $lines.Add([PSCustomObject]@{ Name = 'User'; Value = ($un -join ', ') })
                }
                if ($fd.SharedFolderUids -and $fd.SharedFolderUids.Length -gt 0) {
                    $lines.Add([PSCustomObject]@{ Name = 'Shared Folder'; Value = (($fd.SharedFolderUids | ForEach-Object { $_.Id }) -join ', ') })
                }
                if ($fd.RecordUids -and $fd.RecordUids.Length -gt 0) {
                    $lines.Add([PSCustomObject]@{ Name = 'Record'; Value = (($fd.RecordUids | ForEach-Object { $_.Id }) -join ', ') })
                }
            }

            $lines.Add([PSCustomObject]@{ Name = 'Send To Originator (*)'; Value = $alert.SendToOriginator })
            if ($alert.Recipients) {
                foreach ($r in $alert.Recipients) {
                    $lines.Add([PSCustomObject]@{ Name = '--- Recipient'; Value = $r.Id })
                    $lines.Add([PSCustomObject]@{ Name = 'Name'; Value = $r.Name })
                    $lines.Add([PSCustomObject]@{ Name = 'Status'; Value = $(if ($r.Disabled) { 'Disabled' } else { 'Enabled' }) })
                    if ($r.Webhook) {
                        $lines.Add([PSCustomObject]@{ Name = 'Webhook URL'; Value = $r.Webhook.Url })
                        if ($r.Webhook.Template) { $lines.Add([PSCustomObject]@{ Name = 'HTTP Body'; Value = $r.Webhook.Template }) }
                        if ($r.Webhook.Token) { $lines.Add([PSCustomObject]@{ Name = 'Webhook Token'; Value = $r.Webhook.Token }) }
                        $lines.Add([PSCustomObject]@{ Name = 'Certificate Errors'; Value = $(if ($r.Webhook.AllowUnverifiedCertificate) { 'Ignore' } else { 'Enforce' }) })
                    }
                    if ($r.Email) { $lines.Add([PSCustomObject]@{ Name = 'Email To'; Value = $r.Email }) }
                    if ($r.Phone) {
                        $pd = if ($r.PhoneCountry) { "(+$($r.PhoneCountry)) $($r.Phone)" } else { $r.Phone }
                        $lines.Add([PSCustomObject]@{ Name = 'Text To'; Value = $pd })
                    }
                }
            }

            Write-AuditAlertTable @($lines) $Format $Output
        }

        'history' {
            if ([string]::IsNullOrWhiteSpace($Target)) {
                Stop-KeeperAuditAlert 'history requires -Target (alert ID or name).'
            }
            $alert = Resolve-KeeperAuditAlertConfiguration -Settings $settings -Target $Target
            $rq = New-Object KeeperSecurity.Enterprise.AuditLogCommands.GetAuditEventReportsCommand
            $rq.ReportType = 'raw'
            $rq.ReportFormat = 'fields'
            $rq.Limit = 100
            $rq.Order = 'descending'
            $f = New-Object KeeperSecurity.Enterprise.AuditLogCommands.ReportFilter
            $f.EventTypes = @('audit_alert_sent')
            $f.ParentId = [long]$alert.AlertUid
            $rq.Filter = $f
            try {
                $rs = $auth.ExecuteAuthCommand($rq, [KeeperSecurity.Enterprise.AuditLogCommands.GetAuditEventReportsResponse], $true).GetAwaiter().GetResult()
            } catch {
                Write-Error "Failed to load alert history (get_audit_event_reports): $($_.Exception.Message)" -ErrorAction Stop
            }
            Assert-KeeperApiResponse -Response $rs -Context 'get_audit_event_reports (alert history)'
            if (-not $rs.Events -or $rs.Events.Count -eq 0) {
                Write-Host 'No alert history events found.'
                return
            }
            $table = [System.Collections.Generic.List[object]]::new()
            foreach ($evt in $rs.Events) {
                $rec = ''
                if ($evt.ContainsKey('recipient')) { $rec = $evt['recipient'].ToString() }
                if ($rec -eq 'throttled') {
                    if ($table.Count -gt 0) {
                        $last = $table[$table.Count - 1]
                        $last.Occurrences = [int]$last.Occurrences + 1
                    }
                } else {
                    $created = ''
                    if ($evt.ContainsKey('created')) {
                        $cr = $evt['created'].ToString()
                        $epoch = 0L
                        if ([long]::TryParse($cr, [ref]$epoch)) {
                            $created = [DateTimeOffset]::FromUnixTimeSeconds($epoch).LocalDateTime.ToString('g')
                        } else { $created = $cr }
                    }
                    $table.Add([PSCustomObject]@{ AlertSentAt = $created; Occurrences = 1 })
                }
            }
            Write-AuditAlertTable @($table) $Format $Output
        }

        'delete' {
            if (-not $settings -or -not $settings.AuditAlertFilter -or $settings.AuditAlertFilter.Length -eq 0) {
                Write-Host 'No alerts found.'
                return
            }
            $toDelete = @()
            if ($PSBoundParameters.ContainsKey('From') -and $PSBoundParameters.ContainsKey('To')) {
                if ($From -le 0 -or $To -le 0) { Stop-KeeperAuditAlert 'Alert IDs must be positive integers.' }
                if ($From -ge $To) { Stop-KeeperAuditAlert "--From ($From) must be less than --To ($To)." }
                foreach ($a in $settings.AuditAlertFilter) {
                    if ($a.Id -ge $From -and $a.Id -le $To) { $toDelete += $a }
                }
                if ($toDelete.Count -eq 0) { Stop-KeeperAuditAlert "No alerts found in range $From-$To" }
            }
            elseif ($All.IsPresent) {
                $toDelete = @($settings.AuditAlertFilter)
            }
            elseif ($Target) {
                $toDelete = @(Resolve-KeeperAuditAlertConfiguration -Settings $settings -Target $Target)
            } else {
                Stop-KeeperAuditAlert 'delete requires -Target, -All, or both -From and -To.'
            }

            if (-not $Force.IsPresent) {
                Write-Host ""
                Write-Host "The following $($toDelete.Count) alert(s) will be deleted:"
                Write-Host ("-" * 60)
                foreach ($a in $toDelete) { Write-Host "  ID: $($a.Id) | Name: $($a.Name)" }
                Write-Host ("-" * 60)
                $resp = Read-Host "Are you sure you want to delete $($toDelete.Count) alert(s)? (y/n)"
                if ($resp -notin 'y', 'yes') { Write-Host 'Deletion cancelled.'; return }
            }

            $deleted = 0
            foreach ($a in $toDelete) {
                try {
                    $dq = New-Object KeeperSecurity.Enterprise.DeleteEnterpriseSettingCommand
                    $dq.Type = 'AuditAlertFilter'
                    $dq.Id = $a.Id
                    $delRs = $auth.ExecuteAuthCommand($dq, [KeeperSecurity.Commands.KeeperApiResponse], $true).GetAwaiter().GetResult()
                    Assert-KeeperApiResponse -Response $delRs -Context "delete enterprise setting (AuditAlertFilter id $($a.Id))"
                    $deleted++
                } catch {
                    Write-Warning "Failed to delete alert $($a.Name) (ID $($a.Id)): $($_.Exception.Message)"
                }
            }
            Clear-KeeperAuditAlertCache
            if ($deleted -gt 0) { Invoke-KeeperAuditAlert -Action list -Reload }
            else { Write-Warning 'No alerts were deleted.' }
        }

        'add' {
            if ([string]::IsNullOrWhiteSpace($Name)) { Stop-KeeperAuditAlert 'add requires -Name.' }
            $settings = Get-KeeperAuditAlertSettingsInternal -Auth $auth -EnterpriseData $edata -Reload
            $existing = $settings.AuditAlertFilter
            foreach ($x in $existing) {
                if ($x.Name -and $x.Name.ToLowerInvariant() -eq $Name.ToLowerInvariant()) {
                    Stop-KeeperAuditAlert "Alert name `"$Name`" is not unique."
                }
            }
            $maxId = 0
            foreach ($x in $existing) { if ($x.Id -gt $maxId) { $maxId = $x.Id } }
            $newId = $maxId + 1
            $alert = New-Object KeeperSecurity.Enterprise.AuditAlertFilterEntry
            $alert.Id = $newId
            $alert.AlertUid = Get-Random -Minimum 1 -Maximum ([int]::MaxValue)
            $alert.Name = $Name
            $alert.Frequency = New-Object KeeperSecurity.Enterprise.AlertFrequency
            $alert.Frequency.Period = 'event'
            $alert.Filter = New-Object KeeperSecurity.Enterprise.AuditAlertFilterDetail

            Apply-AlertOptions $alert

            $put = New-Object KeeperSecurity.Enterprise.PutAuditAlertFilterEnterpriseSettingCommand
            $put.Settings = $alert
            $putRs = $auth.ExecuteAuthCommand($put, [KeeperSecurity.Commands.KeeperApiResponse], $true).GetAwaiter().GetResult()
            Assert-KeeperApiResponse -Response $putRs -Context 'put audit alert filter (add)'

            if ($Active -eq 'off') {
                $ctx = New-Object KeeperSecurity.Enterprise.AuditAlertContextPatch
                $ctx.Id = $newId
                $ctx.Disabled = $true
                $p2 = New-Object KeeperSecurity.Enterprise.PutAuditAlertContextEnterpriseSettingCommand
                $p2.Settings = $ctx
                $putCtxRs = $auth.ExecuteAuthCommand($p2, [KeeperSecurity.Commands.KeeperApiResponse], $true).GetAwaiter().GetResult()
                Assert-KeeperApiResponse -Response $putCtxRs -Context 'put audit alert context (add, disabled)'
            }
            Clear-KeeperAuditAlertCache
            Invoke-KeeperAuditAlert -Action view -Target "$newId" -Format $Format -Output $Output
        }

        'edit' {
            if ([string]::IsNullOrWhiteSpace($Target)) { Stop-KeeperAuditAlert 'edit requires -Target.' }
            $alert = Resolve-KeeperAuditAlertConfiguration -Settings $settings -Target $Target
            Apply-AlertOptions $alert

            $put = New-Object KeeperSecurity.Enterprise.PutAuditAlertFilterEnterpriseSettingCommand
            $put.Settings = $alert
            $putRs = $auth.ExecuteAuthCommand($put, [KeeperSecurity.Commands.KeeperApiResponse], $true).GetAwaiter().GetResult()
            Assert-KeeperApiResponse -Response $putRs -Context 'put audit alert filter (edit)'

            if ($Active) {
                $ctx = Get-KeeperAuditAlertContext -Settings $settings -AlertId $alert.Id
                $curOff = $ctx -and $ctx.Disabled
                $wantOff = ($Active -eq 'off')
                if ($curOff -ne $wantOff) {
                    $patch = New-Object KeeperSecurity.Enterprise.AuditAlertContextPatch
                    $patch.Id = $alert.Id
                    $patch.Disabled = $wantOff
                    $p2 = New-Object KeeperSecurity.Enterprise.PutAuditAlertContextEnterpriseSettingCommand
                    $p2.Settings = $patch
                    $putCtxRs = $auth.ExecuteAuthCommand($p2, [KeeperSecurity.Commands.KeeperApiResponse], $true).GetAwaiter().GetResult()
                    Assert-KeeperApiResponse -Response $putCtxRs -Context 'put audit alert context (edit active state)'
                }
            }
            Clear-KeeperAuditAlertCache
            Invoke-KeeperAuditAlert -Action view -Target $Target -Format $Format -Output $Output
        }

        'reset-counts' {
            if ([string]::IsNullOrWhiteSpace($Target)) { Stop-KeeperAuditAlert 'reset-counts requires -Target.' }
            $alert = Resolve-KeeperAuditAlertConfiguration -Settings $settings -Target $Target
            $patch = New-Object KeeperSecurity.Enterprise.AuditAlertContextPatch
            $patch.Id = $alert.Id
            $patch.Counter = 0
            $patch.SentCounter = 0
            $patch.LastReset = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
            $put = New-Object KeeperSecurity.Enterprise.PutAuditAlertContextEnterpriseSettingCommand
            $put.Settings = $patch
            $putRs = $auth.ExecuteAuthCommand($put, [KeeperSecurity.Commands.KeeperApiResponse], $true).GetAwaiter().GetResult()
            Assert-KeeperApiResponse -Response $putRs -Context 'put audit alert context (reset-counts)'
            Clear-KeeperAuditAlertCache
            Write-Host 'Alert counts reset to zero.'
        }

        'enable' {
            Invoke-KeeperAuditAlertEnableDisable -Disabled $false
        }

        'disable' {
            Invoke-KeeperAuditAlertEnableDisable -Disabled $true
        }

        'recipient' {
            if ([string]::IsNullOrWhiteSpace($Target)) { Stop-KeeperAuditAlert 'recipient requires -Target alert.' }
            if ([string]::IsNullOrWhiteSpace($RecipientAction)) { Stop-KeeperAuditAlert 'recipient requires -RecipientAction (enable|disable|delete|add|edit).' }
            $alert = Resolve-KeeperAuditAlertConfiguration -Settings $settings -Target $Target

            switch ($RecipientAction) {
                'enable' {
                    if ([string]::IsNullOrWhiteSpace($Recipient)) { Stop-KeeperAuditAlert 'recipient enable requires -Recipient.' }
                    if ($Recipient -eq '*') { $alert.SendToOriginator = $true }
                    else {
                        $r = Find-Recipient $alert $Recipient
                        $r.Disabled = $false
                    }
                }
                'disable' {
                    if ([string]::IsNullOrWhiteSpace($Recipient)) { Stop-KeeperAuditAlert 'recipient disable requires -Recipient.' }
                    if ($Recipient -eq '*') { $alert.SendToOriginator = $false }
                    else {
                        $r = Find-Recipient $alert $Recipient
                        $r.Disabled = $true
                    }
                }
                'delete' {
                    if ([string]::IsNullOrWhiteSpace($Recipient)) { Stop-KeeperAuditAlert 'recipient delete requires -Recipient.' }
                    $r = Find-Recipient $alert $Recipient
                    $list = [System.Collections.Generic.List[KeeperSecurity.Enterprise.AlertRecipient]]::new()
                    foreach ($x in $alert.Recipients) { if ($x.Id -ne $r.Id) { $list.Add($x) } }
                    $alert.Recipients = $list.ToArray()
                }
                'edit' {
                    if ([string]::IsNullOrWhiteSpace($Recipient)) { Stop-KeeperAuditAlert 'recipient edit requires -Recipient.' }
                    $r = Find-Recipient $alert $Recipient
                    Apply-RecipientOptions $r
                }
                'add' {
                    if (-not $alert.Recipients) { $alert.Recipients = @() }
                    $ids = @($alert.Recipients | ForEach-Object { $_.Id })
                    $newId = 0
                    for ($i = 1; $i -le 1000; $i++) {
                        if ($ids -notcontains $i) { $newId = $i; break }
                    }
                    if ($newId -eq 0) { Stop-KeeperAuditAlert 'Could not allocate recipient id.' }
                    $r = New-Object KeeperSecurity.Enterprise.AlertRecipient
                    $r.Id = $newId
                    $alert.Recipients = @($alert.Recipients) + @($r)
                    Apply-RecipientOptions $r
                }
            }

            $put = New-Object KeeperSecurity.Enterprise.PutAuditAlertFilterEnterpriseSettingCommand
            $put.Settings = $alert
            $putRs = $auth.ExecuteAuthCommand($put, [KeeperSecurity.Commands.KeeperApiResponse], $true).GetAwaiter().GetResult()
            Assert-KeeperApiResponse -Response $putRs -Context 'put audit alert filter (recipient)'
            Clear-KeeperAuditAlertCache
            Invoke-KeeperAuditAlert -Action view -Target $Target -Format $Format -Output $Output
        }
    }
    } catch {
        $ex = $_.Exception
        while ($null -ne $ex.InnerException) { $ex = $ex.InnerException }
        if ($ex -is [KeeperSecurity.Authentication.KeeperApiException]) {
            Write-Error "Keeper API [$($ex.Code)]: $($ex.Message)" -ErrorAction Stop
        }
        throw
    }
}
