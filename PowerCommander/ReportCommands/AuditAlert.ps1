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
    Fail if a Keeper API response indicates an error.
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
    Stop execution with a formatted error message.
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
        Stop-KeeperAuditAlert "No audit alerts are configured, or alert `"$Target`" was not found. Run Get-KeeperAuditAlert -Action list to see IDs and names."
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
        Stop-KeeperAuditAlert "No audit alert matches `"$Target`". Run Get-KeeperAuditAlert -Action list and use a real alert name or numeric ID for -Target."
    }
    if ($matches.Count -gt 1) {
        Stop-KeeperAuditAlert "There are $($matches.Count) alerts named `"$Target`". Use the alert ID."
    }
    return $matches[0]
}

function Write-AuditAlertTable {
    param($Objects, [string] $Format, [string] $OutputPath)
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

function Find-AuditAlertRecipient {
    param(
        [Parameter(Mandatory)][KeeperSecurity.Enterprise.AuditAlertFilterEntry] $Alert,
        [Parameter(Mandatory)][string] $NameOrId
    )
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

function Apply-AuditAlertOptions {
    param(
        [Parameter(Mandatory)][KeeperSecurity.Enterprise.AuditAlertFilterEntry] $Alert,
        [Parameter(Mandatory)][KeeperSecurity.Enterprise.EnterpriseData] $EnterpriseData,
        [Parameter(Mandatory)][hashtable] $CallerParams
    )
    $eventMap = $script:AuditAlertEventTypes

    $Name = $CallerParams['Name']
    if ($Name) { $Alert.Name = $Name }

    if ($CallerParams.ContainsKey('Frequency') -and $CallerParams['Frequency']) {
        $Alert.Frequency = ConvertFrom-KeeperAuditAlertFrequencyText $CallerParams['Frequency']
    }

    if (-not $Alert.Filter) {
        $Alert.Filter = New-Object KeeperSecurity.Enterprise.AuditAlertFilterDetail
    }
    $f = $Alert.Filter

    $AuditEvent = $CallerParams['AuditEvent']
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

    $User = $CallerParams['User']
    if ($User -and $User.Count -gt 0) {
        $emailLookup = @{}
        foreach ($eu in $EnterpriseData.Users) {
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

    $RecordUid = $CallerParams['RecordUid']
    if ($RecordUid -and $RecordUid.Count -gt 0) {
        $vault = getVault
        foreach ($chunk in $RecordUid) {
            foreach ($r in $chunk.Split(',')) {
                $uid = $r.Trim()
                if ([string]::IsNullOrEmpty($uid)) { continue }
                [KeeperSecurity.Vault.KeeperRecord] $rec = $null
                if (-not $vault.TryGetRecord($uid, [ref]$rec)) {
                    Stop-KeeperAuditAlert "Record UID `"$uid`" was not found in the vault."
                }
            }
        }
        Set-KeeperAuditFilterIdSelectedEntries -Detail $f -Property RecordUids -Chunks $RecordUid
    }

    $SharedFolderUid = $CallerParams['SharedFolderUid']
    if ($SharedFolderUid -and $SharedFolderUid.Count -gt 0) {
        $vault = getVault
        foreach ($chunk in $SharedFolderUid) {
            foreach ($s in $chunk.Split(',')) {
                $uid = $s.Trim()
                if ([string]::IsNullOrEmpty($uid)) { continue }
                [KeeperSecurity.Vault.SharedFolder] $sf = $null
                if (-not $vault.TryGetSharedFolder($uid, [ref]$sf)) {
                    Stop-KeeperAuditAlert "Shared folder UID `"$uid`" was not found in the vault."
                }
            }
        }
        Set-KeeperAuditFilterIdSelectedEntries -Detail $f -Property SharedFolderUids -Chunks $SharedFolderUid
    }
}

function Apply-AuditAlertRecipientOptions {
    param(
        [Parameter(Mandatory)][KeeperSecurity.Enterprise.AlertRecipient] $R,
        [Parameter(Mandatory)][hashtable] $CallerParams
    )
    if ($CallerParams.ContainsKey('RecipientName') -and $CallerParams['RecipientName']) { $R.Name = $CallerParams['RecipientName'] }
    if ($CallerParams.ContainsKey('Email')) { $R.Email = $CallerParams['Email'] }
    if ($CallerParams.ContainsKey('Phone')) {
        $ph = $CallerParams['Phone']
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
    if ($CallerParams.ContainsKey('Webhook')) {
        $Webhook = $CallerParams['Webhook']
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
    if ($CallerParams.ContainsKey('HttpBody') -and $R.Webhook) {
        $hb = $CallerParams['HttpBody']
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
    if ($CallerParams.ContainsKey('CertErrors') -and $R.Webhook) {
        $R.Webhook.AllowUnverifiedCertificate = ($CallerParams['CertErrors'] -eq 'ignore')
    }
    $gt = $CallerParams['GenerateToken']
    if ($gt -is [switch] -and $gt.IsPresent -and $R.Webhook) {
        $R.Webhook.Token = [KeeperSecurity.Utils.CryptoUtils]::GenerateUid()
    }
}

function Invoke-AuditAlertList {
    param($Settings, [string] $Format, [string] $Output)

    if (-not $Settings -or -not $Settings.AuditAlertFilter -or $Settings.AuditAlertFilter.Length -eq 0) {
        Write-Host "No alerts found."
        return
    }
    $revMap = Get-KeeperAuditAlertEventReverseMap

    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($alert in $Settings.AuditAlertFilter) {
        $ctx = Get-KeeperAuditAlertContext -Settings $Settings -AlertId $alert.Id
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
            if ($Format -eq 'json') {
                $evText = $names
            } elseif ($Format -eq 'csv') {
                $evText = $names -join ', '
            } else {
                if ($names.Length -eq 1) { $evText = $names[0] }
                elseif ($names.Length -le 3) { $evText = ($names -join ', ') }
                else { $evText = "$($names[0]), $($names[1]) +$($names.Length - 2) more" }
            }
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
}

function Invoke-AuditAlertView {
    param(
        $Settings,
        [KeeperSecurity.Enterprise.EnterpriseData] $EnterpriseData,
        [string] $Target,
        [switch] $All,
        [string] $Format,
        [string] $Output
    )
    $revMap = Get-KeeperAuditAlertEventReverseMap

    if ($All.IsPresent -or [string]::IsNullOrWhiteSpace($Target)) {
        if (-not $Settings -or -not $Settings.AuditAlertFilter) { Write-Host 'No alerts found.'; return }
        $rows = foreach ($alert in $Settings.AuditAlertFilter) {
            $ctx = Get-KeeperAuditAlertContext -Settings $Settings -AlertId $alert.Id
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
                    $users += Get-KeeperAuditAlertUserEmailForId -EnterpriseData $EnterpriseData -UserId ([long]$uid)
                }
            }
            $sf = @()
            if ($fd -and $fd.SharedFolderUids) { $sf = @($fd.SharedFolderUids | ForEach-Object { $_.Id }) }
            $rec = @()
            if ($fd -and $fd.RecordUids) { $rec = @($fd.RecordUids | ForEach-Object { $_.Id }) }
            $sep = if ($Format -eq 'csv') { ', ' } elseif ($Format -eq 'json') { $null } else { "`n" }
            $evDisplay  = if ($null -eq $sep) { $evNames } else { $evNames -join $sep }
            $usDisplay  = if ($null -eq $sep) { $users }   else { $users -join $sep }
            $sfDisplay  = if ($null -eq $sep) { $sf }      else { $sf -join $sep }
            $recDisplay = if ($null -eq $sep) { $rec }     else { $rec -join $sep }
            $recipDisplay = if ($Format -eq 'json') {
                @{ SendToOriginator = $alert.SendToOriginator; Recipients = $alert.Recipients }
            } else {
                (@{ SendToOriginator = $alert.SendToOriginator; Recipients = $alert.Recipients } | ConvertTo-Json -Depth 6 -Compress)
            }

            [PSCustomObject]@{
                AlertId       = $alert.Id
                AlertName     = $alert.Name
                Status        = if ($ctxDisabled) { 'Disabled' } else { 'Enabled' }
                Frequency     = (ConvertTo-KeeperAuditAlertFrequencyDisplay $alert.Frequency)
                Occurrences   = $oc
                SentCounter   = $sc
                LastSent      = $ls
                EventTypes    = $evDisplay
                Users         = $usDisplay
                SharedFolders = $sfDisplay
                Records       = $recDisplay
                Recipients    = $recipDisplay
            }
        }
        Write-AuditAlertTable @($rows) $Format $Output
        return
    }

    $alert = Resolve-KeeperAuditAlertConfiguration -Settings $Settings -Target $Target
    $ctx = Get-KeeperAuditAlertContext -Settings $Settings -AlertId $alert.Id
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
                Get-KeeperAuditAlertUserEmailForId -EnterpriseData $EnterpriseData -UserId ([long]$uid)
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

function Invoke-AuditAlertHistory {
    param(
        [KeeperSecurity.Authentication.IAuthentication] $Auth,
        $Settings,
        [string] $Target,
        [string] $Format,
        [string] $Output
    )
    if ([string]::IsNullOrWhiteSpace($Target)) {
        Stop-KeeperAuditAlert 'history requires -Target (alert ID or name).'
    }
    $alert = Resolve-KeeperAuditAlertConfiguration -Settings $Settings -Target $Target
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
        $rs = $Auth.ExecuteAuthCommand($rq, [KeeperSecurity.Enterprise.AuditLogCommands.GetAuditEventReportsResponse], $true).GetAwaiter().GetResult()
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

function Invoke-AuditAlertDelete {
    param(
        [KeeperSecurity.Authentication.IAuthentication] $Auth,
        $Settings,
        [string] $Target,
        [switch] $All,
        [int] $From,
        [int] $To,
        [switch] $Force,
        [hashtable] $CallerParams,
        [string] $Format,
        [string] $Output
    )
    if (-not $Settings -or -not $Settings.AuditAlertFilter -or $Settings.AuditAlertFilter.Length -eq 0) {
        Write-Host 'No alerts found.'
        return
    }
    $toDelete = @()
    if ($CallerParams.ContainsKey('From') -and $CallerParams.ContainsKey('To')) {
        if ($From -le 0 -or $To -le 0) { Stop-KeeperAuditAlert 'Alert IDs must be positive integers.' }
        if ($From -ge $To) { Stop-KeeperAuditAlert "--From ($From) must be less than --To ($To)." }
        foreach ($a in $Settings.AuditAlertFilter) {
            if ($a.Id -ge $From -and $a.Id -le $To) { $toDelete += $a }
        }
        if ($toDelete.Count -eq 0) { Stop-KeeperAuditAlert "No alerts found in range $From-$To" }
    }
    elseif ($All.IsPresent) {
        $toDelete = @($Settings.AuditAlertFilter)
    }
    elseif ($Target) {
        $toDelete = @(Resolve-KeeperAuditAlertConfiguration -Settings $Settings -Target $Target)
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
            $delRs = $Auth.ExecuteAuthCommand($dq, [KeeperSecurity.Commands.KeeperApiResponse], $true).GetAwaiter().GetResult()
            Assert-KeeperApiResponse -Response $delRs -Context "delete enterprise setting (AuditAlertFilter id $($a.Id))"
            $deleted++
        } catch {
            Write-Warning "Failed to delete alert $($a.Name) (ID $($a.Id)): $($_.Exception.Message)"
        }
    }
    Clear-KeeperAuditAlertCache
    if ($deleted -gt 0) { Get-KeeperAuditAlert -Action list -Reload -Format $Format -Output $Output }
    else { Write-Warning 'No alerts were deleted.' }
}

function Invoke-AuditAlertAdd {
    param(
        [KeeperSecurity.Authentication.IAuthentication] $Auth,
        [KeeperSecurity.Enterprise.EnterpriseData] $EnterpriseData,
        [hashtable] $CallerParams,
        [string] $Format,
        [string] $Output
    )
    $Name = $CallerParams['Name']
    $Active = $CallerParams['Active']

    if ([string]::IsNullOrWhiteSpace($Name)) { Stop-KeeperAuditAlert 'add requires -Name.' }
    $settings = Get-KeeperAuditAlertSettingsInternal -Auth $Auth -EnterpriseData $EnterpriseData -Reload
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

    Apply-AuditAlertOptions -Alert $alert -EnterpriseData $EnterpriseData -CallerParams $CallerParams

    $put = New-Object KeeperSecurity.Enterprise.PutAuditAlertFilterEnterpriseSettingCommand
    $put.Settings = $alert
    $putRs = $Auth.ExecuteAuthCommand($put, [KeeperSecurity.Commands.KeeperApiResponse], $true).GetAwaiter().GetResult()
    Assert-KeeperApiResponse -Response $putRs -Context 'put audit alert filter (add)'

    if ($Active -eq 'off') {
        $ctx = New-Object KeeperSecurity.Enterprise.AuditAlertContextPatch
        $ctx.Id = $newId
        $ctx.Disabled = $true
        $p2 = New-Object KeeperSecurity.Enterprise.PutAuditAlertContextEnterpriseSettingCommand
        $p2.Settings = $ctx
        $putCtxRs = $Auth.ExecuteAuthCommand($p2, [KeeperSecurity.Commands.KeeperApiResponse], $true).GetAwaiter().GetResult()
        Assert-KeeperApiResponse -Response $putCtxRs -Context 'put audit alert context (add, disabled)'
    }
    Clear-KeeperAuditAlertCache
    Get-KeeperAuditAlert -Action view -Target "$newId" -Format $Format -Output $Output
}

function Invoke-AuditAlertEdit {
    param(
        [KeeperSecurity.Authentication.IAuthentication] $Auth,
        $Settings,
        [KeeperSecurity.Enterprise.EnterpriseData] $EnterpriseData,
        [string] $Target,
        [hashtable] $CallerParams,
        [string] $Format,
        [string] $Output
    )
    $Active = $CallerParams['Active']

    if ([string]::IsNullOrWhiteSpace($Target)) { Stop-KeeperAuditAlert 'edit requires -Target.' }
    $alert = Resolve-KeeperAuditAlertConfiguration -Settings $Settings -Target $Target
    Apply-AuditAlertOptions -Alert $alert -EnterpriseData $EnterpriseData -CallerParams $CallerParams

    $put = New-Object KeeperSecurity.Enterprise.PutAuditAlertFilterEnterpriseSettingCommand
    $put.Settings = $alert
    $putRs = $Auth.ExecuteAuthCommand($put, [KeeperSecurity.Commands.KeeperApiResponse], $true).GetAwaiter().GetResult()
    Assert-KeeperApiResponse -Response $putRs -Context 'put audit alert filter (edit)'

    if ($Active) {
        $ctx = Get-KeeperAuditAlertContext -Settings $Settings -AlertId $alert.Id
        $curOff = $ctx -and $ctx.Disabled
        $wantOff = ($Active -eq 'off')
        if ($curOff -ne $wantOff) {
            $patch = New-Object KeeperSecurity.Enterprise.AuditAlertContextPatch
            $patch.Id = $alert.Id
            $patch.Disabled = $wantOff
            $p2 = New-Object KeeperSecurity.Enterprise.PutAuditAlertContextEnterpriseSettingCommand
            $p2.Settings = $patch
            $putCtxRs = $Auth.ExecuteAuthCommand($p2, [KeeperSecurity.Commands.KeeperApiResponse], $true).GetAwaiter().GetResult()
            Assert-KeeperApiResponse -Response $putCtxRs -Context 'put audit alert context (edit active state)'
        }
    }
    Clear-KeeperAuditAlertCache
    Get-KeeperAuditAlert -Action view -Target $Target -Format $Format -Output $Output
}

function Invoke-AuditAlertResetCounts {
    param(
        [KeeperSecurity.Authentication.IAuthentication] $Auth,
        $Settings,
        [string] $Target
    )
    if ([string]::IsNullOrWhiteSpace($Target)) { Stop-KeeperAuditAlert 'reset-counts requires -Target.' }
    $alert = Resolve-KeeperAuditAlertConfiguration -Settings $Settings -Target $Target
    $patch = New-Object KeeperSecurity.Enterprise.AuditAlertContextPatch
    $patch.Id = $alert.Id
    $patch.Counter = 0
    $patch.SentCounter = 0
    $patch.LastReset = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
    $put = New-Object KeeperSecurity.Enterprise.PutAuditAlertContextEnterpriseSettingCommand
    $put.Settings = $patch
    $putRs = $Auth.ExecuteAuthCommand($put, [KeeperSecurity.Commands.KeeperApiResponse], $true).GetAwaiter().GetResult()
    Assert-KeeperApiResponse -Response $putRs -Context 'put audit alert context (reset-counts)'
    Clear-KeeperAuditAlertCache
    Write-Host 'Alert counts reset to zero.'
}

function Invoke-AuditAlertEnableDisable {
    param(
        [KeeperSecurity.Authentication.IAuthentication] $Auth,
        $Settings,
        [string] $Target,
        [switch] $All,
        [bool] $Disabled,
        [string] $ActionLabel,
        [string] $Format,
        [string] $Output
    )
    if ($All.IsPresent -and $Target) { Stop-KeeperAuditAlert "Cannot use -All together with -Target." }
    if ($All.IsPresent) {
        $alerts = @($Settings.AuditAlertFilter | Where-Object { $_.Id })
        if ($alerts.Count -eq 0) {
            Write-Host "No valid alerts found to $ActionLabel."
            return
        }
        $successCount = 0
        foreach ($a in $alerts) {
            $patch = New-Object KeeperSecurity.Enterprise.AuditAlertContextPatch
            $patch.Id = $a.Id
            $patch.Disabled = $Disabled
            $put = New-Object KeeperSecurity.Enterprise.PutAuditAlertContextEnterpriseSettingCommand
            $put.Settings = $patch
            try {
                $putRs = $Auth.ExecuteAuthCommand($put, [KeeperSecurity.Commands.KeeperApiResponse], $true).GetAwaiter().GetResult()
                Assert-KeeperApiResponse -Response $putRs -Context "$ActionLabel alert $($a.Id)"
                $successCount++
            } catch {
                Write-Warning "Failed to $ActionLabel alert $($a.Id) `"$($a.Name)`": $($_.Exception.Message)"
            }
        }
        Clear-KeeperAuditAlertCache
        $past = if ($Disabled) { 'Disabled' } else { 'Enabled' }
        Write-Host "$past $successCount of $($alerts.Count) alert(s)."
        Get-KeeperAuditAlert -Action list -Reload -Format $Format -Output $Output
        return
    }
    if ([string]::IsNullOrWhiteSpace($Target)) { Stop-KeeperAuditAlert "$ActionLabel requires -Target or -All." }
    $alert = Resolve-KeeperAuditAlertConfiguration -Settings $Settings -Target $Target
    $patch = New-Object KeeperSecurity.Enterprise.AuditAlertContextPatch
    $patch.Id = $alert.Id
    $patch.Disabled = $Disabled
    $put = New-Object KeeperSecurity.Enterprise.PutAuditAlertContextEnterpriseSettingCommand
    $put.Settings = $patch
    $putRs = $Auth.ExecuteAuthCommand($put, [KeeperSecurity.Commands.KeeperApiResponse], $true).GetAwaiter().GetResult()
    $ctxLabel = if ($Disabled) { 'put audit alert context (disable)' } else { 'put audit alert context (enable)' }
    Assert-KeeperApiResponse -Response $putRs -Context $ctxLabel
    Clear-KeeperAuditAlertCache
    if ($Disabled) {
        Write-Host "Alert `"$($alert.Name)`" has been disabled."
    } else {
        Write-Host "Alert `"$($alert.Name)`" has been enabled."
    }
    Get-KeeperAuditAlert -Action view -Target $Target -Format $Format -Output $Output
}

function Invoke-AuditAlertRecipient {
    param(
        [KeeperSecurity.Authentication.IAuthentication] $Auth,
        $Settings,
        [KeeperSecurity.Enterprise.EnterpriseData] $EnterpriseData,
        [string] $Target,
        [string] $RecipientAction,
        [string] $Recipient,
        [hashtable] $CallerParams,
        [string] $Format,
        [string] $Output
    )
    if ([string]::IsNullOrWhiteSpace($Target)) { Stop-KeeperAuditAlert 'recipient requires -Target alert.' }
    if ([string]::IsNullOrWhiteSpace($RecipientAction)) { Stop-KeeperAuditAlert 'recipient requires -RecipientAction (enable|disable|delete|add|edit).' }
    $alert = Resolve-KeeperAuditAlertConfiguration -Settings $Settings -Target $Target

    switch ($RecipientAction) {
        'enable' {
            if ([string]::IsNullOrWhiteSpace($Recipient)) { Stop-KeeperAuditAlert 'recipient enable requires -Recipient.' }
            if ($Recipient -eq '*') { $alert.SendToOriginator = $true }
            else {
                $r = Find-AuditAlertRecipient -Alert $alert -NameOrId $Recipient
                $r.Disabled = $false
            }
        }
        'disable' {
            if ([string]::IsNullOrWhiteSpace($Recipient)) { Stop-KeeperAuditAlert 'recipient disable requires -Recipient.' }
            if ($Recipient -eq '*') { $alert.SendToOriginator = $false }
            else {
                $r = Find-AuditAlertRecipient -Alert $alert -NameOrId $Recipient
                $r.Disabled = $true
            }
        }
        'delete' {
            if ([string]::IsNullOrWhiteSpace($Recipient)) { Stop-KeeperAuditAlert 'recipient delete requires -Recipient.' }
            $r = Find-AuditAlertRecipient -Alert $alert -NameOrId $Recipient
            $list = [System.Collections.Generic.List[KeeperSecurity.Enterprise.AlertRecipient]]::new()
            foreach ($x in $alert.Recipients) { if ($x.Id -ne $r.Id) { $list.Add($x) } }
            $alert.Recipients = $list.ToArray()
        }
        'edit' {
            if ([string]::IsNullOrWhiteSpace($Recipient)) { Stop-KeeperAuditAlert 'recipient edit requires -Recipient.' }
            $r = Find-AuditAlertRecipient -Alert $alert -NameOrId $Recipient
            Apply-AuditAlertRecipientOptions -R $r -CallerParams $CallerParams
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
            Apply-AuditAlertRecipientOptions -R $r -CallerParams $CallerParams
        }
    }

    $put = New-Object KeeperSecurity.Enterprise.PutAuditAlertFilterEnterpriseSettingCommand
    $put.Settings = $alert
    $putRs = $Auth.ExecuteAuthCommand($put, [KeeperSecurity.Commands.KeeperApiResponse], $true).GetAwaiter().GetResult()
    Assert-KeeperApiResponse -Response $putRs -Context 'put audit alert filter (recipient)'
    Clear-KeeperAuditAlertCache
    Get-KeeperAuditAlert -Action view -Target $Target -Format $Format -Output $Output
}

function Get-KeeperAuditAlert {
    <#
    .SYNOPSIS
    Configure and inspect enterprise audit alert rules.

    .DESCRIPTION
    List, view, add, edit, delete, enable/disable audit alert rules and their recipients.
    Requires enterprise admin privileges.

    .PARAMETER Action
    list | view | history | delete | add | edit | reset-counts | enable | disable | recipient

    .EXAMPLE
    Get-KeeperAuditAlert -Action list

    .EXAMPLE
    Get-KeeperAuditAlert -Action view -Target 'My Alert'

    .EXAMPLE
    Get-KeeperAuditAlert -Action add -Name 'Logins' -AuditEvent login -Frequency event
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
        $settings = Get-KeeperAuditAlertSettingsInternal -Auth $auth -EnterpriseData $edata -Reload:$Reload

        switch ($Action) {
            'list'         { Invoke-AuditAlertList -Settings $settings -Format $Format -Output $Output }
            'view'         { Invoke-AuditAlertView -Settings $settings -EnterpriseData $edata -Target $Target -All:$All -Format $Format -Output $Output }
            'history'      { Invoke-AuditAlertHistory -Auth $auth -Settings $settings -Target $Target -Format $Format -Output $Output }
            'delete'       { Invoke-AuditAlertDelete -Auth $auth -Settings $settings -Target $Target -All:$All -From $From -To $To -Force:$Force -CallerParams $PSBoundParameters -Format $Format -Output $Output }
            'add'          { Invoke-AuditAlertAdd -Auth $auth -EnterpriseData $edata -CallerParams $PSBoundParameters -Format $Format -Output $Output }
            'edit'         { Invoke-AuditAlertEdit -Auth $auth -Settings $settings -EnterpriseData $edata -Target $Target -CallerParams $PSBoundParameters -Format $Format -Output $Output }
            'reset-counts' { Invoke-AuditAlertResetCounts -Auth $auth -Settings $settings -Target $Target }
            'enable'       { Invoke-AuditAlertEnableDisable -Auth $auth -Settings $settings -Target $Target -All:$All -Disabled $false -ActionLabel 'enable' -Format $Format -Output $Output }
            'disable'      { Invoke-AuditAlertEnableDisable -Auth $auth -Settings $settings -Target $Target -All:$All -Disabled $true -ActionLabel 'disable' -Format $Format -Output $Output }
            'recipient'    { Invoke-AuditAlertRecipient -Auth $auth -Settings $settings -EnterpriseData $edata -Target $Target -RecipientAction $RecipientAction -Recipient $Recipient -CallerParams $PSBoundParameters -Format $Format -Output $Output }
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
New-Alias -Name audit-alert -Value Get-KeeperAuditAlert
