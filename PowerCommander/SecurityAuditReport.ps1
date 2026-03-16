#requires -Version 5.1

function Script:Get-KeeperJsonPropertyValue {
    param(
        [Parameter()]
        $Object,

        [Parameter(Mandatory = $true)]
        [string] $Name,

        [Parameter()]
        $DefaultValue = $null
    )

    if ($null -eq $Object) {
        return $DefaultValue
    }

    $property = $Object.PSObject.Properties[$Name]
    if ($null -ne $property) {
        return $property.Value
    }

    return $DefaultValue
}

function Script:ConvertTo-KeeperInt {
    param(
        [Parameter()]
        $Value,

        [Parameter()]
        [int] $DefaultValue = 0
    )

    if ($null -eq $Value) {
        return $DefaultValue
    }

    $parsed = 0
    if ([int]::TryParse($Value.ToString(), [ref]$parsed)) {
        return $parsed
    }

    return $DefaultValue
}

function Script:Show-KeeperSecurityAuditSyntaxHelp {
    Write-Host @"
Security Audit Report Command Syntax Description:

Column Name       Description
  email             e-mail address
  name              user display name
  sync_pending      whether security data sync is pending
  weak              number of records whose password strength is in the weak category
  fair              number of records whose password strength is in the fair category
  medium            number of records whose password strength is in the medium category
  strong            number of records whose password strength is in the strong category
  reused            number of reused passwords
  unique            number of unique passwords
  securityScore     security score (0-100)
  twoFactorChannel  2FA - On/Off
  node              enterprise node path

BreachWatch Columns (with -BreachWatch):
  at_risk           number of at-risk records
  passed            number of passed records
  ignored           number of ignored records

Switches:
  -Format <table|json|csv>        format of the report
  -Output <FILENAME>              output to the given filename
  -SyntaxHelp                     display description of each column in the report
  -Node <name|UID>                name(s) or UID(s) of node(s) to filter results by
  -BreachWatch                    display a BreachWatch security report
  -ShowUpdated                    calculate current security audit scores locally
  -Save                           push updated scores to Keeper
  -ScoreType <type>               strong_passwords or default
  -AttemptFix                     reset invalid security-data for affected users
  -Force                          skip confirmation prompts
"@
}

function Script:Expand-KeeperSecurityAuditData {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Json,

        [Parameter(Mandatory = $true)]
        [int] $NumberOfReusedPasswords
    )

    $parsed = $Json | ConvertFrom-Json
    $secStats = Get-KeeperJsonPropertyValue $parsed 'securityAuditStats'
    $bwStats = Get-KeeperJsonPropertyValue $parsed 'bwStats'
    $hasSecStats = $null -ne $secStats

    function getIntValue {
        param(
            $TopLevel,
            $SecLevel,
            $BwLevel = $null
        )

        $topValue = ConvertTo-KeeperInt (Get-KeeperJsonPropertyValue $parsed $TopLevel)
        if ($topValue -ne 0) {
            return $topValue
        }

        if ($null -ne $secStats) {
            $secValue = ConvertTo-KeeperInt (Get-KeeperJsonPropertyValue $secStats $SecLevel)
            if ($secValue -ne 0) {
                return $secValue
            }
        }

        if ($null -ne $bwStats -and -not [string]::IsNullOrEmpty($BwLevel)) {
            return (ConvertTo-KeeperInt (Get-KeeperJsonPropertyValue $bwStats $BwLevel))
        }

        return 0
    }

    $weak = getIntValue 'weak_record_passwords' 'weak_record_passwords'
    $fair = getIntValue 'fair_record_passwords' 'fair_record_passwords'
    $medium = getIntValue 'medium_record_passwords' 'medium_record_passwords'
    $strong = getIntValue 'strong_record_passwords' 'strong_record_passwords'
    $total = getIntValue 'total_record_passwords' 'total_record_passwords'
    $unique = [Math]::Max(0, $total - $NumberOfReusedPasswords)
    $passed = ConvertTo-KeeperInt (Get-KeeperJsonPropertyValue $bwStats 'passed_records')
    $atRisk = ConvertTo-KeeperInt (Get-KeeperJsonPropertyValue $bwStats 'at_risk_records')
    $ignored = ConvertTo-KeeperInt (Get-KeeperJsonPropertyValue $bwStats 'ignored_records')

    if (-not $hasSecStats) {
        $medium = $total - $weak - $strong
    }

    return @{
        weak_record_passwords = $weak
        fair_record_passwords = $fair
        medium_record_passwords = $medium
        strong_record_passwords = $strong
        total_record_passwords = $total
        unique_record_passwords = $unique
        passed_records = $passed
        at_risk_records = $atRisk
        ignored_records = $ignored
    }
}

function Script:Get-KeeperSecurityStrengthCategory {
    # Maps Keeper password-strength scores to bucket names.
    # Score mapping: 0-1 = weak, 2 = fair, 3 = medium, 4+ = strong
    param([int] $Score)

    if ($Score -ge 4) { return 'strong' }
    if ($Score -eq 2) { return 'fair' }
    if ($Score -le 1) { return 'weak' }
    return 'medium'
}

function Script:Get-KeeperSecurityScoreDeltas {
    param(
        [Parameter()]
        $RecordSecurityData,

        [Parameter(Mandatory = $true)]
        [int] $Delta
    )

    $deltas = @{
        weak_record_passwords = 0
        fair_record_passwords = 0
        medium_record_passwords = 0
        strong_record_passwords = 0
        total_record_passwords = 0
        unique_record_passwords = 0
        passed_records = 0
        at_risk_records = 0
        ignored_records = 0
    }

    $passwordStrength = ConvertTo-KeeperInt (Get-KeeperJsonPropertyValue $RecordSecurityData 'strength')
    $strengthKey = '{0}_record_passwords' -f (Get-KeeperSecurityStrengthCategory $passwordStrength)
    if ($deltas.ContainsKey($strengthKey)) {
        $deltas[$strengthKey] = $Delta
    }
    $deltas.total_record_passwords = $Delta

    # bw_result from the API: 2 = at-risk (breached), 1 = passed (clean), 0/other = ignored
    $breachWatchResult = ConvertTo-KeeperInt (Get-KeeperJsonPropertyValue $RecordSecurityData 'bw_result')
    if ($breachWatchResult -eq 2) {
        $deltas.at_risk_records = $Delta
    }
    elseif ($breachWatchResult -eq 1) {
        $deltas.passed_records = $Delta
    }
    else {
        $deltas.ignored_records = $Delta
    }

    return $deltas
}

function Script:Update-KeeperSecurityScoreDeltas {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable] $Data,

        [Parameter(Mandatory = $true)]
        [hashtable] $Deltas
    )

    foreach ($entry in $Deltas.GetEnumerator()) {
        if ($Data.ContainsKey($entry.Key)) {
            $Data[$entry.Key] += $entry.Value
        }
        else {
            $Data[$entry.Key] = $entry.Value
        }
    }
}

function Script:Decrypt-KeeperSecurityData {
    param(
        [Parameter()]
        $SecurityData,

        [Parameter(Mandatory = $true)]
        [Enterprise.EncryptedKeyType] $KeyType,

        [Parameter()]
        $RsaKey,

        [Parameter()]
        $EcKey
    )

    if ($null -eq $SecurityData -or $SecurityData.IsEmpty) {
        return $null
    }

    $dataBytes = $SecurityData.ToByteArray()

    try {
        if ($KeyType -eq [Enterprise.EncryptedKeyType]::KtEncryptedByPublicKeyEcc) {
            if ($null -eq $EcKey) {
                return $null
            }
            $decryptedBytes = [KeeperSecurity.Utils.CryptoUtils]::DecryptEc($dataBytes, $EcKey)
        }
        else {
            if ($null -eq $RsaKey) {
                return $null
            }
            $decryptedBytes = [KeeperSecurity.Utils.CryptoUtils]::DecryptRsa($dataBytes, $RsaKey)
        }
    }
    catch {
        return $null
    }

    try {
        $json = [System.Text.Encoding]::UTF8.GetString($decryptedBytes)
        return ($json | ConvertFrom-Json)
    }
    catch {
        return $null
    }
}

function Script:Update-KeeperSecurityIncrementalData {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable] $Data,

        [Parameter(Mandatory = $true)]
        [Authentication.SecurityReport] $SecurityReport,

        [Parameter()]
        $RsaKey,

        [Parameter()]
        $EcKey,

        [Parameter(Mandatory = $true)]
        [ref] $HasErrors
    )

    $updatedData = @{}
    foreach ($key in $Data.Keys) {
        $updatedData[$key] = $Data[$key]
    }

    foreach ($incrementalData in $SecurityReport.SecurityReportIncrementalData) {
        $oldData = Decrypt-KeeperSecurityData $incrementalData.OldSecurityData $incrementalData.OldDataEncryptionType $RsaKey $EcKey
        $currentData = Decrypt-KeeperSecurityData $incrementalData.CurrentSecurityData $incrementalData.CurrentDataEncryptionType $RsaKey $EcKey

        if (($null -ne $oldData -and $null -eq (Get-KeeperJsonPropertyValue $oldData 'strength')) -or
            ($null -ne $currentData -and $null -eq (Get-KeeperJsonPropertyValue $currentData 'strength'))) {
            $HasErrors.Value = $true
            break
        }

        if ($null -ne $oldData) {
            $deltas = Get-KeeperSecurityScoreDeltas $oldData -1
            Update-KeeperSecurityScoreDeltas $updatedData $deltas
        }
        if ($null -ne $currentData) {
            $deltas = Get-KeeperSecurityScoreDeltas $currentData 1
            Update-KeeperSecurityScoreDeltas $updatedData $deltas
        }
    }

    if ($HasErrors.Value) {
        return $Data
    }

    return $updatedData
}

function Script:Format-KeeperSecurityReportData {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable] $Data
    )

    $report = [ordered]@{
        securityAuditStats = [ordered]@{
            weak_record_passwords = ConvertTo-KeeperInt $Data.weak_record_passwords
            fair_record_passwords = ConvertTo-KeeperInt $Data.fair_record_passwords
            medium_record_passwords = ConvertTo-KeeperInt $Data.medium_record_passwords
            strong_record_passwords = ConvertTo-KeeperInt $Data.strong_record_passwords
            total_record_passwords = ConvertTo-KeeperInt $Data.total_record_passwords
            unique_record_passwords = ConvertTo-KeeperInt $Data.unique_record_passwords
        }
        bwStats = [ordered]@{
            passed_records = ConvertTo-KeeperInt $Data.passed_records
            at_risk_records = ConvertTo-KeeperInt $Data.at_risk_records
            ignored_records = ConvertTo-KeeperInt $Data.ignored_records
        }
    }

    return ($report | ConvertTo-Json -Depth 5 -Compress)
}

function Script:Get-KeeperStrongByTotal {
    param(
        [Parameter(Mandatory = $true)]
        [int] $Total,

        [Parameter(Mandatory = $true)]
        [int] $Strong
    )

    if ($Total -eq 0) {
        return 0.0
    }

    return ([double]$Strong / [double]$Total)
}

function Script:Get-KeeperSecurityScore {
    param(
        [Parameter(Mandatory = $true)]
        [int] $Total,

        [Parameter(Mandatory = $true)]
        [int] $Strong,

        [Parameter(Mandatory = $true)]
        [int] $Unique,

        [Parameter(Mandatory = $true)]
        [bool] $TwoFactorOn
    )

    $strongByTotal = Get-KeeperStrongByTotal $Total $Strong
    $uniqueByTotal = if ($Total -eq 0) { 0.0 } else { [double]$Unique / [double]$Total }
    $twoFactorValue = if ($TwoFactorOn) { 1.0 } else { 0.0 }
    return ($strongByTotal + $uniqueByTotal + 1.0 + $twoFactorValue) / 4.0
}

function Script:Confirm-KeeperSecurityAuditAction {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Prompt,

        [Parameter()]
        [switch] $Force
    )

    if ($Force) {
        return $true
    }

    $answer = Read-Host $Prompt
    return ($answer -match '^(?i)y(es)?$')
}

function Script:Clear-KeeperSecurityDataForUsers {
    param(
        [Parameter(Mandatory = $true)]
        [Enterprise] $Enterprise,

        [Parameter(Mandatory = $true)]
        [System.Collections.Generic.List[long]] $UserIds
    )

    $chunkSize = 999
    for ($offset = 0; $offset -lt $UserIds.Count; $offset += $chunkSize) {
        $request = New-Object Enterprise.ClearSecurityDataRequest
        $request.Type = [Enterprise.ClearSecurityDataType]::ForceClientResendSecurityData

        $endIndex = [Math]::Min($offset + $chunkSize - 1, $UserIds.Count - 1)
        for ($index = $offset; $index -le $endIndex; $index++) {
            $request.EnterpriseUserId.Add($UserIds[$index]) | Out-Null
        }

        $Enterprise.loader.Auth.ExecuteAuthRest("enterprise/clear_security_data", $request).GetAwaiter().GetResult() | Out-Null
    }

    Write-Host "Security data cleared for $($UserIds.Count) user(s)."
}

function Script:Test-KeeperRunReportsPrivilege {
    param(
        [Parameter(Mandatory = $true)]
        [Enterprise] $Enterprise
    )

    if ($Script:Context.ManagedCompanyId -gt 0) {
        return $true
    }

    $enterpriseData = $Enterprise.enterpriseData
    $roleData = $Enterprise.roleData
    if ($null -eq $enterpriseData -or $null -eq $roleData) {
        return $false
    }

    $currentUser = $null
    if (-not $enterpriseData.TryGetUserByEmail($Enterprise.loader.Auth.Username, [ref]$currentUser)) {
        return $false
    }

    $userRoleIds = [System.Collections.Generic.HashSet[long]]::new()
    foreach ($roleId in $roleData.GetRolesForUser($currentUser.Id)) {
        [void]$userRoleIds.Add($roleId)
    }

    foreach ($managedNode in @($roleData.GetManagedNodes())) {
        if (-not $userRoleIds.Contains($managedNode.RoleId)) {
            continue
        }

        foreach ($privilege in @($roleData.GetPrivilegesForRoleAndNode($managedNode.RoleId, $managedNode.ManagedNodeId))) {
            if ([string]::Equals($privilege.PrivilegeType, 'RUN_REPORTS', [System.StringComparison]::OrdinalIgnoreCase)) {
                return $true
            }
        }
    }

    return $false
}

function Script:Test-KeeperEnterpriseAddonEnabled {
    param(
        [Parameter(Mandatory = $true)]
        [Enterprise] $Enterprise,

        [Parameter(Mandatory = $true)]
        [string] $AddonName
    )

    $license = $Enterprise.enterpriseData.EnterpriseLicense
    if ($null -eq $license) {
        return $false
    }

    if ([string]::Equals($license.LicenseStatus, 'business_trial', [System.StringComparison]::OrdinalIgnoreCase)) {
        return $true
    }

    foreach ($addon in @($license.AddOns)) {
        if (-not [string]::Equals($addon.Name, $AddonName, [System.StringComparison]::OrdinalIgnoreCase)) {
            continue
        }

        if ($addon.Enabled -or $addon.IncludedInProduct) {
            return $true
        }
    }

    return $false
}

function Script:Write-KeeperSecurityAuditOutput {
    param(
        [Parameter(Mandatory = $true)]
        [object[]] $Rows,

        [Parameter(Mandatory = $true)]
        [bool] $ShowBreachWatch,

        [Parameter(Mandatory = $true)]
        [ValidateSet('table', 'json', 'csv')]
        [string] $Format,

        [Parameter()]
        [string] $Output
    )

    $title = if ($ShowBreachWatch) { 'Security Audit Report (BreachWatch)' } else { 'Security Audit Report' }
    $internalFields = if ($ShowBreachWatch) {
        @('email', 'name', 'sync_pending', 'at_risk', 'passed', 'ignored')
    } else {
        @('email', 'name', 'sync_pending', 'weak', 'fair', 'medium', 'strong', 'reused', 'unique', 'securityScore', 'twoFactorChannel', 'node')
    }

    $displayRows = if ($ShowBreachWatch) {
        $Rows | Select-Object @{Name='Email';Expression={$_.email}},
            @{Name='Name';Expression={$_.name}},
            @{Name='Sync Pending';Expression={$_.sync_pending}},
            @{Name='At Risk';Expression={$_.at_risk}},
            @{Name='Passed';Expression={$_.passed}},
            @{Name='Ignored';Expression={$_.ignored}}
    } else {
        $Rows | Select-Object @{Name='Email';Expression={$_.email}},
            @{Name='Name';Expression={$_.name}},
            @{Name='Sync Pending';Expression={$_.sync_pending}},
            @{Name='Weak';Expression={$_.weak}},
            @{Name='Fair';Expression={$_.fair}},
            @{Name='Medium';Expression={$_.medium}},
            @{Name='Strong';Expression={$_.strong}},
            @{Name='Reused';Expression={$_.reused}},
            @{Name='Unique';Expression={$_.unique}},
            @{Name='Security Score';Expression={$_.securityScore}},
            @{Name='2FA';Expression={$_.twoFactorChannel}},
            @{Name='Node';Expression={$_.node}}
    }

    switch ($Format) {
        'json' {
            $jsonRows = foreach ($row in $Rows) {
                $jsonRow = [ordered]@{}
                foreach ($field in $internalFields) {
                    $jsonRow[$field] = $row.$field
                }
                [PSCustomObject]$jsonRow
            }
            $jsonText = $jsonRows | ConvertTo-Json -Depth 5
            if ($Output) {
                Set-Content -Path $Output -Value $jsonText -Encoding utf8
                Write-Host "Output written to $Output"
                return
            }
            return $jsonText
        }
        'csv' {
            $csvText = ($displayRows | ConvertTo-Csv -NoTypeInformation)
            if ($Output) {
                Set-Content -Path $Output -Value $csvText -Encoding utf8
                Write-Host "Output written to $Output"
                return
            }
            return $csvText
        }
        default {
            if ($Output) {
                $tableText = @($displayRows | Format-Table -Property * -AutoSize | Out-String -Width 8192)
                Set-Content -Path $Output -Value @($title, '', $tableText) -Encoding utf8
                Write-Host "Output written to $Output"
                return
            }

            Write-Host ""
            Write-Host $title
            $displayRows | Format-Table -Property * -AutoSize | Out-String -Width 8192
        }
    }
}

function Get-KeeperSecurityAuditReport {
    <#
    .SYNOPSIS
    Generate a password security strength report for enterprise users.

    .DESCRIPTION
    Retrieves enterprise security audit data from Keeper, decrypts each user's report
    payload, optionally applies incremental security data updates, and returns the
    results in table, JSON, or CSV form.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateSet('table', 'json', 'csv')]
        [string] $Format = 'table',

        [Parameter()]
        [string] $Output,

        [Parameter()]
        [switch] $SyntaxHelp,

        [Parameter()]
        [string[]] $Node,

        [Parameter()]
        [switch] $BreachWatch,

        [Parameter()]
        [switch] $ShowUpdated,

        [Parameter()]
        [switch] $Save,

        [Parameter()]
        [ValidateSet('strong_passwords', 'default')]
        [string] $ScoreType = 'default',

        [Parameter()]
        [switch] $AttemptFix,

        [Parameter()]
        [switch] $Force
    )

    if ($SyntaxHelp) {
        Show-KeeperSecurityAuditSyntaxHelp
        return
    }

    [Enterprise]$enterprise = getEnterprise
    if ($null -eq $enterprise.enterpriseData) {
        Write-Warning "Enterprise data is not available."
        return
    }

    $treeKey = $enterprise.loader.TreeKey
    if ($null -eq $treeKey -or $treeKey.Length -eq 0) {
        Write-Warning "Enterprise tree key is not available. Ensure enterprise data is loaded."
        return
    }

    $nodeFilter = Resolve-EnterpriseNodeFilter -Enterprise $enterprise -Nodes $Node
    $showUpdatedData = $ShowUpdated.IsPresent -or $Save.IsPresent
    $saveReport = $Save.IsPresent
    $useStrongPasswordScoring = [string]::Equals($ScoreType, 'strong_passwords', [System.StringComparison]::OrdinalIgnoreCase)

    $rsaKey = $null
    if ($enterprise.loader.RsaPrivateKey -and $enterprise.loader.RsaPrivateKey.Length -gt 0) {
        try {
            $rsaKey = [KeeperSecurity.Utils.CryptoUtils]::LoadRsaPrivateKey($enterprise.loader.RsaPrivateKey)
        }
        catch { Write-Verbose "Failed to load RSA private key from enterprise loader: $_" }
    }

    $ecKey = $null
    if ($enterprise.loader.EcPrivateKey -and $enterprise.loader.EcPrivateKey.Length -gt 0) {
        try {
            $ecKey = [KeeperSecurity.Utils.CryptoUtils]::LoadEcPrivateKey($enterprise.loader.EcPrivateKey)
        }
        catch { Write-Verbose "Failed to load EC private key from enterprise loader: $_" }
    }

    $rows = New-Object System.Collections.Generic.List[object]
    $invalidUsers = New-Object 'System.Collections.Generic.List[long]'
    $updatedSecurityReports = New-Object 'System.Collections.Generic.List[Authentication.SecurityReport]'
    $saveBuildFailures = 0
    $fromPage = 0L
    $complete = $false
    $asOfRevision = 0L
    $hasErrors = $false

    while (-not $complete) {
        $request = New-Object Authentication.SecurityReportRequest
        $request.FromPage = $fromPage

        $response = $enterprise.loader.Auth.ExecuteAuthRest(
            "enterprise/get_security_report_data",
            $request,
            [Authentication.SecurityReportResponse]
        ).GetAwaiter().GetResult()

        $asOfRevision = $response.AsOfRevision

        try {
            if ($null -eq $rsaKey -and $response.EnterprisePrivateKey -and -not $response.EnterprisePrivateKey.IsEmpty) {
                $keyData = [KeeperSecurity.Utils.CryptoUtils]::DecryptAesV2($response.EnterprisePrivateKey.ToByteArray(), $treeKey)
                $rsaKey = [KeeperSecurity.Utils.CryptoUtils]::LoadRsaPrivateKey($keyData)
            }
            if ($null -eq $ecKey -and $response.EnterpriseEccPrivateKey -and -not $response.EnterpriseEccPrivateKey.IsEmpty) {
                $keyData = [KeeperSecurity.Utils.CryptoUtils]::DecryptAesV2($response.EnterpriseEccPrivateKey.ToByteArray(), $treeKey)
                $ecKey = [KeeperSecurity.Utils.CryptoUtils]::LoadEcPrivateKey($keyData)
            }
        }
        catch { Write-Verbose "Failed to load enterprise private keys from response: $_" }

        foreach ($securityReport in $response.SecurityReport) {
            $user = $null
            if (-not $enterprise.enterpriseData.TryGetUserById($securityReport.EnterpriseUserId, [ref]$user)) {
                continue
            }

            if ($nodeFilter -and -not $nodeFilter.Contains($user.ParentNodeId)) {
                continue
            }

            $email = if ($user.Email) { $user.Email } else { $securityReport.EnterpriseUserId.ToString() }
            $name = if ($user.DisplayName) { $user.DisplayName } else { $email }
            $nodePath = Get-KeeperNodePath -NodeId $user.ParentNodeId
            $twoFactorOn = ($securityReport.TwoFactor -ne 'two_factor_disabled' -and -not [string]::IsNullOrEmpty($securityReport.TwoFactor))

            $row = [ordered]@{
                email = $email
                name = $name
                sync_pending = ''
                node = $nodePath
                reused = [int]$securityReport.NumberOfReusedPassword
                twoFactorChannel = if ($twoFactorOn) { 'On' } else { 'Off' }
            }

            if ($securityReport.EncryptedReportData -and $securityReport.EncryptedReportData.Length -gt 0) {
                try {
                    $decryptedBytes = [KeeperSecurity.Utils.CryptoUtils]::DecryptAesV2($securityReport.EncryptedReportData.ToByteArray(), $treeKey)
                    $json = [System.Text.Encoding]::UTF8.GetString($decryptedBytes)
                    $data = Expand-KeeperSecurityAuditData -Json $json -NumberOfReusedPasswords $securityReport.NumberOfReusedPassword
                }
                catch {
                    $invalidUsers.Add($securityReport.EnterpriseUserId) | Out-Null
                    continue
                }
            }
            else {
                $data = @{
                    weak_record_passwords = 0
                    fair_record_passwords = 0
                    medium_record_passwords = 0
                    strong_record_passwords = 0
                    total_record_passwords = 0
                    unique_record_passwords = 0
                    passed_records = 0
                    at_risk_records = 0
                    ignored_records = 0
                }
            }

            $rowIncrementalFailed = $false
            if ($showUpdatedData -and $securityReport.SecurityReportIncrementalData.Count -gt 0) {
                $data = Update-KeeperSecurityIncrementalData -Data $data -SecurityReport $securityReport -RsaKey $rsaKey -EcKey $ecKey -HasErrors ([ref]$rowIncrementalFailed)
                if ($rowIncrementalFailed) {
                    $hasErrors = $true
                }
                else {
                    $data.unique_record_passwords = [Math]::Max(0, (ConvertTo-KeeperInt $data.total_record_passwords) - [int]$securityReport.NumberOfReusedPassword)
                }
            }

            $row.weak = ConvertTo-KeeperInt $data.weak_record_passwords
            $row.fair = ConvertTo-KeeperInt $data.fair_record_passwords
            $row.medium = ConvertTo-KeeperInt $data.medium_record_passwords
            $row.strong = ConvertTo-KeeperInt $data.strong_record_passwords
            $row.total = ConvertTo-KeeperInt $data.total_record_passwords
            $row.unique = ConvertTo-KeeperInt $data.unique_record_passwords
            $row.passed = ConvertTo-KeeperInt $data.passed_records
            $row.at_risk = ConvertTo-KeeperInt $data.at_risk_records
            $row.ignored = ConvertTo-KeeperInt $data.ignored_records

            if ($row.unique -lt 0 -and $row.total -gt 0 -and $AttemptFix.IsPresent) {
                $invalidUsers.Add($securityReport.EnterpriseUserId) | Out-Null
                continue
            }

            if ($rowIncrementalFailed) {
                $row.sync_pending = 'Error'
            }
            elseif ($row.total -eq 0 -and $row.reused -ne 0) {
                $row.sync_pending = 'Yes'
            }

            if ($useStrongPasswordScoring) {
                $score = Get-KeeperStrongByTotal -Total $row.total -Strong $row.strong
                $displayScore = [int](100 * $score)
            }
            else {
                $score = Get-KeeperSecurityScore -Total $row.total -Strong $row.strong -Unique $row.unique -TwoFactorOn $twoFactorOn
                $displayScore = [int](100 * [Math]::Round($score, 2))
            }
            $row.securityScore = $displayScore

            $rows.Add([PSCustomObject]$row) | Out-Null

            if ($saveReport -and -not $hasErrors) {
                try {
                    $updatedSecurityReport = New-Object Authentication.SecurityReport
                    $updatedSecurityReport.Revision = $asOfRevision
                    $updatedSecurityReport.EnterpriseUserId = $securityReport.EnterpriseUserId
                    $reportJson = Format-KeeperSecurityReportData -Data $data
                    $jsonBytes = [System.Text.Encoding]::UTF8.GetBytes($reportJson)
                    $updatedSecurityReport.EncryptedReportData = [Google.Protobuf.ByteString]::CopyFrom(
                        [KeeperSecurity.Utils.CryptoUtils]::EncryptAesV2($jsonBytes, $treeKey)
                    )
                    $updatedSecurityReports.Add($updatedSecurityReport) | Out-Null
                }
                catch {
                    $saveBuildFailures++
                }
            }
        }

        $complete = $response.Complete
        $fromPage = $response.ToPage + 1
    }

    if ($invalidUsers.Count -gt 0) {
        Write-Warning "Decryption failed for $($invalidUsers.Count) user(s). Successfully decrypted: $($rows.Count)."
    }
    else {
        Write-Verbose "All $($rows.Count) user record(s) decrypted successfully."
    }

    if ($AttemptFix.IsPresent -and $invalidUsers.Count -gt 0) {
        if (Confirm-KeeperSecurityAuditAction -Prompt "Do you want to reset their security data? (y/n)" -Force:$Force.IsPresent) {
            Clear-KeeperSecurityDataForUsers -Enterprise $enterprise -UserIds $invalidUsers
        }
        else {
            Write-Host "Skipping security data reset."
        }
    }

    if ($saveReport -and $saveBuildFailures -gt 0) {
        Write-Warning "Unable to prepare $saveBuildFailures updated security report(s). Save skipped."
    }
    elseif ($saveReport -and $hasErrors) {
        Write-Warning "Updated security scores were not saved because some incremental security data could not be processed."
    }
    elseif ($saveReport -and $updatedSecurityReports.Count -gt 0) {
        if (Confirm-KeeperSecurityAuditAction -Prompt "Push updated security scores to Keeper? (y/n)" -Force:$Force.IsPresent) {
            try {
                $saveRequest = New-Object Authentication.SecurityReportSaveRequest
                $saveRequest.SecurityReport.AddRange($updatedSecurityReports)
                $enterprise.loader.Auth.ExecuteAuthRest("enterprise/save_summary_security_report", $saveRequest).GetAwaiter().GetResult() | Out-Null
                Write-Host "Security scores pushed to Keeper."
            }
            catch {
                Write-Warning "Error saving security reports: $($_.Exception.Message)"
            }
        }
        else {
            Write-Host "Save cancelled."
        }
    }

    $sortedRows = @($rows | Sort-Object email)
    Write-KeeperSecurityAuditOutput -Rows $sortedRows -ShowBreachWatch:$BreachWatch.IsPresent -Format $Format -Output $Output
}

function Get-KeeperBreachWatchReport {
    <#
    .SYNOPSIS
    Run a BreachWatch security report for all users in your enterprise.

    .DESCRIPTION
    Validates BreachWatch reporting access, then executes the security audit report
    pipeline in BreachWatch mode with updated report data saved back to Keeper.
    Note: this command pushes updated summary scores to Keeper automatically.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateSet('table', 'json', 'csv')]
        [string] $Format = 'table',

        [Parameter()]
        [string] $Output
    )

    [Enterprise]$enterprise = getEnterprise
    if (-not (Test-KeeperRunReportsPrivilege -Enterprise $enterprise)) {
        throw "You do not have the required privilege to run a BreachWatch report"
    }

    if (-not (Test-KeeperEnterpriseAddonEnabled -Enterprise $enterprise -AddonName 'enterprise_breach_watch')) {
        throw "BreachWatch is not enabled for this enterprise."
    }

    Get-KeeperSecurityAuditReport -Format $Format -Output $Output -BreachWatch -Save -Force
}

Set-Alias -Name bw-report -Value Get-KeeperBreachWatchReport
