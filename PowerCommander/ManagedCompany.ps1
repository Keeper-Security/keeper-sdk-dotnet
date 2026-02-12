function Switch-KeeperMC {
    <#
        .Synopsis
    	Switch to managed company

    	.Parameter Name
	    Managed Company ID or Name
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0)][string] $Name
    )

    [Enterprise]$enterprise = getMspEnterprise
 
    $mc = $enterprise.mspData.ManagedCompanies | Where-Object { ($_.EnterpriseId -eq $Name) }
    if ($mc.Length -eq 0) {
        $mc = $enterprise.mspData.ManagedCompanies | Where-Object { ($_.EnterpriseName -like $Name + '*') }
    }

    if ($mc.Length -eq 0) {
        Write-Error -Message "Managed Company`"$Name`" not found" -ErrorAction Stop
    }
    elseif ($mc.Length -gt 1) {
        Write-Error -Message "Managed Company`"$Name`" is not unique. Use Company ID." -ErrorAction Stop
    }

    $Script:Context.ManagedCompanyId = $mc.EnterpriseId
    Sync-KeeperEnterprise

    Write-Information "Switched to MC `"$($mc.EnterpriseName)`""
}
New-Alias -Name switch-to-mc -Value Switch-KeeperMC

function Switch-KeeperMSP {
    <#
        .Synopsis
    	Switch to MSP 
    #>
    [CmdletBinding()]

    [Enterprise]$enterprise = getMspEnterprise

    $Script:Context.ManagedCompanyId = 0
    Sync-KeeperEnterprise

    Write-Information "Switched to MSP"
}
New-Alias -Name switch-to-msp -Value Switch-KeeperMSP


function Get-KeeperManagedCompany {
    <#
        .Synopsis
    	Get a list of managed companies
    	.Parameter Filter
	    Managed Company ID or Name (optional filter)
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $false)][string] $Filter
    )

    [Enterprise]$enterprise = getMspEnterprise
    $list = $enterprise.mspData.ManagedCompanies
    if ($Filter) {
        $filterStr = $Filter.Trim()
        $list = @($list) | Where-Object {
            $_.EnterpriseId.ToString() -eq $filterStr -or
            ($_.EnterpriseName -and ($_.EnterpriseName -like '*' + $filterStr + '*'))
        }
    }
    $list | ForEach-Object {
        $mc = $_
        $addonsStr = ''
        if ($mc.AddOns -and $mc.AddOns.Count -gt 0) {
            $addonsStr = ($mc.AddOns | ForEach-Object { $_.Name }) -join ', '
        }
        $nodeName = $mc.ParentNodeId
        $node = $enterprise.enterpriseData.Nodes | Where-Object { $_.Id -eq $mc.ParentNodeId } | Select-Object -First 1
        if ($node) {
            $nodeName = if ([string]::IsNullOrEmpty($node.DisplayName)) { $node.Id.ToString() } else { $node.DisplayName }
        }
        [PSCustomObject]@{
            EnterpriseId   = $mc.EnterpriseId
            EnterpriseName = $mc.EnterpriseName
            ProductId      = $mc.ProductId
            NumberOfSeats  = $mc.NumberOfSeats
            NumberOfUsers  = $mc.NumberOfUsers
            FilePlanType   = $mc.FilePlanType
            IsExpired      = $mc.IsExpired
            ParentNodeId   = $mc.ParentNodeId
            NodeName       = $nodeName
            Addons         = $addonsStr
        }
    }
}
New-Alias -Name kmc -Value Get-KeeperManagedCompany

$Keeper_MspAddonName = {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)

    $result = @()
    $msp_addons = @('enterprise_breach_watch', 'compliance_report', 'enterprise_audit_and_reporting', 'msp_service_and_support', 'secrets_manager', 'connection_manager', 'chat')

    $toComplete = $wordToComplete += '*'
    foreach ($addon in $msp_addons) {
        if ($addon -like $toComplete) {
            $result += $addon
        }
    }
    if ($result.Count -gt 0) {
        return $result
    }
    else {
        return $null
    }
}

function New-KeeperManagedCompany {
    <#
        .Synopsis
    	Adds new Managed Company
    	.Parameter Name
	    Managed Company Name
    	.Parameter PlanId
	    Managed Company Plan
    	.Parameter MaximumSeats
	    Maximum Number of Seats
        .Parameter Storage
        Storage Plan
        .Parameter Addons
        Addons
        .Parameter Node
        Node Name or ID
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    Param (
        [Parameter(Mandatory = $true, Position = 0)][string] $Name,
        [Parameter(Mandatory = $true)][ValidateSet('business', 'businessPlus', 'enterprise', 'enterprisePlus')][string] $PlanId,
        [Parameter(Mandatory = $true)][int] $MaximumSeats,
        [Parameter(Mandatory = $false)][ValidateSet('100GB', '1TB', '10TB')][string] $Storage,
        [Parameter(Mandatory = $false)][string[]] $Addons,
        [Parameter(Mandatory = $false)][string] $Node
    )

    [Enterprise]$enterprise = getMspEnterprise

    $options = New-Object KeeperSecurity.Enterprise.ManagedCompanyOptions
    $options.Name = $Name
    $options.ProductId = $PlanId
    $options.NumberOfSeats = $MaximumSeats
    if ($Node) {
        $n = findEnterpriseNode $Node
        if ($n) {
            $options.NodeId = $n.Id
        }
        else {
            Write-Error -Message "Node ${Node} not found" -ErrorAction Stop
        }
    }
    else {
        $options.NodeId = $enterprise.enterpriseData.RootNode.Id
    }
    switch ($Storage) {
        '100GB' { $options.FilePlanType = [KeeperSecurity.Enterprise.ManagedCompanyConstants]::StoragePlan100GB }
        '1TB' { $options.FilePlanType = [KeeperSecurity.Enterprise.ManagedCompanyConstants]::StoragePlan1TB }
        '10TB' { $options.FilePlanType = [KeeperSecurity.Enterprise.ManagedCompanyConstants]::StoragePlan10TB }
    }
    if ($Addons) {
        $aons = @()
        foreach ($addon in $Addons) {
            $names = $addon -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
            foreach ($name in $names) {
                $parts = $name -split ':'
                $addonOption = New-Object KeeperSecurity.Enterprise.ManagedCompanyAddonOptions
                $addonOption.Addon = $parts[0].Trim()
                if ($parts.Length -gt 1) {
                    $addonOption.NumberOfSeats = $parts[1].Trim() -as [int]
                }
                $aons += $addonOption
            }
        }
        $options.Addons = $aons
    }


    if ($PSCmdlet.ShouldProcess($Name, "Creating Managed Company")) {
        return $enterprise.mspData.CreateManagedCompany($options).GetAwaiter().GetResult()
    }
}
New-Alias -Name kamc -Value New-KeeperManagedCompany
Register-ArgumentCompleter -CommandName New-KeeperManagedCompany -ParameterName Addons -ScriptBlock $Keeper_MspAddonName

function Remove-KeeperManagedCompany {
    <#
        .Synopsis
    	Removes Managed Company
    	.Parameter Name
	    Managed Company Id or Name
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    Param (
        [Parameter(Position = 0, Mandatory = $true)][string] $Name
    )

    [Enterprise]$enterprise = getMspEnterprise
    $mc = findManagedCompany $Name
    if (-not $mc) {
        Write-Error -Message "Managed Company ${Name} not found" -ErrorAction Stop
    }

    if ($PSCmdlet.ShouldProcess($mc.EnterpriseName, "Removing Managed Company")) {
        $enterprise.mspData.RemoveManagedCompany($mc.EnterpriseId).GetAwaiter().GetResult() | Out-Null
        Write-Information "Removed Managed Company `"$($mc.EnterpriseName)`" ID: $($mc.EnterpriseId)"
    }
}
New-Alias -Name krmc -Value Remove-KeeperManagedCompany

function Edit-KeeperManagedCompany {
    <#
        .Synopsis
    	Removes Managed Company
    	.Parameter Name
	    Managed Company New Name
    	.Parameter PlanId
	    Managed Company Plan
    	.Parameter MaximumSeats
	    Maximum Number of Seats
        .Parameter Storage
        Storage Plan
        .Parameter Addons
        Addons
        .Parameter Node
        Node Name or ID
    	.Parameter Id
	    Managed Company Name or Id
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $false)][string] $Name,
        [Parameter(Mandatory = $false)][ValidateSet('business', 'businessPlus', 'enterprise', 'enterprisePlus')][string] $PlanId,
        [Parameter(Mandatory = $false)][int] $MaximumSeats,
        [Parameter(Mandatory = $false)][ValidateSet('100GB', '1TB', '10TB')][string] $Storage,
        [Parameter(Mandatory = $false)][string[]] $Addons,
        [Parameter(Mandatory = $false)][string] $Node,
        [Parameter(Position = 0, Mandatory = $true)][string] $Id
    )

    [Enterprise]$enterprise = getMspEnterprise
    $mc = findManagedCompany $Id
    if (-not $mc) {
        Write-Error -Message "Managed Company ${Id} not found" -ErrorAction Stop
    }

    $options = New-Object KeeperSecurity.Enterprise.ManagedCompanyOptions
    if ($Name) {
        $options.Name = $Name
    }
    if ($PlanId) {
        $options.ProductId = $PlanId
    }
    if ($MaximumSeats) {
        $options.NumberOfSeats = $MaximumSeats
    }
    if ($Storage) {
        switch ($Storage.Trim().ToUpper()) {
            '100GB' { $options.FilePlanType = [KeeperSecurity.Enterprise.ManagedCompanyConstants]::StoragePlan100GB }
            '1TB' { $options.FilePlanType = [KeeperSecurity.Enterprise.ManagedCompanyConstants]::StoragePlan1TB }
            '10TB' { $options.FilePlanType = [KeeperSecurity.Enterprise.ManagedCompanyConstants]::StoragePlan10TB }
        }
    }
    if ($Addons) {
        $aons = @()
        foreach ($addon in $Addons) {
            $names = $addon -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
            foreach ($name in $names) {
                $parts = $name -split ':'
                $addonOption = New-Object KeeperSecurity.Enterprise.ManagedCompanyAddonOptions
                $addonOption.Addon = $parts[0].Trim()
                if ($parts.Length -gt 1) {
                    $addonOption.NumberOfSeats = $parts[1].Trim() -as [int]
                }
                $aons += $addonOption
            }
        }
        $options.Addons = $aons
    }
    if ($Node) {
        $n = findEnterpriseNode $Node
        if ($n) {
            $options.NodeId = $n.Id
        }
        else {
            Write-Error -Message "Node ${Node} not found" -ErrorAction Stop
        }
    }
    $enterprise.mspData.UpdateManagedCompany($mc.EnterpriseId, $options).GetAwaiter().GetResult()
}
New-Alias -Name kemc -Value Edit-KeeperManagedCompany
Register-ArgumentCompleter -CommandName Edit-KeeperManagedCompany -ParameterName Addons -ScriptBlock $Keeper_MspAddonName

# Plan id -> display name (aligned with Python Commander constants.MSP_PLANS)
$script:MspPlanNames = @{
    1 = 'business'; 2 = 'businessPlus'; 10 = 'enterprise'; 11 = 'enterprisePlus'
}

function Get-MspBillingReport {
    <#
    .Synopsis
    Generate MSP Consumption Billing Statement (aligned with Python Commander msp-billing-report).
    .Parameter Month
    Report month as 1-12 (numeric) or YYYY-MM (e.g. 2022-02). If omitted, previous calendar month is used.
    .Parameter Year
    Report year (e.g. 2022). Used when Month is numeric only.
    .Parameter ShowDate
    Breakdown report by date (-d).
    .Parameter ShowCompany
    Breakdown report by managed company (-c).
    .Parameter Format
    Output format: table (default), json, or csv.
    .Parameter Output
    If supplied, save the report to the given file path.
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $false)]
        [object] $Month,
        [Parameter(Mandatory = $false)]
        [int] $Year = 0,
        [Parameter(Mandatory = $false)]
        [Alias('d')]
        [switch] $ShowDate,
        [Parameter(Mandatory = $false)]
        [Alias('c')]
        [switch] $ShowCompany,
        [Parameter(Mandatory = $false)]
        [ValidateSet('table', 'json', 'csv')]
        [string] $Format = 'table',
        [Parameter(Mandatory = $false)]
        [string] $Output
    )

    $dt = Get-Date
    $apiMonth = -1
    $apiYear = -1

    if ($null -ne $Month -and $Month -is [string] -and $Month -match '^(\d{4})-(\d{2})$') {
        $apiYear = [int]$Matches[1]
        $m = [int]$Matches[2]
        if ($m -lt 1 -or $m -gt 12) {
            Write-Error "Month in YYYY-MM must be 01-12 (got $($Matches[2]))" -ErrorAction Stop
        }
        $apiMonth = $m - 1
    } elseif ($Year -ne 0 -or ($null -ne $Month -and [int]$Month -ne 0)) {
        if ($Year -eq 0) { $Year = $dt.Year }
        $apiYear = $Year
        if ($null -ne $Month -and [int]$Month -ge 1 -and [int]$Month -le 12) {
            $apiMonth = [int]$Month - 1
        } else {
            $apiMonth = $dt.Month - 1
            if ($apiMonth -le 0) {
                $apiYear -= 1
                $apiMonth = 11
            }
        }
    } else {
        $apiYear = $dt.Year
        $apiMonth = $dt.Month - 2
        if ($apiMonth -lt 0) {
            $apiMonth += 12
            $apiYear -= 1
        }
    }

    $auth = [KeeperSecurity.Authentication.IAuthentication]$Script:Context.Auth

    $url = [KeeperSecurity.Authentication.AuthExtensions]::GetBiUrl($auth, 'mapping/addons')
    $rqAddons = New-Object BI.MappingAddonsRequest
    $rsAddons = $auth.ExecuteAuthRest($url, $rqAddons, [BI.MappingAddonsResponse]).GetAwaiter().GetResult()
    $filePlanMap = @{ 4 = '100GB'; 7 = '1TB'; 8 = '10TB' }
    foreach ($fp in $rsAddons.FilePlans) { $filePlanMap[$fp.Id] = $fp.Name }
    $addonById = @{}
    foreach ($a in $rsAddons.Addons) { $addonById[$a.Id] = $a.Name }

    $urlPricing = [KeeperSecurity.Authentication.AuthExtensions]::GetBiUrl($auth, 'subscription/mc_pricing')
    $rqPricing = New-Object BI.SubscriptionMcPricingRequest
    $rsPricing = $auth.ExecuteAuthRest($urlPricing, $rqPricing, [BI.SubscriptionMcPricingResponse]).GetAwaiter().GetResult()
    $rateByProductId = @{}
    $currencySymbol = @{ [int][BI.Currency]::Usd = '$'; [int][BI.Currency]::Eur = [char]0x20AC; [int][BI.Currency]::Gbp = [char]0x00A3; [int][BI.Currency]::Jpy = [char]0x00A5 }
    foreach ($p in $rsPricing.BasePlans) {
        $sym = $currencySymbol[[int]$p.Cost.Currency]
        if (-not $sym) { $sym = '' }
        $rateByProductId[$p.Id] = "$sym$($p.Cost.Amount)"
    }
    foreach ($p in $rsPricing.FilePlans) {
        $sym = $currencySymbol[[int]$p.Cost.Currency]
        if (-not $sym) { $sym = '' }
        $rateByProductId[($p.Id * 100)] = "$sym$($p.Cost.Amount)"
    }
    foreach ($p in $rsPricing.Addons) {
        $sym = $currencySymbol[[int]$p.Cost.Currency]
        if (-not $sym) { $sym = '' }
        $rateByProductId[($p.Id * 10000)] = "$sym$($p.Cost.Amount)"
    }

    $url = [KeeperSecurity.Authentication.AuthExtensions]::GetBiUrl($auth, 'reporting/daily_snapshot')
    $rq = New-Object BI.ReportingDailySnapshotRequest
    $rq.Month = [Math]::Max(1, [Math]::Min(12, $apiMonth + 1))
    $rq.Year = $apiYear
    $rs = $auth.ExecuteAuthRest($url, $rq, [BI.ReportingDailySnapshotResponse]).GetAwaiter().GetResult()
    $mcNames = @{}
    foreach ($mc in $rs.McEnterprises) { $mcNames[$mc.Id] = $mc.Name }

    $dailySnapshots = @{}
    foreach ($rec in $rs.Records) {
        $recDate = [KeeperSecurity.Utils.DateTimeOffsetExtensions]::FromUnixTimeMilliseconds($rec.Date).UtcDateTime.Date
        $dateOrdinal = $recDate.Ticks / [TimeSpan]::TicksPerDay
        $key = "$($rec.McEnterpriseId)_$dateOrdinal"
        if (-not $dailySnapshots[$key]) { $dailySnapshots[$key] = @{ McId = $rec.McEnterpriseId; DateOrdinal = $dateOrdinal; Units = @{} } }
        $u = $dailySnapshots[$key].Units
        if ($rec.MaxLicenseCount -gt 0) {
            if ($rec.MaxBasePlanId -gt 0) { $u[$rec.MaxBasePlanId] = $rec.MaxLicenseCount }
            if ($rec.MaxFilePlanTypeId -gt 0) { $u[$rec.MaxFilePlanTypeId * 100] = $rec.MaxLicenseCount }
        }
        foreach ($addon in $rec.Addons) {
            if ($addon.MaxAddonId -gt 0) { $u[$addon.MaxAddonId * 10000] = $addon.Units }
        }
    }

    $merged = @{}
    foreach ($k in $dailySnapshots.Keys) {
        $ds = $dailySnapshots[$k]
        $mc = if ($ShowCompany) { $ds.McId } else { 0 }
        $d = if ($ShowDate) { $ds.DateOrdinal } else { 0 }
        $mergeKey = "${mc}_$d"
        if (-not $merged[$mergeKey]) {
            $merged[$mergeKey] = @{ McId = $mc; DateOrdinal = $d; QtyDays = @{} }
        }
        $qd = $merged[$mergeKey].QtyDays
        foreach ($pid in $ds.Units.Keys) {
            $q = $ds.Units[$pid]
            if (-not $qd[$pid]) { $qd[$pid] = @(0, 0) }
            $qd[$pid][0] += $q
            $qd[$pid][1] += 1
        }
    }

    $numReportedDays = 30
    $allDates = @($dailySnapshots.Values | ForEach-Object { $_.DateOrdinal } | Sort-Object -Unique)
    if ($allDates.Count -gt 0) {
        $numReportedDays = [int](($allDates[-1] - $allDates[0]) + 1)
    }

    $getCountId = {
        param([long]$productKey)
        if ($productKey -gt 0 -and $productKey -lt 100) { return [int]$productKey }
        if ($productKey -gt 100 -and $productKey -lt 10000) { return [int]($productKey / 100) }
        if ($productKey -gt 10000) { return [int]($productKey / 10000) }
        return 0
    }
    $getProductName = {
        param([long]$productKey)
        $cid = & $getCountId $productKey
        if ($productKey -gt 0 -and $productKey -lt 100) {
            $name = $script:MspPlanNames[[int]$productKey]
            if ($name) { return $name }
            return "Plan #$cid"
        }
        if ($productKey -gt 100 -and $productKey -lt 10000) {
            $name = $filePlanMap[$cid]
            if ($name) { return $name }
            return "Storage #$cid"
        }
        if ($productKey -gt 10000) {
            $name = $addonById[$cid]
            if ($name) { return $name }
            return "Addon #$cid"
        }
        return "Product $productKey"
    }
    $getRate = { param([long]$productKey) $r = $rateByProductId[$productKey]; if ($r) { return $r }; return '' }

    $startEndByMc = @{}
    $mcIds = @($dailySnapshots.Values | ForEach-Object { $_.McId } | Sort-Object -Unique)
    foreach ($mid in $mcIds) {
        $dates = @($dailySnapshots.GetEnumerator() | Where-Object { $_.Value.McId -eq $mid } | ForEach-Object { $_.Value.DateOrdinal } | Sort-Object -Unique)
        if ($dates.Count -eq 0) { continue }
        $minD = $dates[0]; $maxD = $dates[-1]
        $startUnits = @{}; $endUnits = @{}
        foreach ($kv in $dailySnapshots.GetEnumerator()) {
            $v = $kv.Value
            if ($v.McId -ne $mid) { continue }
            if ($v.DateOrdinal -eq $minD) {
                foreach ($p in $v.Units.Keys) { $startUnits[$p] = ($startUnits[$p] + 0) + $v.Units[$p] }
            }
            if ($v.DateOrdinal -eq $maxD) {
                foreach ($p in $v.Units.Keys) { $endUnits[$p] = ($endUnits[$p] + 0) + $v.Units[$p] }
            }
        }
        $startEndByMc[$mid] = @{ Start = $startUnits; End = $endUnits }
    }
    $globalStart = @{}; $globalEnd = @{}
    foreach ($kv in $dailySnapshots.GetEnumerator()) {
        $v = $kv.Value
        $isMin = ($allDates.Count -gt 0 -and $v.DateOrdinal -eq $allDates[0])
        $isMax = ($allDates.Count -gt 0 -and $v.DateOrdinal -eq $allDates[-1])
        if ($isMin) { foreach ($p in $v.Units.Keys) { $globalStart[$p] = ($globalStart[$p] + 0) + $v.Units[$p] } }
        if ($isMax) { foreach ($p in $v.Units.Keys) { $globalEnd[$p] = ($globalEnd[$p] + 0) + $v.Units[$p] } }
    }

    $maxByProductMc = @{}
    foreach ($mid in @(0) + @($mcIds)) {
        $maxByProductMc[$mid] = @{}
        $datesToSum = if ($mid -eq 0) { $allDates } else { @($dailySnapshots.GetEnumerator() | Where-Object { $_.Value.McId -eq $mid } | ForEach-Object { $_.Value.DateOrdinal } | Sort-Object -Unique) }
        foreach ($d in $datesToSum) {
            $dayTotal = @{}
            foreach ($kv in $dailySnapshots.GetEnumerator()) {
                $v = $kv.Value
                if ($mid -ne 0 -and $v.McId -ne $mid) { continue }
                if ($v.DateOrdinal -ne $d) { continue }
                foreach ($p in $v.Units.Keys) { $dayTotal[$p] = ($dayTotal[$p] + 0) + $v.Units[$p] }
            }
            foreach ($p in $dayTotal.Keys) {
                if (-not $maxByProductMc[$mid][$p]) { $maxByProductMc[$mid][$p] = 0 }
                if ($dayTotal[$p] -gt $maxByProductMc[$mid][$p]) { $maxByProductMc[$mid][$p] = $dayTotal[$p] }
            }
        }
    }

    $table = [System.Collections.ArrayList]::new()
    $calendarMonth = [Math]::Max(1, [Math]::Min(12, $apiMonth + 1))
    $monthName = (Get-Date -Year $apiYear -Month $calendarMonth -Day 1).ToString('MMMM')
    $title = "Consumption Billing Statement: $monthName $apiYear"

    foreach ($mergeKey in ($merged.Keys | Sort-Object)) {
        $point = $merged[$mergeKey]
        $mc = $point.McId
        $dateOrd = $point.DateOrdinal
        $dayStr = ''
        if ($ShowDate -and $dateOrd -ne 0) {
            $dayStr = [DateTime]::new([long]($dateOrd * [TimeSpan]::TicksPerDay)).ToString('yyyy-MM-dd')
        }
        $company = ''
        $companyId = ''
        if ($ShowCompany -and $mc -ne 0) {
            $company = $mcNames[$mc]
            if (-not $company) { $company = "MC $mc" }
            $companyId = $mc
        }
        $daysForPoint = if ($ShowDate -and $dateOrd -ne 0) { 1 } else { $numReportedDays }
        if ($ShowCompany -and $mc -ne 0 -and -not $ShowDate) {
            $mcDates = @($dailySnapshots.GetEnumerator() | Where-Object { $_.Value.McId -eq $mc } | ForEach-Object { $_.Value.DateOrdinal } | Sort-Object -Unique)
            if ($mcDates.Count -gt 0) { $daysForPoint = [int](($mcDates[-1] - $mcDates[0]) + 1) }
        }
        $startUnits = if ($mc -eq 0) { $globalStart } else { $startEndByMc[$mc].Start }
        $endUnits = if ($mc -eq 0) { $globalEnd } else { $startEndByMc[$mc].End }
        $maxUnits = $maxByProductMc[$mc]

        $productIds = $point.QtyDays.Keys | Sort-Object
        foreach ($productKey in $productIds) {
            $qtyDays = $point.QtyDays[$productKey]
            $count = $qtyDays[0]
            $days = if ($ShowCompany -and $mc -ne 0) { $qtyDays[1] } else { $daysForPoint }
            $productName = & $getProductName $productKey
            $rateText = & $getRate $productKey
            $row = [ordered]@{}
            if ($ShowDate) { $row['Date'] = $dayStr }
            if ($ShowCompany) { $row['Company'] = $company; $row['CompanyId'] = $companyId }
            $row['Product'] = $productName
            $row['Licenses'] = $count
            $row['Rate'] = $rateText
            $row['AvgPerDay'] = if ($days -gt 0) { [math]::Round($count / [double]$days, 2) } else { 0 }
            if ($ShowDate -and $dateOrd -ne 0) {
                $startCount = $count; $endCount = $count; $maxCount = $count
            } else {
                $startCount = 0; if ($startUnits -and $startUnits[$productKey]) { $startCount = $startUnits[$productKey] }
                $endCount = 0; if ($endUnits -and $endUnits[$productKey]) { $endCount = $endUnits[$productKey] }
                $maxCount = 0; if ($maxUnits -and $maxUnits[$productKey]) { $maxCount = $maxUnits[$productKey] }
            }
            $row['InitialLicenses'] = $startCount
            $row['FinalLicenses'] = $endCount
            $row['MaxLicenses'] = $maxCount
            [void]$table.Add([PSCustomObject]$row)
        }
    }

    $out = $null
    switch ($Format) {
        'json' { $out = @{ title = $title; rows = $table } | ConvertTo-Json -Depth 5 }
        'csv' { $out = $table | ConvertTo-Csv -NoTypeInformation }
        'table' { $out = $table | Format-Table -AutoSize }
    }

    if ($Output) {
        if ($Format -eq 'table') {
            $tableStr = $table | Format-Table -AutoSize | Out-String
            Set-Content -Path $Output -Value ($title + "`n`n" + $tableStr) -Encoding utf8
        } else {
            Set-Content -Path $Output -Value $out -Encoding utf8
        }
    } else {
        if ($Format -eq 'table') {
            Write-Host $title
            Write-Host ''
        }
        $out
    }
}

function findManagedCompany {
    Param (
        [string]$mc
    )
    $enterprise = getMspEnterprise
    $enterprise.mspData.ManagedCompanies | Where-Object { ($_.EnterpriseId -eq $mc) -or ($_.EnterpriseName -eq $mc) } | Select-Object -First 1
}

function findEnterpriseNode {
    Param (
        [string]$node
    )
    $enterprise = getEnterprise
    if ($node -eq $enterprise.loader.EnterpriseName) {
        return $enterprise.enterpriseData.RootNode
    }
    $enterprise.enterpriseData.Nodes | Where-Object { ($_.Id -eq $node) -or ($_.DisplayName -eq $node) } | Select-Object -First 1
}

function getMspEnterprise {
    [Enterprise] $enterprise = $Script:Context.Enterprise
    if (-not $enterprise) {
        $enterprise = getEnterprise
    }
    if ($enterprise.enterpriseData.EnterpriseLicense -and $enterprise.enterpriseData.EnterpriseLicense.LicenseStatus -like "msp*") {
        return $enterprise
    }
    Write-Error -Message "Not a MSP (Managed Service Provider)" -ErrorAction Stop
}
