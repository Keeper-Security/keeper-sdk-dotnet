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

    $mc = @($enterprise.mspData.ManagedCompanies | Where-Object { ($_.EnterpriseId -eq $Name) })
    if ($mc.Count -eq 0) {
        $mc = @($enterprise.mspData.ManagedCompanies | Where-Object { ($_.EnterpriseName -like $Name + '*') })
    }
    if ($mc.Count -eq 0) {
        Write-Error -Message "Managed Company`"$Name`" not found" -ErrorAction Stop
    }
    elseif ($mc.Count -gt 1) {
        Write-Error -Message "Managed Company`"$Name`" is not unique. Use Company ID." -ErrorAction Stop
    }

    $Script:Context.ManagedCompanyId = $mc[0].EnterpriseId
    Sync-KeeperEnterprise

    Write-Host "Switched to Managed Company `"$($mc[0].EnterpriseName)`" (ID: $($mc[0].EnterpriseId))."
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

    Write-Host "Switched to MSP."
}
New-Alias -Name switch-to-msp -Value Switch-KeeperMSP


function Get-KeeperManagedCompany {
    <#
    .SYNOPSIS
    MSP info and managed company list: restriction, pricing, or MC list.
    .DESCRIPTION
    One command for all MSP info: -Restriction (permits), -Pricing (BI pricing), or MC list (default). Use -Detailed for MC list with sorted names, display labels, and addon:seats. Supports -Format and -Output.
    .PARAMETER Restriction
    Display MSP restriction information (allowed products, add-ons, max file plan, unlimited licenses).
    .PARAMETER Pricing
    Display pricing information (BI subscription/mc_pricing).
    .PARAMETER Filter
    Managed Company ID or Name (optional partial filter; ignored when -ManagedCompany or -Restriction or -Pricing is used).
    .PARAMETER Detailed
    Detailed MC list: company_id, company_name, node, node_name, plan, storage, addons, allocated, active; sorted by name; addon:seats.
    .PARAMETER ManagedCompany
    Filter to a single managed company by exact name or ID (exact match). Use with -Detailed.
    .PARAMETER Format
    Output format: table (default), json, csv.
    .PARAMETER Output
    If supplied, write output to this file path.
    .EXAMPLE
    Get-KeeperManagedCompany
    Get-KeeperManagedCompany -Detailed
    Get-KeeperManagedCompany -Restriction
    Get-KeeperManagedCompany -Pricing -Format json -Output pricing.json
    Get-KeeperManagedCompany -Detailed -ManagedCompany "Acme"
    #>
    [CmdletBinding()]
    Param (
        [Parameter()][Alias('r')][switch] $Restriction,
        [Parameter()][Alias('p')][switch] $Pricing,
        [Parameter(Mandatory = $false)][string] $Filter,
        [Parameter()][Alias('v')][switch] $Detailed,
        [Parameter()][Alias('mc')][string] $ManagedCompany,
        [Parameter()][ValidateSet('table', 'json', 'csv')][string] $Format = 'table',
        [Parameter()][string] $Output
    )

    [Enterprise]$enterprise = getMspEnterprise
    $ed = $enterprise.enterpriseData

    if ($Restriction) {
        $permits = $ed.EnterpriseLicense.MspPermits
        if (-not $permits) {
            Write-Information 'MSP has no restrictions'
            return
        }
        $allProducts = @{ 'business' = 'Business'; 'businessplus' = 'Business Plus'; 'enterprise' = 'Enterprise'; 'enterprise_plus' = 'Enterprise Plus' }
        $allAddons = @{}
        $addonKeys = @($script:MspAddonDisplayNames.Keys)
        foreach ($k in $addonKeys) { $allAddons[$k.ToLower()] = $script:MspAddonDisplayNames[$k] }
        $allFilePlans = @{ '100gb' = '100GB'; '1tb' = '1TB'; '10tb' = '10TB' }
        $rows = [System.Collections.ArrayList]::new()
        [void]$rows.Add([PSCustomObject]@{ 'Permit Name' = 'Allow Unlimited Licenses'; 'Value' = $permits.AllowUnlimitedLicenses })
        $allowedProducts = @($permits.AllowedMcProducts | ForEach-Object { $p = $_.ToLower(); $d = $allProducts[$p]; if ($d) { "$_ ($d)" } else { $_ } })
        [void]$rows.Add([PSCustomObject]@{ 'Permit Name' = 'Allowed Products'; 'Value' = ($allowedProducts -join ', ') })
        $allowedAddons = @($permits.AllowedAddOns | ForEach-Object { $a = $_.ToLower(); $d = $allAddons[$a]; if ($d) { "$_ ($d)" } else { $_ } })
        [void]$rows.Add([PSCustomObject]@{ 'Permit Name' = 'Allowed Add-Ons'; 'Value' = ($allowedAddons -join ', ') })
        $maxFp = $permits.MaxFilePlanType
        $fpD = $allFilePlans[[string]$maxFp.ToLower()]
        [void]$rows.Add([PSCustomObject]@{ 'Permit Name' = 'Max File Storage plan'; 'Value' = $(if ($fpD) { $fpD } else { $maxFp }) })
        $result = @($rows)
        if ($Output) {
            if ($Format -eq 'json') { Set-Content -Path $Output -Value ($result | ConvertTo-Json -Depth 3) -Encoding utf8 }
            elseif ($Format -eq 'csv') { Set-Content -Path $Output -Value ($result | ConvertTo-Csv -NoTypeInformation) -Encoding utf8 }
            else { $result | Format-Table | Out-String -Width 8192 | Set-Content -Path $Output -Encoding utf8 }
        } else {
            if ($Format -eq 'table') { $result | Format-Table | Out-String -Width 8192 } else { $result }
        }
        return
    }

    if ($Pricing) {
        $auth = [KeeperSecurity.Authentication.IAuthentication]$Script:Context.Auth
        $urlMap = [KeeperSecurity.Authentication.AuthExtensions]::GetBiUrl($auth, 'mapping/addons')
        $rqMap = New-Object BI.MappingAddonsRequest
        $rsMap = $auth.ExecuteAuthRest($urlMap, $rqMap, [BI.MappingAddonsResponse]).GetAwaiter().GetResult()
        $addonNameById = @{}
        foreach ($a in $rsMap.Addons) { $addonNameById[$a.Id] = $a.Name }
        $filePlanNameById = @{ 4 = '100GB'; 7 = '1TB'; 8 = '10TB' }
        foreach ($fp in $rsMap.FilePlans) { $filePlanNameById[$fp.Id] = $fp.Name }
        $url = [KeeperSecurity.Authentication.AuthExtensions]::GetBiUrl($auth, 'subscription/mc_pricing')
        $rq = New-Object BI.SubscriptionMcPricingRequest
        $rs = $auth.ExecuteAuthRest($url, $rq, [BI.SubscriptionMcPricingResponse]).GetAwaiter().GetResult()
        $currencySymbol = @{ [int][BI.Currency]::Usd = '$'; [int][BI.Currency]::Eur = [char]0x20AC; [int][BI.Currency]::Gbp = [char]0x00A3; [int][BI.Currency]::Jpy = [char]0x00A5 }
        $unitLabel = @{ 0 = ''; 1 = 'month'; 2 = 'user/month' }
        $rows = [System.Collections.ArrayList]::new()
        foreach ($p in $rs.BasePlans) {
            $sym = $currencySymbol[[int]$p.Cost.Currency]; if (-not $sym) { $sym = '' }
            $unit = $unitLabel[[int]$p.Cost.AmountPer]; if (-not $unit) { $unit = 'month' }
            $name = $script:MspPlanNames[[int]$p.Id]; if (-not $name) { $name = "Plan$($p.Id)" }
            [void]$rows.Add([PSCustomObject]@{ Category = 'Product'; Name = $name; Code = $p.Id; Price = "$sym$($p.Cost.Amount)/$unit" })
        }
        foreach ($p in $rs.Addons) {
            $sym = $currencySymbol[[int]$p.Cost.Currency]; if (-not $sym) { $sym = '' }
            $unit = $unitLabel[[int]$p.Cost.AmountPer]; if (-not $unit) { $unit = 'month' }
            $name = $addonNameById[$p.Id]; if (-not $name) { $name = "Addon$($p.Id)" }
            [void]$rows.Add([PSCustomObject]@{ Category = 'Addon'; Name = $name; Code = $p.Id; Price = "$sym$($p.Cost.Amount)/$unit" })
        }
        foreach ($p in $rs.FilePlans) {
            $sym = $currencySymbol[[int]$p.Cost.Currency]; if (-not $sym) { $sym = '' }
            $unit = $unitLabel[[int]$p.Cost.AmountPer]; if (-not $unit) { $unit = 'month' }
            $name = $filePlanNameById[$p.Id]; if (-not $name) { $name = "FilePlan$($p.Id)" }
            [void]$rows.Add([PSCustomObject]@{ Category = 'File Plan'; Name = $name; Code = $p.Id; Price = "$sym$($p.Cost.Amount)/$unit" })
        }
        $result = @($rows)
        if ($Output) {
            if ($Format -eq 'json') { Set-Content -Path $Output -Value ($result | ConvertTo-Json -Depth 3) -Encoding utf8 }
            elseif ($Format -eq 'csv') { Set-Content -Path $Output -Value ($result | ConvertTo-Csv -NoTypeInformation) -Encoding utf8 }
            else { $result | Format-Table | Out-String -Width 8192 | Set-Content -Path $Output -Encoding utf8 }
        } else {
            if ($Format -eq 'table') { $result | Format-Table | Out-String -Width 8192 } else { $result }
        }
        return
    }

    $list = $enterprise.mspData.ManagedCompanies
    if (-not $list -or $list.Count -eq 0) {
        if ($Detailed) { Write-Information 'No Managed Companies' }
        return @()
    }

    if ($ManagedCompany) {
        $mcInput = $ManagedCompany.Trim()
        $isId = $false
        try { [long]::Parse($mcInput) | Out-Null; $isId = $true } catch { }
        $filtered = @(if ($isId) {
            @($list) | Where-Object { $_.EnterpriseId -eq [long]$mcInput }
        } else {
            @($list) | Where-Object { $_.EnterpriseName -and ($_.EnterpriseName.Trim().ToLower() -eq $mcInput.ToLower()) }
        })
        if ($filtered.Count -eq 0) {
            Write-Error "Managed Company `"$ManagedCompany`" not found" -ErrorAction Stop
        }
        $list = @($filtered)
    } elseif ($Filter) {
        $filterStr = $Filter.Trim()
        $list = @($list) | Where-Object {
            $_.EnterpriseId.ToString() -eq $filterStr -or
            ($_.EnterpriseName -and ($_.EnterpriseName -like '*' + $filterStr + '*'))
        }
    }

    if ($Detailed) {
        $list = @($list | Sort-Object { $_.EnterpriseName })
        $planDisplay = @{ 'business' = 'Business'; 'businessplus' = 'Business Plus'; 'enterprise' = 'Enterprise'; 'enterprise_plus' = 'Enterprise Plus' }
        $filePlanMap = @{ '100gb' = '100GB'; '1tb' = '1TB'; '10tb' = '10TB'; 'storage_100gb' = '100GB'; 'storage_1tb' = '1TB'; 'storage_10tb' = '10TB' }
        $result = [System.Collections.ArrayList]::new()
        foreach ($mc in $list) {
            $nodeId = if ($mc.ParentNodeId -le 0) { $ed.RootNode.Id } else { $mc.ParentNodeId }
            $nodePath = Get-MspNodePath -EnterpriseData $ed -NodeId $nodeId -OmitRoot $true
            if ([string]::IsNullOrEmpty($nodePath)) { $nodePath = $nodeId.ToString() }
            $nodeName = $nodePath
            $filePlan = $mc.FilePlanType
            if ($filePlan) { $fp = $filePlanMap[[string]$filePlan.ToLower()]; if ($fp) { $filePlan = $fp } }
            $addonList = [System.Collections.Generic.List[string]]::new()
            if ($mc.AddOns) {
                foreach ($ao in $mc.AddOns) {
                    $an = $ao.Name
                    if ($ao.Seats -and [int]$ao.Seats -gt 0) {
                        $s = $ao.Seats; if ($s -eq -1 -or $s -ge $script:McUnlimitedSeatsValue) { $s = -1 }
                        $addonList.Add("${an}:$s")
                    } else {
                        $addonList.Add($an)
                    }
                }
            }
            $addonsOut = $addonList -join ', '
            $plan = $mc.ProductId
            if ($plan) { $pd = $planDisplay[[string]$plan.ToLower()]; if ($pd) { $plan = $pd } }
            $seats = $mc.NumberOfSeats
            if ($seats -eq -1 -or $seats -ge $script:McUnlimitedSeatsValue) { $seats = -1 }
            $row = [ordered]@{
                company_id   = $mc.EnterpriseId
                company_name = $mc.EnterpriseName
                node         = $nodePath
                node_name    = $nodeName
                plan         = $plan
                storage      = $filePlan
                addons       = $addonsOut
                allocated    = $seats
                active       = $mc.NumberOfUsers
            }
            [void]$result.Add([PSCustomObject]$row)
        }
        $result = @($result)
    } else {
        $result = @($list | ForEach-Object {
            $mc = $_
            $addonsStr = ''
            if ($mc.AddOns -and $mc.AddOns.Count -gt 0) {
                $addonsStr = ($mc.AddOns | ForEach-Object { $_.Name }) -join ', '
            }
            $nodeName = $mc.ParentNodeId
            $node = $ed.Nodes | Where-Object { $_.Id -eq $mc.ParentNodeId } | Select-Object -First 1
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
        })
    }

    if ($result.Count -eq 0) { return @() }
    if ($Output) {
        if ($Format -eq 'json') { Set-Content -Path $Output -Value ($result | ConvertTo-Json -Depth 4) -Encoding utf8 }
        elseif ($Format -eq 'csv') { Set-Content -Path $Output -Value ($result | ConvertTo-Csv -NoTypeInformation) -Encoding utf8 }
        else { $result | Format-Table | Out-String -Width 8192 | Set-Content -Path $Output -Encoding utf8 }
    } else {
        if ($Format -eq 'table') { $result | Format-Table | Out-String -Width 8192 } else { $result }
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
	    Managed Company Plan. ValidateSet casing (e.g. businessPlus)
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
        Write-Host "`"$($mc.EnterpriseName)`" MSP removed successfully."
    }
}
New-Alias -Name krmc -Value Remove-KeeperManagedCompany

function Edit-KeeperManagedCompany {
    <#
    .SYNOPSIS
    Update a Managed Company.
    .DESCRIPTION
    Modify MC name, plan, seats, storage, node, or addons. Use -AddAddon / -RemoveAddon to add/remove individual addons, or -Addons to set the full addon list. -MaximumSeats -1 = unlimited.
    .PARAMETER Id
    Managed Company name or ID (required).
    .PARAMETER Name
    New managed company name.
    .PARAMETER PlanId
    License plan: business, businessPlus, enterprise, enterprisePlus.
    .PARAMETER MaximumSeats
    Max licenses; use -1 for unlimited.
    .PARAMETER Storage
    File storage plan: 100GB, 1TB, 10TB. Cannot be lower than the plan's default (e.g. Enterprise Plus defaults to 1TB).
    .PARAMETER Node
    Node name or ID to move the MC to.
    .PARAMETER Addons
    Full addon list (replaces existing). Each item: AddonName or AddonName:Seats (e.g. connection_manager:5).
    .PARAMETER AddAddon
    Add (or update) addon(s); can repeat. Format: AddonName or AddonName:Seats.
    .PARAMETER RemoveAddon
    Remove addon(s); can repeat.
    .EXAMPLE
    Edit-KeeperManagedCompany -Id "Acme" -Name "Acme Corp" -MaximumSeats 100
    Edit-KeeperManagedCompany -Id 3862 -AddAddon "connection_manager:5" -RemoveAddon "secrets_manager"
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    Param (
        [Parameter(Position = 0, Mandatory = $true)][string] $Id,
        [Parameter(Mandatory = $false)][string] $Name,
        [Parameter(Mandatory = $false)][ValidateSet('business', 'businessPlus', 'enterprise', 'enterprisePlus')][string] $PlanId,
        [Parameter(Mandatory = $false)][int] $MaximumSeats = [int]::MinValue,
        [Parameter(Mandatory = $false)][ValidateSet('100GB', '1TB', '10TB')][string] $Storage,
        [Parameter(Mandatory = $false)][string] $Node,
        [Parameter(Mandatory = $false)][string[]] $Addons,
        [Parameter(Mandatory = $false)][string[]] $AddAddon,
        [Parameter(Mandatory = $false)][string[]] $RemoveAddon
    )

    [Enterprise]$enterprise = getMspEnterprise
    $mc = findManagedCompany $Id
    if (-not $mc) {
        Write-Error -Message "Managed Company `"$Id`" not found" -ErrorAction Stop
    }

    $options = New-Object KeeperSecurity.Enterprise.ManagedCompanyOptions
    if ($Name) { $options.Name = $Name }
    if ($PlanId) { $options.ProductId = $PlanId }
    if ($MaximumSeats -ne [int]::MinValue) {
        $options.NumberOfSeats = if ($MaximumSeats -gt 1) { $MaximumSeats } else { -1 }
    }
    if ($Storage) {
        switch ($Storage.Trim().ToUpper()) {
            '100GB' { $options.FilePlanType = [KeeperSecurity.Enterprise.ManagedCompanyConstants]::StoragePlan100GB }
            '1TB' { $options.FilePlanType = [KeeperSecurity.Enterprise.ManagedCompanyConstants]::StoragePlan1TB }
            '10TB' { $options.FilePlanType = [KeeperSecurity.Enterprise.ManagedCompanyConstants]::StoragePlan10TB }
        }
    }
    if ($Node) {
        $n = findEnterpriseNode $Node
        if ($n) { $options.NodeId = $n.Id }
        else { Write-Error -Message "Node `"$Node`" not found" -ErrorAction Stop }
    }

    $addonsToSend = $null
    if ($Addons) {
        $addonsToSend = [System.Collections.ArrayList]::new()
        foreach ($addon in $Addons) {
            foreach ($item in ($addon -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
                $parts = $item -split ':', 2
                $addonOption = New-Object KeeperSecurity.Enterprise.ManagedCompanyAddonOptions
                $addonOption.Addon = $parts[0].Trim().ToLower()
                if ($parts.Length -gt 1 -and $parts[1]) {
                    $s = $parts[1].Trim()
                    $addonOption.NumberOfSeats = if ($s -eq '-1') { -1 } else { [int]$s }
                }
                [void]$addonsToSend.Add($addonOption)
            }
        }
    } elseif ($AddAddon -or $RemoveAddon) {
        $addonDict = [System.Collections.Generic.Dictionary[string, object]]::new([StringComparer]::OrdinalIgnoreCase)
        if ($mc.AddOns) {
            foreach ($ao in $mc.AddOns) {
                if (-not $ao.IsEnabled) { continue }
                $addonOption = New-Object KeeperSecurity.Enterprise.ManagedCompanyAddonOptions
                $addonOption.Addon = $ao.Name
                if ($ao.Seats -gt 0) { $addonOption.NumberOfSeats = if ($ao.Seats -eq -1 -or $ao.Seats -ge $script:McUnlimitedSeatsValue) { -1 } else { $ao.Seats } }
                $addonDict[$ao.Name] = $addonOption
            }
        }
        foreach ($ra in @($RemoveAddon)) {
            foreach ($a in ($ra -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
                $addonDict.Remove($a) | Out-Null
            }
        }
        foreach ($aa in @($AddAddon)) {
            foreach ($item in ($aa -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
                $parts = $item -split ':', 2
                $addonName = $parts[0].Trim().ToLower()
                $addonOption = New-Object KeeperSecurity.Enterprise.ManagedCompanyAddonOptions
                $addonOption.Addon = $addonName
                if ($parts.Length -gt 1 -and $parts[1]) {
                    $s = $parts[1].Trim()
                    $addonOption.NumberOfSeats = if ($s -eq '-1') { -1 } else { [int]$s }
                }
                $addonDict[$addonName] = $addonOption
            }
        }
        $addonsToSend = [System.Collections.ArrayList]::new()
        foreach ($v in $addonDict.Values) { [void]$addonsToSend.Add($v) }
    }
    if ($addonsToSend -and $addonsToSend.Count -gt 0) {
        $options.Addons = @($addonsToSend)
    }

    if ($PSCmdlet.ShouldProcess($mc.EnterpriseName, "Updating Managed Company")) {
        $enterprise.mspData.UpdateManagedCompany($mc.EnterpriseId, $options).GetAwaiter().GetResult()
    }
}
New-Alias -Name kemc -Value Edit-KeeperManagedCompany
Register-ArgumentCompleter -CommandName Edit-KeeperManagedCompany -ParameterName Addons -ScriptBlock $Keeper_MspAddonName

function Copy-KeeperMCRole {
    <#
    .SYNOPSIS
    Copy role(s) with enforcements from MSP to one or more Managed Companies.
    .DESCRIPTION
    Each specified role (by name or ID): finds or creates a role with the same name in each target MC
    and syncs enforcements from the source role (add/update to match source, remove any not in source).
    Requires MSP account. Does not change current context (MSP or MC).
    .PARAMETER Role
    Source role name or ID. Can be repeated. Roles are resolved in the current MSP enterprise.
    .PARAMETER ManagedCompany
    Target Managed Company name or ID. Can be repeated. Each MC will receive a copy of each role's enforcements.
    .EXAMPLE
    Copy-KeeperMCRole -Role "Keeper Administrator" -ManagedCompany "Acme Corp", 3862
    Copy-KeeperMCRole -Role "Auditor", "Help Desk" -ManagedCompany "Acme"
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    Param (
        [Parameter(Mandatory = $true)][string[]] $Role,
        [Parameter(Mandatory = $true)][string[]] $ManagedCompany
    )

    [Enterprise]$mspEnterprise = getMspEnterprise
    $mspRd = $mspEnterprise.roleData
    $mspLoader = $mspEnterprise.loader

    $sourceRoles = [System.Collections.Generic.List[object]]::new()
    foreach ($rInput in $Role) {
        $rInput = $rInput.Trim()
        $matched = $null
        $idParsed = 0L
        if ([long]::TryParse($rInput, [ref]$idParsed)) {
            $matched = @($mspRd.Roles | Where-Object { $_.Id -eq $idParsed })
        }
        if (-not $matched -or $matched.Count -eq 0) {
            $matched = @($mspRd.Roles | Where-Object { $_.DisplayName -and ($_.DisplayName.Trim() -eq $rInput) })
        }
        if (-not $matched -or $matched.Count -eq 0) {
            Write-Error "Role `"$rInput`" not found" -ErrorAction Stop
        }
        if ($matched.Count -gt 1) {
            Write-Error "Multiple roles match `"$rInput`". Use Role ID." -ErrorAction Stop
        }
        $sourceRoles.Add($matched[0]) | Out-Null
    }

    $enforcementByRole = @{}
    foreach ($sr in $sourceRoles) {
        $roleName = $sr.DisplayName
        if ([string]::IsNullOrWhiteSpace($roleName)) {
            Write-Warning "Skipping role with ID $($sr.Id) (no display name)"
            continue
        }
        $dict = Get-RoleEnforcementDictionary -RoleData $mspRd -RoleId $sr.Id
        $enforcementByRole[$roleName] = @{ Role = $sr; Enforcements = $dict }
    }

    if ($enforcementByRole.Count -eq 0) {
        Write-Warning "No roles with display name to copy."
        return
    }

    $seenMcIds = [System.Collections.Generic.HashSet[int]]::new()
    $mcs = [System.Collections.Generic.List[object]]::new()
    foreach ($mcInput in $ManagedCompany) {
        $mc = findManagedCompany $mcInput.Trim()
        if (-not $mc) {
            Write-Warning "Managed Company `"$mcInput`" not found; skipping."
            continue
        }
        $eid = [int]$mc.EnterpriseId
        if ($seenMcIds.Add($eid)) {
            $mcs.Add($mc) | Out-Null
        }
    }

    foreach ($mc in $mcs) {
        if (-not $PSCmdlet.ShouldProcess("$($mc.EnterpriseName) (ID: $($mc.EnterpriseId))", "Copy role(s) to Managed Company")) { continue }

        $authMc = New-Object KeeperSecurity.Enterprise.ManagedCompanyAuth
        $authMc.LoginToManagedCompany($mspLoader, $mc.EnterpriseId).GetAwaiter().GetResult() | Out-Null

        $edMc = New-Object KeeperSecurity.Enterprise.EnterpriseData
        $rdMc = New-Object KeeperSecurity.Enterprise.RoleData
        $daMc = New-Object KeeperSecurity.Enterprise.DeviceApprovalData
        $plugins = [KeeperSecurity.Enterprise.EnterpriseDataPlugin[]]@($edMc, $rdMc, $daMc)
        $loaderMc = New-Object KeeperSecurity.Enterprise.EnterpriseLoader($authMc, $plugins)
        $loaderMc.Load().GetAwaiter().GetResult() | Out-Null

        $rootNodeId = $edMc.RootNode.Id

        foreach ($roleName in $enforcementByRole.Keys) {
            $srcData = $enforcementByRole[$roleName]
            $srcRole = $srcData.Role
            $srcEnforcements = $srcData.Enforcements

            $mcRoles = @($rdMc.Roles | Where-Object { $_.DisplayName -and ($_.DisplayName.Trim() -eq $roleName) })
            if ($mcRoles.Count -gt 1) {
                Write-Warning "MC $($mc.EnterpriseId): Multiple roles named `"$roleName`". Skipping."
                continue
            }

            $mcRole = $null
            if ($mcRoles.Count -eq 0) {
                $mcRole = $rdMc.CreateRole($roleName, $rootNodeId, $srcRole.NewUserInherit).GetAwaiter().GetResult()
                if (-not $mcRole) {
                    Write-Warning "MC $($mc.EnterpriseId): Failed to create role `"$roleName`"."
                    continue
                }
            } else {
                $mcRole = $mcRoles[0]
            }

            $mcEnforcementDict = Get-RoleEnforcementDictionary -RoleData $rdMc -RoleId $mcRole.Id

            $toAdd = [System.Collections.Generic.Dictionary[KeeperSecurity.Enterprise.RoleEnforcementPolicies, string]]::new()
            $toUpdate = [System.Collections.Generic.Dictionary[KeeperSecurity.Enterprise.RoleEnforcementPolicies, string]]::new()
            $toRemove = [System.Collections.Generic.List[KeeperSecurity.Enterprise.RoleEnforcementPolicies]]::new()

            foreach ($srcKvp in $srcEnforcements.GetEnumerator()) {
                $policy = $srcKvp.Key
                $srcVal = $srcKvp.Value
                $mcHas = $mcEnforcementDict.ContainsKey($policy)
                if (-not $mcHas) {
                    $toAdd[$policy] = $srcVal
                } else {
                    $mcVal = $mcEnforcementDict[$policy]
                    if ([string]::Compare($srcVal, $mcVal, [StringComparison]::OrdinalIgnoreCase) -ne 0) {
                        $toUpdate[$policy] = $srcVal
                    }
                }
            }
            foreach ($mcKvp in $mcEnforcementDict.GetEnumerator()) {
                if (-not $srcEnforcements.ContainsKey($mcKvp.Key)) {
                    $toRemove.Add($mcKvp.Key) | Out-Null
                }
            }

            if ($toRemove.Count -gt 0) {
                $rdMc.RoleEnforcementRemoveBatch($mcRole, $toRemove).GetAwaiter().GetResult() | Out-Null
            }
            if ($toAdd.Count -gt 0) {
                $rdMc.RoleEnforcementAddBatch($mcRole, $toAdd).GetAwaiter().GetResult() | Out-Null
            }
            if ($toUpdate.Count -gt 0) {
                $rdMc.RoleEnforcementUpdateBatch($mcRole, $toUpdate).GetAwaiter().GetResult() | Out-Null
            }
        }

        Write-Information "MC $($mc.EnterpriseId) ($($mc.EnterpriseName)): Roles are in sync."
    }
}
New-Alias -Name msp-copy-role -Value Copy-KeeperMCRole

$script:McUnlimitedSeatsValue = [int]::MaxValue

$script:MspPlanNames = @{
    1 = 'business'; 2 = 'businessPlus'; 10 = 'enterprise'; 11 = 'enterprisePlus'
}

$script:MspFilePlanNames = @{
    '100gb' = '100GB'; '1tb' = '1TB'; '10tb' = '10TB'
}

$script:MspAddonDisplayNames = @{
    'keeper_endpoint_privilege_manager' = 'KEPM'
    'remote_browser_isolation' = 'Remote Browser Isolation'
    'connection_manager' = 'Connection Manager'
    'enterprise_breach_watch' = 'Breach Watch'
    'compliance_report' = 'Compliance Report'
    'enterprise_audit_and_reporting' = 'Audit & Reporting'
    'msp_service_and_support' = 'MSP Service & Support'
    'secrets_manager' = 'Secrets Manager'
    'chat' = 'Chat'
}

function Script:Get-MspNodePath {
    param([object]$EnterpriseData, [long]$NodeId, [bool]$OmitRoot = $false)
    $parts = [System.Collections.Generic.List[string]]::new()
    $n = $null
    if (-not $EnterpriseData.TryGetNode($NodeId, [ref]$n)) {
        return ''
    }
    while ($n) {
        $name = if ($n.ParentNodeId -le 0) { $EnterpriseData.RootNode.DisplayName } else { $n.DisplayName }
        if ([string]::IsNullOrEmpty($name)) { $name = $n.Id.ToString() }
        $parts.Insert(0, $name)
        if ($n.ParentNodeId -le 0) { break }
        $next = $null
        if (-not $EnterpriseData.TryGetNode($n.ParentNodeId, [ref]$next)) { break }
        $n = $next
    }
    if ($OmitRoot -and $parts.Count -gt 1) { $parts.RemoveAt(0) }
    $parts -join ' / '
}

function Get-MspBillingReport {
    <#
    .Synopsis
    Generate MSP Consumption Billing Statement.
    .Parameter Month
    Report month as 1-12 (numeric) or YYYY-MM (e.g. 2022-02). If omitted, previous calendar month is used.
    .Parameter Year
    Report year (e.g. 2022). Used when Month is numeric only.
    .Parameter ShowDate
    Breakdown report by date.
    .Parameter ShowCompany
    Breakdown report by managed company.
    .Parameter Format
    Output format: table (default), json, or csv.
    .Parameter Output
    If supplied, save the report to the given file path.
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $false, Position = 0)]
        [object] $Month,
        [Parameter(Mandatory = $false, Position = 1)]
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

    $monthNum = $null
    if ($null -ne $Month) {
        if ($Month -is [string] -and $Month -match '^(\d{4})-(\d{2})$') {
        } elseif ($Month -is [int] -and $Month -ge 1 -and $Month -le 12) {
            $monthNum = $Month
        } else {
            $tryNum = 0
            if ([int]::TryParse([string]$Month, [ref]$tryNum) -and $tryNum -ge 1 -and $tryNum -le 12) { $monthNum = $tryNum }
            else { $Month = $null }
        }
    }

    if ($null -ne $Month -and $Month -is [string] -and $Month -match '^(\d{4})-(\d{2})$') {
        $apiYear = [int]$Matches[1]
        $m = [int]$Matches[2]
        if ($m -lt 1 -or $m -gt 12) {
            Write-Error "Month in YYYY-MM must be 01-12 (got $($Matches[2]))" -ErrorAction Stop
        }
        $apiMonth = $m - 1
    } elseif ($Year -ne 0 -or $null -ne $monthNum) {
        if ($Year -eq 0) { $Year = $dt.Year }
        $apiYear = $Year
        if ($null -ne $monthNum -and $monthNum -ge 1 -and $monthNum -le 12) {
            $apiMonth = $monthNum - 1
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
        foreach ($productId in $ds.Units.Keys) {
            $q = $ds.Units[$productId]
            if (-not $qd[$productId]) { $qd[$productId] = @(0, 0) }
            $qd[$productId][0] += $q
            $qd[$productId][1] += 1
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
        if ($productKey -ge 100 -and $productKey -lt 10000) { return [int]($productKey / 100) }
        if ($productKey -ge 10000) { return [int]($productKey / 10000) }
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
        if ($productKey -ge 100 -and $productKey -lt 10000) {
            $name = $filePlanMap[$cid]
            if ($name) { return $name }
            return "Storage #$cid"
        }
        if ($productKey -ge 10000) {
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
        'table' { $out = $table | Format-Table | Out-String -Width 8192 }
    }

    if ($Output) {
        if ($Format -eq 'table') {
            $tableStr = $table | Format-Table | Out-String -Width 8192
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

function Get-KeeperMspLegacyReport {
    <#
    .Synopsis
    Generate MSP legacy billing report.

    .Description
    Retrieves the MSP legacy license adjustment log from the Keeper server.
    Supports predefined date ranges or custom from/to dates.
    Results can be output as table, CSV, or JSON.

    .Parameter Range
    Pre-defined date range. Choices: today, yesterday, last_7_days, last_30_days,
    month_to_date, last_month, year_to_date, last_year. Default: last_30_days.

    .Parameter From
    Custom start date. ISO 8601 format (YYYY-MM-dd) or Unix timestamp.
    Both -From and -To must be specified together. Cannot be combined with -Range.

    .Parameter To
    Custom end date. ISO 8601 format (YYYY-MM-dd) or Unix timestamp.
    Both -From and -To must be specified together. Cannot be combined with -Range.

    .Parameter Format
    Output format: table (default), csv, json.

    .Parameter Output
    File path to save the report.

    .Example
    Get-KeeperMspLegacyReport
    Returns legacy billing log for the last 30 days.

    .Example
    Get-KeeperMspLegacyReport -Range last_7_days
    Returns legacy billing log for the last 7 days.

    .Example
    Get-KeeperMspLegacyReport -From "2025-01-01" -To "2025-06-30" -Format csv -Output "report.csv"
    Returns legacy billing log for a custom date range, saved as CSV.

    .Example
    Get-KeeperMspLegacyReport -From "2026-02-01" -To "2026-02-28"
    Returns legacy billing log for February 2026.
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $false)]
        [ValidateSet('today', 'yesterday', 'last_7_days', 'last_30_days', 'month_to_date', 'last_month', 'year_to_date', 'last_year')]
        [string] $Range = 'last_30_days',

        [Parameter(Mandatory = $false)]
        [string] $From,

        [Parameter(Mandatory = $false)]
        [string] $To,

        [Parameter(Mandatory = $false)]
        [ValidateSet('table', 'json', 'csv')]
        [string] $Format = 'table',

        [Parameter(Mandatory = $false)]
        [string] $Output
    )

    $hasFrom = [bool]$From
    $hasTo = [bool]$To
    $rangeExplicit = $PSBoundParameters.ContainsKey('Range')

    if (($hasFrom -or $hasTo) -and $rangeExplicit) {
        Write-Error "-Range cannot be combined with -From/-To. Use either -Range or -From/-To." -ErrorAction Stop
        return
    }

    if (($hasFrom -and -not $hasTo) -or ($hasTo -and -not $hasFrom)) {
        Write-Error "Both -From and -To must be specified for a custom date range." -ErrorAction Stop
        return
    }

    try {
        [Enterprise]$enterprise = getMspEnterprise
    }
    catch {
        Write-Error "Failed to load MSP enterprise context: $($_.Exception.Message)" -ErrorAction Stop
        return
    }
    $auth = $enterprise.loader.Auth

    function parseDateInput([string]$value, [string]$paramName) {
        $numeric = [long]0
        if ([long]::TryParse($value, [ref]$numeric)) {
            return [DateTimeOffset]::FromUnixTimeSeconds($numeric).LocalDateTime
        }
        $parsed = [DateTime]::MinValue
        if ([DateTime]::TryParseExact($value, 'yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$parsed)) {
            return $parsed
        }
        Write-Error "Cannot parse -${paramName} date: '$value'. Use YYYY-MM-dd or Unix timestamp." -ErrorAction Stop
        return $null
    }

    $fromDate = $null
    $toDate = $null

    if ($hasFrom -and $hasTo) {
        $fromDate = parseDateInput $From 'From'
        if ($null -eq $fromDate) { return }

        $toDate = parseDateInput $To 'To'
        if ($null -eq $toDate) { return }
        $toDate = $toDate.Date.AddDays(1).AddTicks(-1)
    } else {
        $now = Get-Date
        $todayStart = $now.Date
        $todayEnd = $now.Date.AddDays(1).AddTicks(-1)

        switch ($Range) {
            'today' {
                $fromDate = $todayStart
                $toDate = $todayEnd
            }
            'yesterday' {
                $fromDate = $todayStart.AddDays(-1)
                $toDate = $todayEnd.AddDays(-1)
            }
            'last_7_days' {
                $fromDate = $todayStart.AddDays(-7)
                $toDate = $todayEnd
            }
            'last_30_days' {
                $fromDate = $todayStart.AddDays(-30)
                $toDate = $todayEnd
            }
            'month_to_date' {
                $fromDate = [DateTime]::new($now.Year, $now.Month, 1)
                $toDate = $todayEnd
            }
            'last_month' {
                $lastMonth = $now.AddMonths(-1)
                $fromDate = [DateTime]::new($lastMonth.Year, $lastMonth.Month, 1)
                $lastDay = [DateTime]::DaysInMonth($lastMonth.Year, $lastMonth.Month)
                $toDate = [DateTime]::new($lastMonth.Year, $lastMonth.Month, $lastDay).AddDays(1).AddTicks(-1)
            }
            'year_to_date' {
                $fromDate = [DateTime]::new($now.Year, 1, 1)
                $toDate = $todayEnd
            }
            'last_year' {
                $fromDate = [DateTime]::new($now.Year - 1, 1, 1)
                $toDate = [DateTime]::new($now.Year - 1, 12, 31).AddDays(1).AddTicks(-1)
            }
        }
    }

    $fromTimestampMs = [long]([DateTimeOffset]::new($fromDate).ToUnixTimeMilliseconds())
    $toTimestampMs = [long]([DateTimeOffset]::new($toDate).ToUnixTimeMilliseconds())

    $rq = New-Object KeeperSecurity.Commands.GetMcLicenseAdjustmentLogCommand
    $rq.From = $fromTimestampMs
    $rq.To = $toTimestampMs

    try {
        $response = $auth.ExecuteAuthCommand($rq, [KeeperSecurity.Commands.GetMcLicenseAdjustmentLogResponse], $true).GetAwaiter().GetResult()
        $rs = [KeeperSecurity.Commands.GetMcLicenseAdjustmentLogResponse]$response
    } catch {
        Write-Error "Failed to retrieve MSP legacy report: $($_.Exception.Message)" -ErrorAction Stop
        return
    }

    if (-not $rs.Log -or $rs.Log.Count -eq 0) {
        Write-Host "No legacy billing log entries found."
        return
    }

    $table = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($log in $rs.Log) {
        $table.Add([PSCustomObject]@{
            'ID'                    = $log.Id
            'Time'                  = $log.Date
            'Company ID'            = $log.EnterpriseId
            'Company Name'          = $log.EnterpriseName
            'Status'                = $log.Status
            'Number Of Allocations' = $log.NewNumberOfSeats
            'Plan'                  = $log.NewProductType
            'Transaction Notes'     = $log.Note
            'Price Estimate'        = $log.Price
        })
    }

    $out = $null
    switch ($Format) {
        'json' { $out = $table | ConvertTo-Json -Depth 5 }
        'csv'  { $out = $table | ConvertTo-Csv -NoTypeInformation }
        'table' { $out = $table | Format-Table -AutoSize | Out-String -Width 8192 }
    }

    if ($Output) {
        try {
            Set-Content -Path $Output -Value $out -Encoding utf8
            Write-Host "Report saved to: $Output"
        } catch {
            Write-Error "Failed to save report to '$Output': $($_.Exception.Message)" -ErrorAction Stop
            return
        }
    } else {
        if ($Format -eq 'table') {
            $table | Format-Table -AutoSize
        } else {
            Write-Output $out
        }
    }
}
New-Alias -Name 'msp-legacy-report' -Value Get-KeeperMspLegacyReport

function findManagedCompany {
    Param (
        [string]$mc
    )
    $enterprise = getMspEnterprise
    $trimmed = $mc.Trim()
    $id = [long]0
    if ([long]::TryParse($trimmed, [ref]$id)) {
        $enterprise.mspData.ManagedCompanies | Where-Object { $_.EnterpriseId -eq $id } | Select-Object -First 1
    } else {
        $enterprise.mspData.ManagedCompanies | Where-Object { $_.EnterpriseName -eq $trimmed } | Select-Object -First 1
    }
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
