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
	    Managed Company ID or Name
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $false)][string] $Filter
    )

    [Enterprise]$enterprise = getMspEnterprise
    if ($Name) {
        $enterprise.mspData.ManagedCompanies | Where-Object { ($_.EnterpriseId -eq $Filter) -or ($_.EnterpriseName -like $Filter + '*') }
    }
    else {
        $enterprise.mspData.ManagedCompanies
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
            $parts = $addon -split ':'
            $addonOption = New-Object KeeperSecurity.Enterprise.ManagedCompanyAddonOptions
            $addonOption.Addon = $parts[0]
            if ($parts.Length -gt 1) {
                $addonOption.NumberOfSeats = $parts[1] -as [int]
            }
            $aons += $addonOption
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
    switch ($Storage) {
        '100GB' { $options.FilePlanType = [KeeperSecurity.Enterprise.ManagedCompanyConstants]::StoragePlan100GB }
        '1TB' { $options.FilePlanType = [KeeperSecurity.Enterprise.ManagedCompanyConstants]::StoragePlan1TB }
        '10TB' { $options.FilePlanType = [KeeperSecurity.Enterprise.ManagedCompanyConstants]::StoragePlan10TB }
    }
    if ($Addons) {
        $aons = @()
        foreach ($addon in $Addons) {
            $parts = $addon -split ':'
            $addonOption = New-Object KeeperSecurity.Enterprise.ManagedCompanyAddonOptions
            $addonOption.Addon = $parts[0]
            if ($parts.Length -gt 1) {
                $addonOption.NumberOfSeats = $parts[1] -as [int]
            }
            $aons += $addonOption
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
    else {
        $options.NodeId = $enterprise.enterpriseData.RootNode.Id
    }
    $enterprise.mspData.UpdateManagedCompany($mc.EnterpriseId, $options).GetAwaiter().GetResult()
}
New-Alias -Name kemc -Value Edit-KeeperManagedCompany
Register-ArgumentCompleter -CommandName Edit-KeeperManagedCompany -ParameterName Addons -ScriptBlock $Keeper_MspAddonName

class MspDailySnapshotAddon {
    [string]$Addon
    [int]$Units
}
class MspDailySnapshotRecord {
    [System.DateTime]$Date
    [int]$McEnterpriseId
    [int]$LicenseCount
    [string]$ProductPlan
    [string]$FilePlan
    [MspDailySnapshotAddon[]]$Addons
}

function Get-MspBillingReport {
    <#
    .Synopsis
    Runs MSP Billing Report
    .Parameter Month
    Report Month 1-12
    .Parameter Year
    Report Year 20xx
  #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $false)][int] $Month,
        [Parameter(Mandatory = $false)][int] $Year
    )

    $dt = Get-Date
    if (0 -eq $Year) {
        $Year = $dt.Year
    }
    if (0 -eq $Month) {
        $Month = $dt.Month - 1
        if ($Month -le 0) {
            $Year -= 1
            $Month = 12
        }
    }

    $auth = [KeeperSecurity.Authentication.IAuthentication] $auth = $Script:Context.Auth

    $url = [KeeperSecurity.Authentication.AuthExtensions]::GetBiUrl($auth, 'mapping/addons')
    $rq = New-Object BI.MappingAddonsRequest
    $rs = $auth.ExecuteAuthRest($url, $rq, [BI.MappingAddonsResponse]).GetAwaiter().GetResult()
    $filePlans = @{
        4 = '100GB'
        7 = '1TB'
        8 = '10TB'
    }
    foreach ($fp in $rs.FilePlans) {
        $filePlans[$fp.Id] = $fp.Name
    }
    $addons = @{}
    foreach ($aon in $rs.Addons) {
        $addons[$aon.Id] = $aon.Name
    }

    $url = [KeeperSecurity.Authentication.AuthExtensions]::GetBiUrl($auth, 'reporting/daily_snapshot')
    $rq = New-Object BI.ReportingDailySnapshotRequest
    $rq.Month = $Month
    $rq.Year = $Year

    $rs = $auth.ExecuteAuthRest($url, $rq, [BI.ReportingDailySnapshotResponse]).GetAwaiter().GetResult()
    foreach ($rec in $rs.Records) {
        $r = New-Object MspDailySnapshotRecord
        $r.Date = [KeeperSecurity.Utils.DateTimeOffsetExtensions]::FromUnixTimeMilliseconds($rec.date).Date
        $r.McEnterpriseId = $rec.mcEnterpriseId
        $r.LicenseCount = $rec.maxLicenseCount
        switch ($rec.MaxBasePlanId) {
            1 { $r.ProductPlan = 'business' }
            2 { $r.ProductPlan = 'businessPlus' }
            10 { $r.ProductPlan = 'enterprise' }
            11 { $r.ProductPlan = 'enterprisePlus' }
            default { $r.ProductPlan = "Plan #$($r.rec)" }
        }
        if ($rec.maxFilePlanTypeId) {
            $r.FilePlan = $filePlans[$rec.maxFilePlanTypeId]
            if (-not $r.FilePlan) {
                $r.FilePlan = "Storage Plan #$($rec.maxFilePlanTypeId)"
            }
        }

        foreach ($addon in $rec.addons) {
            if ($addon.maxAddonId) {
                $a = New-Object MspDailySnapshotAddon
                $a.Addon = $addons[$addon.maxAddonId]
                if (-not $a.Addon) {
                    $a.Addon = "Addon # $($addon.maxAddonId)"
                }
                $a.Units = $addon.units
                $r.Addons += $a
            }
        }
        $r
    }
}

function Script:Get-KeeperNodeName {
    Param (
        [long]$nodeId
    )
    $enterprise = getEnterprise
    [KeeperSecurity.Enterprise.EnterpriseNode]$node = $null
    if ($enterprise.enterpriseData.TryGetNode($nodeId, [ref]$node)) {
        if ($node.ParentNodeId -gt 0) {
            return $node.DisplayName
        }
        else {
            return $enterprise.loader.EnterpriseName
        }
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
