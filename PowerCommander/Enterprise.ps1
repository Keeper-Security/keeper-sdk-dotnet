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
        $enterprise.mspData = New-Object KeeperSecurity.Enterprise.ManagedCompanyData

        [KeeperSecurity.Enterprise.EnterpriseDataPlugin[]] $plugins = $enterprise.enterpriseData, $enterprise.roleData, $enterprise.mspData

        $enterprise.loader = New-Object KeeperSecurity.Enterprise.EnterpriseLoader($auth, $plugins)
        $enterprise.loader.Load().GetAwaiter().GetResult() | Out-Null

        $Script:Context.Enterprise = $enterprise
    }

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


function Get-KeeperEnterpriseUser {
    <#
        .Synopsis
    	Get a list of enterprise users
    #>
    [CmdletBinding()]

    [Enterprise]$enterprise = getEnterprise
    return $enterprise.enterpriseData.Users
}
New-Alias -Name keu -Value Get-KeeperEnterpriseUser

function Get-KeeperEnterpriseTeam {
    <#
        .Synopsis
    	Get a list of enterprise teams
    #>
    [CmdletBinding()]

    [Enterprise]$enterprise = getEnterprise
    return $enterprise.enterpriseData.Teams
}
New-Alias -Name ket -Value Get-KeeperEnterpriseTeam

$Keeper_TeamNameCompleter = {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)

    $result = @()
    [Enterprise]$enterprise = $Script:Context.Enterprise
    if (-not $enterprise) {
        return $null
    }
    if ($wordToComplete) {
        $to_complete = $wordToComplete + '*'
    }
    else {
        $to_complete = '*'
    }
    foreach ($team in $enterprise.enterpriseData.Teams) {
        if ($team.Name -like $to_complete) {
            $teamName = $team.Name
            if ($teamName -match '[\s'']') {
                $teamName = $teamName -replace '''', ''''''
                $teamName = "'${teamName}'"
            }

            $result += $teamName
        }
    }
    if ($result.Count -gt 0) {
        return $result
    }
    else {
        return $null
    }
}

function Get-KeeperEnterpriseTeamUser {
    <#
        .Synopsis
    	Get a list of enterprise users for team
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $true)]$Team
    )

    [Enterprise]$enterprise = getEnterprise
    $enterpriseData = $enterprise.enterpriseData
    $uid = $null

    if ($Team -is [String]) {
        $uids = Get-KeeperEnterpriseTeam | Where-Object { $_.Uid -ceq $Team -or $_.Name -ieq $Team } | Select-Object -Property Uid
        if ($uids.Length -gt 1) {
            Write-Error -Message "Team name `"$Team`" is not unique. Use Team UID" -ErrorAction Stop
        }

        if ($null -ne $uids.Uid) {
            $uid = $uids.Uid
        }
    }
    elseif ($null -ne $Team.Uid) {
        $uid = $Team.Uid
    }
    if ($uid) {
        $team = $null
        if ($enterpriseData.TryGetTeam($uid, [ref]$team)) {
            foreach ($userId in $enterpriseData.GetUsersForTeam($uid)) {
                $user = $null
                foreach ($userId in $enterpriseData.TryGetUserById($userId, [ref]$user)) {
                    $user
                }
            }
        }
        else {
            Write-Error -Message "Team `"$uid`" not found" -ErrorAction Stop
        }
    }
    else {
        Write-Error -Message "Team `"$Team`" not found" -ErrorAction Stop
    }
}
New-Alias -Name ketu -Value Get-KeeperEnterpriseTeamUser
Register-ArgumentCompleter -CommandName Get-KeeperEnterpriseTeamUser -ParameterName Team -ScriptBlock $Keeper_TeamNameCompleter

$Keeper_ActiveUserCompleter = {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)

    $result = @()
    [Enterprise]$enterprise = $Script:Context.Enterprise
    if (-not $enterprise) {
        return $null
    }
    if ($wordToComplete) {
        $to_complete = '*' + $wordToComplete + '*'
    }
    else {
        $to_complete = '*'
    }
    foreach ($user in $enterprise.enterpriseData.Users) {
        if ($user.UserStatus -in @([KeeperSecurity.Enterprise.UserStatus]::Active, [KeeperSecurity.Enterprise.UserStatus]::Disabled, [KeeperSecurity.Enterprise.UserStatus]::Blocked)) {
            if ($user.Email -like $to_complete) {
                $result += $user.Email
            }
        }
    }
    if ($result.Count -gt 0) {
        return $result
    }
    else {
        return $null
    }
}

function Lock-KeeperEnterpriseUser {
    <#
        .Synopsis
    	Locks Enterprise User

        .Parameter User
	    User email, enterprise Id, or instance.
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $true)]$User
    )

    [Enterprise]$enterprise = getEnterprise
    $userObject = resolveUser $enterprise.enterpriseData $User
    if ($userObject) {
        $saved = $enterprise.enterpriseData.SetUserLocked($userObject, $true).GetAwaiter().GetResult()
        if ($saved) {
            Write-Output "User `"$($saved.Email)`" was locked"
        }
    }
}
Register-ArgumentCompleter -CommandName Lock-KeeperEnterpriseUser -ParameterName User -ScriptBlock $Keeper_ActiveUserCompleter
New-Alias -Name lock-user -Value Lock-KeeperEnterpriseUser

$Keeper_LockedUserCompleter = {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)

    $result = @()
    [Enterprise]$enterprise = $Script:Context.Enterprise
    if (-not $enterprise) {
        return $null
    }
    if ($wordToComplete) {
        $to_complete = '*' + $wordToComplete + '*'
    }
    else {
        $to_complete = '*'
    }
    foreach ($user in $enterprise.enterpriseData.Users) {
        if ($user.UserStatus -eq [KeeperSecurity.Enterprise.UserStatus]::Locked) {
            if ($user.Email -like $to_complete) {
                $result += $user.Email
            }
        }
    }
    if ($result.Count -gt 0) {
        return $result
    }
    else {
        return $null
    }
}

function Unlock-KeeperEnterpriseUser {
    <#
        .Synopsis
    	Unlocks Enterprise User

        .Parameter User
	    User email, enterprise Id, or instance.
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $true)]$User
    )

    [Enterprise]$enterprise = getEnterprise
    $userObject = resolveUser $enterprise.enterpriseData $User
    if ($userObject) {
        $saved = $enterprise.enterpriseData.SetUserLocked($userObject, $false).GetAwaiter().GetResult()
        if ($saved) {
            Write-Output "User `"$($saved.Email)`" was unlocked"
        }
    }
}
Register-ArgumentCompleter -CommandName Unlock-KeeperEnterpriseUser -ParameterName User -ScriptBlock $Keeper_LockedUserCompleter
New-Alias -Name unlock-user -Value Unlock-KeeperEnterpriseUser

$Keeper_EnterpriseUserCompleter = {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)

    $result = @()
    [Enterprise]$enterprise = $Script:Context.Enterprise
    if (-not $enterprise) {
        return $null
    }
    if ($wordToComplete) {
        $to_complete = '*' + $wordToComplete + '*'
    }
    else {
        $to_complete = '*'
    }
    foreach ($user in $enterprise.enterpriseData.Users) {
        if ($user.Email -like $to_complete) {
            $result += $user.Email
        }
    }
    if ($result.Count -gt 0) {
        return $result
    }
    else {
        return $null
    }
}

function Move-KeeperEnterpriseUser {
    <#
        .Synopsis
    	Transfers enterprise user account to another user

        .Parameter FromUser
	    email or user ID to transfer vault from user

        .Parameter TargetUser
	    email or user ID to transfer vault to user
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $true)]$FromUser,
        [Parameter(Position = 1, Mandatory = $true)]$TargetUser,
        [Switch] $Force
    )

    [Enterprise]$enterprise = getEnterprise

    $fromUserObject = resolveUser $enterprise.enterpriseData $FromUser
    if (-not $fromUserObject) {
        return
    }
    $targetUserObject = resolveUser $enterprise.enterpriseData $TargetUser
    if (-not $targetUserObject) {
        return
    }
    if (-not $Force.IsPresent) {
        Write-Output "This action cannot be undone.`n"
        $answer = Read-Host -Prompt "Do you want to proceed with transferring $($fromUserObject.Email) account (Yes/No)? > "
        if ($answer -ne 'yes' -and $answer -ne 'y') {
            return
        }
    }
    $transferResult = $enterprise.enterpriseData.TransferUserAccount($enterprise.roleData, $fromUserObject, $targetUserObject).GetAwaiter().GetResult()
    if ($transferResult) {
        Write-Information "Successfully Transfered:"
        Write-Information "        Records: $($transferResult.RecordsTransfered)"
        Write-Information " Shared Folders: $($transferResult.SharedFoldersTransfered)"
        Write-Information "           Team: $($transferResult.TeamsTransfered)"
        if ($transferResult.RecordsCorrupted -gt 0 -or $transferResult.SharedFoldersCorrupted -gt 0 -or $transferResult.TeamsCorrupted -gt 0) {
            Write-Information "Failed to Transfer:"
            if ($transferResult.RecordsCorrupted -gt 0) {
                Write-Information "        Records: $($transferResult.RecordsCorrupted)"
            }
            if ($transferResult.SharedFoldersCorrupted -gt 0) {
                Write-Information " Shared Folders: $($transferResult.SharedFoldersCorrupted)"
            }
            if ($transferResult.TeamsCorrupted -gt 0) {
                Write-Information "           Team: $($transferResult.TeamsCorrupted)"
            }
        }
    }
}
Register-ArgumentCompleter -CommandName Move-KeeperEnterpriseUser -ParameterName FromUser -ScriptBlock $Keeper_LockedUserCompleter
Register-ArgumentCompleter -CommandName Move-KeeperEnterpriseUser -ParameterName TargetUser -ScriptBlock $Keeper_ActiveUserCompleter
New-Alias -Name transfer-user -Value Move-KeeperEnterpriseUser

function Remove-KeeperEnterpriseUser {
    <#
        .Synopsis
    	Removes Enterprise User

        .Parameter User
	    User email, enterprise Id, or instance.
    #>
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact = 'High')]
    Param (
        [Parameter(Position = 0, Mandatory = $true)]$User,
        [Switch] $Force
    )

    [Enterprise]$enterprise = getEnterprise
    $userObject = resolveUser $enterprise.enterpriseData $User
    if ($userObject) {
        if (-not $Force.IsPresent) {
            Write-Output  "`nDeleting a user will also delete any records owned and shared by this user."
            "Before you delete this user, we strongly recommend you lock their account"
            "and transfer any important records to other user.`n"
            "This action cannot be undone."

            if ($PSCmdlet.ShouldProcess($userObject.Email, "Removing Enterprise User")) {
                $enterprise.enterpriseData.DeleteUser($userObject).GetAwaiter().GetResult() | Out-Null
                Write-Output "User $($userObject.Email) has been deleted"
            }
        }
    }
}
Register-ArgumentCompleter -CommandName Remove-KeeperEnterpriseUser -ParameterName User -ScriptBlock $Keeper_EnterpriseUserCompleter
New-Alias -Name delete-user -Value Remove-KeeperEnterpriseUser

function resolveUser {
    Param (
        $enterpriseData,
        $user
    )
    [KeeperSecurity.Enterprise.EnterpriseUser] $u = $null

    if ($user -is [long]) {
        if ($enterpriseData.TryGetUserById($user, [ref]$u)) {
            return $u
        }
    }
    elseif ($user -is [string]) {
        if ($enterpriseData.TryGetUserByEmail($user, [ref]$u)) {
            return $u
        }
    }
    elseif ($user -is [KeeperSecurity.Enterprise.EnterpriseUser]) {
        if ($enterpriseData.TryGetUserById($user.Id, [ref]$u)) {
            return $u
        }
    }
    Write-Output "`"${user}`" cannot be resolved as enterprise user"
}

function Get-KeeperEnterpriseNode {
    <#
        .Synopsis
    	Get a list of enterprise nodes
    #>
    [CmdletBinding()]

    [Enterprise]$enterprise = getEnterprise
    return $enterprise.enterpriseData.Nodes
}
New-Alias -Name ken -Value Get-KeeperEnterpriseNode

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
    [Enterprise]$enterprise = getEnterprise
    if ($enterprise.enterpriseData.EnterpriseLicense -and $enterprise.enterpriseData.EnterpriseLicense.LicenseStatus -like "msp*") {
        return $enterprise
    }
    Write-Error -Message "Not a MSP (Managed Service Provider)" -ErrorAction Stop
}
