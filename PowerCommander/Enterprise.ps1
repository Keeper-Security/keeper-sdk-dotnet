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
        $enterprise.mspData = New-Object KeeperSecurity.Enterprise.ManagedCompanyData

        [KeeperSecurity.Enterprise.EnterpriseDataPlugin[]] $plugins = $enterprise.enterpriseData, $enterprise.mspData

        $enterprise.loader = New-Object KeeperSecurity.Enterprise.EnterpriseLoader($auth, $plugins, $null)
        $enterprise.loader.Load().GetAwaiter().GetResult() | Out-Null

        $Script:Context.Enterprise =  $enterprise
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
    

function Get-KeeperEnterpriseUsers {
    <#
        .Synopsis
    	Get the list of enterprise users
    #>
    [CmdletBinding()]

    [Enterprise]$enterprise = getEnterprise
    return $enterprise.enterpriseData.Users
}
New-Alias -Name keu -Value Get-KeeperEnterpriseUsers


$Keeper_ActiveUserCompleter = {
	param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)

	$result = @()
    [Enterprise]$enterprise = $Script:Context.Enterprise
    if (-not $enterprise) {
        return $null
    }
    if ($wordToComplete) {
        $to_complete = '*' + $wordToComplete + '*'
    } else {
        $to_complete = '*'
    }
    foreach($user in $enterprise.enterpriseData.Users) {
        if ($user.UserStatus -in @([KeeperSecurity.Enterprise.UserStatus]::Active,[KeeperSecurity.Enterprise.UserStatus]::Disabled,[KeeperSecurity.Enterprise.UserStatus]::Blocked)) {
            if ($user.Email -like $to_complete) {
                $result += $user.Email
            }
        }
    }
	if ($result.Count -gt 0) {
		return $result
	} else {
		return $null
	}
}

function Lock-KeeperEnterpriseUser {
    <#
        .Synopsis
    	Locks Enterprise Users
    	
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
        Write-Host "User `"$($saved.Email)`" was locked"
    }
}
Register-ArgumentCompleter -CommandName Lock-KeeperEnterpriseUser -ParameterName User -ScriptBlock $Keeper_ActiveUserCompleter
New-Alias -Name keul -Value Lock-KeeperEnterpriseUser

$Keeper_LockedUserCompleter = {
	param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)

	$result = @()
    [Enterprise]$enterprise = $Script:Context.Enterprise
    if (-not $enterprise) {
        return $null
    }
    if ($wordToComplete) {
        $to_complete = '*' + $wordToComplete + '*'
    } else {
        $to_complete = '*'
    }
    foreach($user in $enterprise.enterpriseData.Users) {
        if ($user.UserStatus -eq [KeeperSecurity.Enterprise.UserStatus]::Locked) {
            if ($user.Email -like $to_complete) {
                $result += $user.Email
            }
        }
    }
	if ($result.Count -gt 0) {
		return $result
	} else {
		return $null
	}
}

function Unlock-KeeperEnterpriseUser {
    <#
        .Synopsis
    	Unlocks Enterprise Users
    	
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
        Write-Host "User `"$($saved.Email)`" was unlocked"
    }
}
Register-ArgumentCompleter -CommandName Unlock-KeeperEnterpriseUser -ParameterName User -ScriptBlock $Keeper_LockedUserCompleter
New-Alias -Name keuu -Value Unlock-KeeperEnterpriseUser


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
    Write-Host "`"${user}`" cannot be resolved as enterprise user"
}

function Get-KeeperEnterpriseNodes {
    <#
        .Synopsis
    	Get the list of enterprise nodes
    #>
    [CmdletBinding()]

    [Enterprise]$enterprise = getEnterprise
    return $enterprise.enterpriseData.Nodes
}
New-Alias -Name ken -Value Get-KeeperEnterpriseNodes

function Get-KeeperMspLicenses {
    <#
        .Synopsis
    	Get the list of MSP licenses
    #>
    [CmdletBinding()]
    [Enterprise]$enterprise = getMspEnterprise
    $enterprise.enterpriseData.EnterpriseLicense.MspPool
}
New-Alias -Name kmspl -Value Get-KeeperMspLicenses

function Get-KeeperManagedCompanies {
    <#
        .Synopsis
    	Get the list of managed companies
    	.Parameter Filter
	    Managed Company ID or Name
    #>
    [CmdletBinding()]
	Param (
		[Parameter(Mandatory=$false)][string] $Filter
	)

    [Enterprise]$enterprise = getMspEnterprise
    if ($Name) {
        $enterprise.mspData.ManagedCompanies | Where-Object { ($_.EnterpriseId -eq $Filter) -or ($_.EnterpriseName -like $Filter + '*')}
    } else {
        $enterprise.mspData.ManagedCompanies
    }
}
New-Alias -Name kmc -Value Get-KeeperManagedCompanies

function New-KeeperManagedCompany {
    <#
        .Synopsis
    	Adds new Managed Company
    	.Parameter Name
	    Managed Company Name
    	.Parameter PlanId
	    Managed Company Plan
    	.Parameter Allocated
	    Number of Seats Allocated
    #>
    [CmdletBinding()]
	Param (
		[Parameter(Mandatory=$true)][string] $Name,
		[Parameter(Mandatory=$true)][ValidateSet('business', 'businessPlus', 'enterprise', 'enterprisePlus')][string] $PlanId,
		[Parameter(Mandatory=$true)][int] $Allocated,
		[Parameter(Mandatory=$false)][string] $Node
	)

    [Enterprise]$enterprise = getMspEnterprise

    $options = New-Object KeeperSecurity.Enterprise.ManagedCompanyOptions
    $options.Name = $Name
    $options.ProductId = $PlanId
    $options.NumberOfSeats = $Allocated
    if ($Node) {
        $n = findEnterpriseNode $Node
        if ($n) {
            $options.NodeId = $n.Id
        } else {
            Write-Error -Message "Node ${Node} not found" -ErrorAction Stop
        }
    } else {
        $options.NodeId = $enterprise.enterpriseData.RootNode.Id
    }

    return $enterprise.mspData.CreateManagedCompany($options).GetAwaiter().GetResult()
}
New-Alias -Name kamc -Value New-KeeperManagedCompany

function Remove-KeeperManagedCompany {
    <#
        .Synopsis
    	Removes Managed Company
    	.Parameter Name
	    Managed Company Id or Name
    #>
    [CmdletBinding()]
	Param (
		[Parameter(Position = 0, Mandatory=$true)][string] $Name
	)

    [Enterprise]$enterprise = getMspEnterprise
    $mc = findManagedCompany $Name
    if (-not $mc) {
        Write-Error -Message "Managed Company ${Name} not found" -ErrorAction Stop
    }

    $enterprise.mspData.RemoveManagedCompany($mc.EnterpriseId).GetAwaiter().GetResult() | Out-Null
    Write-Information -MessageData "Removed Managed Company `"${mc.EnterpriseName}`" ID: ${mc.EnterpriseId}"
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
    	.Parameter Allocated
	    Number of Seats Allocated
    	.Parameter Id
	    Managed Company Name or Id

    #>
    [CmdletBinding()]
	Param (
		[Parameter(Mandatory=$false)][string] $Name,
		[Parameter(Mandatory=$false)][ValidateSet('business', 'businessPlus', 'enterprise', 'enterprisePlus')][string] $PlanId,
		[Parameter(Mandatory=$false)][int] $Allocated,
		[Parameter(Mandatory=$false)][string] $Node,
		[Parameter(Position = 0, Mandatory=$true)][string] $Id
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
    if ($Allocated) {
        $options.NumberOfSeats = $Allocated
    }
    if ($Node) {
        $n = findEnterpriseNode $Node
        if ($n) {
            $options.NodeId = $n.Id
        } else {
            Write-Error -Message "Node ${Node} not found" -ErrorAction Stop
        }
    } else {
        $options.NodeId = $enterprise.enterpriseData.RootNode.Id
    }
    $enterprise.mspData.UpdateManagedCompany($mc.EnterpriseId, $options).GetAwaiter().GetResult()
}
New-Alias -Name kemc -Value Edit-KeeperManagedCompany

function Script:Get-KeeperNodeName {
	Param (
		[long]$nodeId
	)
    $enterprise = getEnterprise
    [KeeperSecurity.Enterprise.EnterpriseNode]$node = $null
    if ($enterprise.enterpriseData.TryGetNode($nodeId, [ref]$node)) {
        if ($node.ParentNodeId -gt 0) {
            return $node.DisplayName
        } else {
            return $enterprise.loader.EnterpriseName
        }
    }
}

function findManagedCompany {
	Param (
		[string]$mc
	)
    $enterprise = getMspEnterprise
    $enterprise.mspData.ManagedCompanies | Where-Object { ($_.EnterpriseId -eq $mc) -or ($_.EnterpriseName -eq $mc)} | Select-Object -First 1
}

function findEnterpriseNode {
	Param (
		[string]$node
	)
    $enterprise = getEnterprise
    if ($node -eq $enterprise.loader.EnterpriseName) {
        return $enterprise.enterpriseData.RootNode
    }
    $enterprise.enterpriseData.Nodes | Where-Object { ($_.Id -eq $node) -or ($_.DisplayName -eq $node)} | Select-Object -First 1
}

function getMspEnterprise {
    [Enterprise]$enterprise = getEnterprise
    if ($enterprise.enterpriseData.EnterpriseLicense -and $enterprise.enterpriseData.EnterpriseLicense.LicenseStatus -like "msp*") {
        return $enterprise
    } 
    Write-Error -Message "Not a MSP (Managed Service Provider)" -ErrorAction Stop
}
