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
        .Synopsis
    	Get a list of enterprise users
    #>
    [CmdletBinding()]
    Param (
        [Parameter()][string] $Email,
        [Parameter()][ValidateSet('table', 'json')][string] $Format = 'table',
        [Parameter()][string] $Output
    )

    $users = Get-EnterpriseUser
    if (-not $users) {
        Write-Warning "No enterprise users found."
        return @()
    }

    if ($Email) {
        $users = $users | Where-Object { ($_.Email -eq $Email) -or ($_.Id.ToString() -eq $Email) }
    }

    $result = @($users)
    if ($result.Count -eq 0 -and $Email) {
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
        if ($Output) {
            $result | Format-Table -AutoSize | Out-String -Width 8192 | Set-Content -Path $Output -Encoding utf8
            Write-Host "Results exported to: $Output" -ForegroundColor Green
        } else {
            return $result
        }
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
        .Synopsis
    	Get a list of enterprise teams
    #>
    [CmdletBinding()]
    Param (
        [Parameter()][string] $Name,
        [Parameter()][ValidateSet('table', 'json')][string] $Format = 'table',
        [Parameter()][string] $Output
    )

    $teams = Get-EnterpriseTeam
    if (-not $teams) {
        Write-Warning "No enterprise teams found."
        return @()
    }

    if ($Name) {
        $teams = $teams | Where-Object { ($_.Name -eq $Name) -or ($_.Uid -eq $Name) }
    }

    $result = @($teams)
    if ($result.Count -eq 0 -and $Name) {
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
        if ($Output) {
            $result | Format-Table -AutoSize | Out-String -Width 8192 | Set-Content -Path $Output -Encoding utf8
            Write-Host "Results exported to: $Output" -ForegroundColor Green
        } else {
            return $result
        }
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
        .Synopsis
    	Get a list of enterprise nodes
    #>
    [CmdletBinding()]
    Param (
        [Parameter()][string] $Name,
        [Parameter()][ValidateSet('table', 'json')][string] $Format = 'table',
        [Parameter()][string] $Output
    )

    $nodes = Get-EnterpriseNode
    if (-not $nodes) {
        Write-Warning "No enterprise nodes found."
        return @()
    }

    if ($Name) {
        $nodes = $nodes | Where-Object { ($_.DisplayName -eq $Name) -or ($_.Id.ToString() -eq $Name) }
    }

    $result = @($nodes)
    if ($result.Count -eq 0 -and $Name) {
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
        if ($Output) {
            $result | Format-Table -AutoSize | Out-String -Width 8192 | Set-Content -Path $Output -Encoding utf8
            Write-Host "Results exported to: $Output" -ForegroundColor Green
        } else {
            return $result
        }
    }
}
New-Alias -Name ken -Value Get-KeeperEnterpriseNode

