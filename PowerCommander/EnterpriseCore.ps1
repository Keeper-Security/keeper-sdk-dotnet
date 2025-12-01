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

        if ($enterprise.enterpriseData.EnterpriseLicense.licenseStatus.StartsWith("msp")) {
            $enterprise.ManagedCompanies = @{}
        }

        $Script:Context.Enterprise = $enterprise
        $Script:Context.ManagedCompanyId = 0
    }

    if ($Script:Context.ManagedCompanyId -gt 0) {
        if ($null -ne $enterprise.ManagedCompanies) {
            $enterpriseMc = $enterprise.ManagedCompanies[$Script:Context.ManagedCompanyId]
            if ($null -eq $enterpriseMc) {
                $authMc = New-Object KeeperSecurity.Enterprise.ManagedCompanyAuth
                $authMc.LoginToManagedCompany($Script:Context.Enterprise.loader, $Script:Context.ManagedCompanyId).GetAwaiter().GetResult() | Out-Null

                $enterpriseMc = New-Object Enterprise
                $enterpriseMc.enterpriseData = New-Object KeeperSecurity.Enterprise.EnterpriseData
                $enterpriseMc.roleData = New-Object KeeperSecurity.Enterprise.RoleData
        
                [KeeperSecurity.Enterprise.EnterpriseDataPlugin[]] $plugins = $enterpriseMc.enterpriseData, $enterpriseMc.roleData
        
                $enterpriseMc.loader = New-Object KeeperSecurity.Enterprise.EnterpriseLoader($authMc, $plugins)
                $enterpriseMc.loader.Load().GetAwaiter().GetResult() | Out-Null
                $enterprise.ManagedCompanies[$Script:Context.ManagedCompanyId] = $enterpriseMc
            }
            $enterprise = $enterpriseMc
        }
        else {
            $Script:Context.ManagedCompanyId = 0
        }
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

