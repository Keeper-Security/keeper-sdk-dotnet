#requires -Version 5.0

Class Enterprise {
    [KeeperSecurity.Enterprise.EnterpriseLoader] $loader
    [KeeperSecurity.Enterprise.EnterpriseData] $enterpriseData
    [KeeperSecurity.Enterprise.RoleData] $roleData
    [KeeperSecurity.Enterprise.ManagedCompanyData] $mspData
}

class KeeperContext {
	[KeeperSecurity.Authentication.IAuth] $Auth = $null
	[KeeperSecurity.Vault.VaultOnline] $Vault = $null
	[string] $CurrentFolder = ''
	[Enterprise] $Enterprise = $null
    $AvailableTeams = $null
    $AvailableUsers = $null
}

New-Variable -Name Context -Option Constant -Scope 'Script' -Value (New-Object KeeperContext)

Export-ModuleMember -Function  Connect-Keeper, Sync-Keeper, Disconnect-Keeper
Export-ModuleMember -Alias kc, ks, kq

Export-ModuleMember -Function Get-KeeperLocation, Set-KeeperLocation, Get-KeeperChildItems, 
							  Get-KeeperObject
Export-ModuleMember -Alias kpwd, kcd, kdir, ko

Export-ModuleMember -Function Get-KeeperRecords, Copy-KeeperToClipboard, Show-TwoFactorCode,
                              Add-KeeperRecord, Remove-KeeperRecord, Move-RecordToFolder,
                              Get-KeeperPasswordVisible, Set-KeeperPasswordVisible, Get-KeeperRecordTypes
Export-ModuleMember -Alias kr, kcc, 2fa, kadd, kdel, kmv, krti

Export-ModuleMember -Function Get-KeeperSharedFolders
Export-ModuleMember -Alias ksf

Export-ModuleMember -Function Add-KeeperFolder, Remove-KeeperFolder
Export-ModuleMember -Alias kmkdir, krmdir

Export-ModuleMember -Function Sync-KeeperEnterprise, Get-KeeperEnterpriseUsers, Get-KeeperEnterpriseTeams, 
                              Get-KeeperEnterpriseNodes, Get-KeeperNodeName, Lock-KeeperEnterpriseUser, 
                              Unlock-KeeperEnterpriseUser, Move-KeeperEnterpriseUser, Remove-KeeperEnterpriseUser,
                              Get-KeeperEnterpriseTeamUsers
Export-ModuleMember -Alias ked, keu, ket, ketu, ken, lock-user, unlock-user, transfer-user, delete-user

Export-ModuleMember -Function Get-KeeperManagedCompanies, New-KeeperManagedCompany, 
                              Remove-KeeperManagedCompany, Edit-KeeperManagedCompany
Export-ModuleMember -Alias kmc, kamc, krmc, kemc

Export-ModuleMember -Function Show-KeeperRecordShares, Grant-KeeperRecordAccess, Revoke-KeeperRecordAccess, 
                              Grant-KeeperSharedFolderAccess, Revoke-KeeperSharedFolderAccess, Get-KeeperAvailableTeams
Export-ModuleMember -Alias kshrsh, kshr, kushr, kshf, kushf, kat

Export-ModuleMember -Function Get-KeeperSecretManagerApps, New-KeeperSecretManagerApp, Grant-KeeperSecretManagerFolderAccess,
                              Revoke-KeeperSecretManagerFolderAccess, Add-KeeperSecretManagerClient, Remove-KeeperSecretManagerClient
Export-ModuleMember -Alias ksm, ksm-create, ksm-share, ksm-unshare, ksm-addclient, ksm-rmclient


# function Test-Keeper {
#     [CmdletBinding()]
#     Param (
#         [Parameter(Mandatory = $true)]$Path
#     )
#     [KeeperSecurity.Vault.VaultOnline]$vault = getVault

#     [KeeperSecurity.Vault.FolderNode]$folder = $null
# 	if (!$vault.TryGetFolder($Script:Context.CurrentFolder, [ref]$folder)) {
# 		$folder = $vault.RootFolder
# 	}

#     $comps = splitKeeperPath $Path
#     parseKeeperPath $comps $vault $folder
# }
# Export-ModuleMember -Function Test-Keeper