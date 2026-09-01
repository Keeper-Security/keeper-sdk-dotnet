#requires -Version 5.1

Class Enterprise {
    [KeeperSecurity.Enterprise.EnterpriseLoader] $loader
    [KeeperSecurity.Enterprise.EnterpriseData] $enterpriseData
    [KeeperSecurity.Enterprise.RoleData] $roleData
    [KeeperSecurity.Enterprise.QueuedTeamData] $queuedTeamData
    [KeeperSecurity.Enterprise.ManagedCompanyData] $mspData
    [KeeperSecurity.Enterprise.DeviceApprovalData] $deviceApproval
    [KeeperSecurity.Enterprise.UserAliasData] $userAliasData
    [hashtable] $ManagedCompanies = $null
}

Class EnterpriseTeamTarget {
    [KeeperSecurity.Enterprise.EnterpriseTeam]$Team
    [KeeperSecurity.Enterprise.EnterpriseQueuedTeam]$QueuedTeam
    [string]$Uid
    [string]$Name

    static [EnterpriseTeamTarget] FromActiveTeam([KeeperSecurity.Enterprise.EnterpriseTeam]$team) {
        $target = [EnterpriseTeamTarget]::new()
        $target.Team = $team
        $target.Uid = $team.Uid
        $target.Name = $team.Name
        return $target
    }

    static [EnterpriseTeamTarget] FromQueuedTeam([KeeperSecurity.Enterprise.EnterpriseQueuedTeam]$queuedTeam) {
        $target = [EnterpriseTeamTarget]::new()
        $target.QueuedTeam = $queuedTeam
        $target.Uid = $queuedTeam.Uid
        $target.Name = $queuedTeam.Name
        return $target
    }
}

Class EnterpriseTeamMembershipRequest {
    [Enterprise]$Enterprise
    [KeeperSecurity.Enterprise.EnterpriseUser]$User
    [EnterpriseTeamTarget]$TeamTarget
    [string]$HideSharedFolders
}

class KeeperContext {
    [KeeperSecurity.Authentication.IAuth] $Auth = $null
    [KeeperSecurity.Vault.VaultOnline] $Vault = $null
    [string] $CurrentFolder = ''
    [Enterprise] $Enterprise = $null
    [Int32] $ManagedCompanyId = 0
    $AvailableTeams = $null
    $AvailableUsers = $null
}

New-Variable -Name Context -Option Constant -Scope 'Script' -Value (New-Object KeeperContext)

# Import-Module -Force redefines the Enterprise class; a cached instance from the prior load
# is a different type identity and breaks [Enterprise] parameter binding.
if ($null -ne $Script:Context.Enterprise -and -not ($Script:Context.Enterprise -is [Enterprise])) {
    $Script:Context.Enterprise = $null
    $Script:Context.ManagedCompanyId = 0
}

Export-ModuleMember -Function  Connect-Keeper, Sync-Keeper, Disconnect-Keeper, Get-KeeperInformation, 
Get-KeeperDeviceSettings, Set-KeeperDeviceSettings
Export-ModuleMember -Alias kc, ks, kq, kwhoami, this-device

Export-ModuleMember -Function Get-KeeperLocation, Set-KeeperLocation, Get-KeeperChildItem,
Get-KeeperObject
Export-ModuleMember -Alias kpwd, kcd, kdir, ko

Export-ModuleMember -Function Get-KeeperRecord, Copy-KeeperToClipboard, Show-TwoFactorCode,
Add-KeeperRecord, Remove-KeeperRecord, Move-RecordToFolder,Get-KeeperPasswordVisible, 
Set-KeeperPasswordVisible, Get-KeeperRecordType, New-KeeperRecordType, Edit-KeeperRecordType, 
Remove-KeeperRecordType, Import-KeeperRecordTypes,Export-KeeperRecordTypes, Get-KeeperRecordPassword, 
Get-KeeperPasswordReport, Find-KeeperDuplicateRecords, Get-KeeperRecordHistory
Export-ModuleMember -Alias kr, kcc, 2fa, kadd, kdel, kmv, krti, find-duplicates, krh

Export-ModuleMember -Function Get-KeeperSharedFolder,Get-KeeperSharedFolderDetailsSkipSync, 
Get-KeeperSharedFolderRecordUidsSkipSync, Get-KeeperSharedFolderRecordsSkipSync, Get-KeeperRecordDetailsByUidSkipSync,
Get-KeeperAvailableTeamsSkipSync, Get-KeeperTeamUidSkipSync, Grant-KeeperSharedFolderUserSkipSync, 
Revoke-KeeperSharedFolderUserSkipSync, Grant-KeeperSharedFolderTeamSkipSync, Revoke-KeeperSharedFolderTeamSkipSync

Export-ModuleMember -Alias ksf

Export-ModuleMember -Function Add-KeeperFolder, Edit-KeeperFolder, Remove-KeeperFolder, 
Get-KeeperFolder,Get-KeeperFolders
Export-ModuleMember -Alias kmkdir, krmdir, kgetfolder, kfolders

Export-ModuleMember -Function Get-KeeperNodeName, Get-KeeperNodePath, Get-KeeperRoleName

Export-ModuleMember -Function Sync-KeeperEnterprise, Get-KeeperEnterpriseUser, Get-KeeperEnterpriseTeam, Get-KeeperEnterpriseNode,
Get-KeeperEnterpriseInfoTree, Get-KeeperEnterpriseInfoNode, Get-KeeperEnterpriseInfoUser,
Get-KeeperEnterpriseInfoTeam, Get-KeeperEnterpriseInfoRole, Get-KeeperEnterpriseInfoManagedCompany,
Get-KeeperAuditReport, Get-KeeperUserReport, Export-KeeperAuditLog, Get-KeeperAuditAlert

Export-ModuleMember -Function Add-KeeperEnterpriseUser, Lock-KeeperEnterpriseUser, Unlock-KeeperEnterpriseUser, 
Move-KeeperEnterpriseUser, Remove-KeeperEnterpriseUser, Invoke-ResendKeeperEnterpriseInvite, 
Set-KeeperEnterpriseUserMasterPasswordExpire, Add-KeeperEnterpriseUserAlias, Remove-KeeperEnterpriseUserAlias,
Get-KeeperEnterpriseUserTeam,
Update-KeeperEnterpriseTeamUser, Update-KeeperEnterpriseUser

Export-ModuleMember -Function Get-PendingKeeperDeviceApproval, Approve-KeeperDevice, Deny-KeeperDevice

Export-ModuleMember -Function Get-KeeperEnterpriseRole, Get-KeeperEnterpriseRoleUsers, Get-KeeperEnterpriseRoleTeams,
Get-KeeperEnterpriseAdminRole, Set-KeeperEnterpriseRole, Grant-KeeperEnterpriseRoleToUser, Revoke-KeeperEnterpriseRoleFromUser,
Grant-KeeperEnterpriseRoleToTeam, Revoke-KeeperEnterpriseRoleFromTeam, New-KeeperEnterpriseRole, Remove-KeeperEnterpriseRole,
Add-KeeperEnterpriseRoleManagedNode, Update-KeeperEnterpriseRoleManagedNode, Remove-KeeperEnterpriseRoleManagedNode,
Add-KeeperEnterpriseRolePrivilege, Remove-KeeperEnterpriseRolePrivilege, Copy-KeeperEnterpriseRole,
Add-KeeperEnterpriseRoleEnforcement, Update-KeeperEnterpriseRoleEnforcement, Remove-KeeperEnterpriseRoleEnforcement


Export-ModuleMember -Function New-KeeperEnterpriseTeam, Update-KeeperEnterpriseTeam, Remove-KeeperEnterpriseTeam,
Get-KeeperEnterpriseTeamUser, Add-KeeperEnterpriseTeamMember, Remove-KeeperEnterpriseTeamMember,
Get-KeeperEnterpriseTeamRole,
Get-KeeperEnterpriseTeams

Export-ModuleMember -Function New-KeeperEnterpriseNode, Edit-KeeperEnterpriseNode, Remove-KeeperEnterpriseNode, 
Set-KeeperEnterpriseNodeCustomInvitation, Get-KeeperEnterpriseNodeCustomInvitation, Set-KeeperEnterpriseNodeCustomLogo,
Invoke-KeeperEnterpriseNodeWipeOut


Export-ModuleMember -Alias ked, keu, ket, keta, kete, ketdel, ketu, ketr, keut, ken, ker, keru, kert, kerap, kena, kenu, kend, kenwipe, kers,
kerua, kerur, kerta, kertr, keradd, kerdel, kercopy, keitree, kein, keiu, keit, keir, keimc, invite-user, 
lock-user, unlock-user, transfer-user, delete-user, kuser-alias-add, kuser-alias-remove, list-team, kar, user-report, kal, audit-alert

Export-ModuleMember -Function Get-KeeperManagedCompany, New-KeeperManagedCompany, Remove-KeeperManagedCompany,
Edit-KeeperManagedCompany, Get-MspBillingReport, Get-KeeperMspLegacyReport, Switch-KeeperMC, Switch-KeeperMSP, Copy-KeeperMCRole
Export-ModuleMember -Alias kmc, kamc, krmc, kemc, switch-to-mc, switch-to-msp, msp-copy-role, msp-legacy-report

Export-ModuleMember -Function Show-KeeperRecordShare, Grant-KeeperRecordAccess, Revoke-KeeperRecordAccess, 
Revoke-KeeperSharesWithUser,Grant-KeeperSharedFolderAccess, Revoke-KeeperSharedFolderAccess, Get-KeeperAvailableTeam,
Move-KeeperRecordOwnership,New-KeeperOneTimeShare, Get-KeeperOneTimeShare, Remove-KeeperOneTimeShare, Get-KeeperComplianceReport, 
Get-KeeperComplianceTeamReport, Get-KeeperComplianceRecordAccessReport, Get-KeeperComplianceSummaryReport, 
Get-KeeperComplianceSharedFolderReport, Get-KeeperExternalSharesReport, Get-KeeperAgingReport
Export-ModuleMember -Alias kshrsh, kshr, kushr, kcancelshare, kshf, kushf, kat, ktr, kotsr, kotsn, kotsg, compliance-report,
compliance-team-report, record-access-report, compliance-summary-report, compliance-shared-folder-report, external-shares-report, aging-report

Export-ModuleMember -Function Get-KeeperSecretManagerApp, Add-KeeperSecretManagerApp, Remove-KeeperSecretManagerApp,
Grant-KeeperSecretManagerFolderAccess, Revoke-KeeperSecretManagerFolderAccess, Update-KeeperSecretManagerShare,
Add-KeeperSecretManagerClient, Remove-KeeperSecretManagerClient, Grant-KeeperAppAccess, Revoke-KeeperAppAccess
Export-ModuleMember -Alias ksm, ksm-create, ksm-delete, ksm-share, ksm-unshare, ksm-share-update, ksm-addclient, ksm-rmclient

Export-ModuleMember -Function Copy-KeeperFileAttachment, Copy-KeeperFileAttachmentToStream, Copy-FileToKeeperRecord, 
Remove-KeeperFileAttachment,Get-KeeperFileReport
Export-ModuleMember -Alias kda, krfa, file-report

Export-ModuleMember -Function Get-KeeperBreachWatchList, Test-PasswordAgainstBreachWatch,
Set-KeeperBreachWatchRecordIgnore, Get-KeeperIgnoredBreachWatchRecords,
Get-KeeperSecurityAuditReport, Get-KeeperBreachWatchReport
Export-ModuleMember -Alias kbw, kbwp, kbwi, kbwig, bw-report

Export-ModuleMember -Function Register-KeeperBiometricCredential, Assert-KeeperBiometricCredential, 
Show-KeeperBiometricCredentials, Unregister-KeeperBiometricCredential

Export-ModuleMember -Function Get-KeeperTrashList, Restore-KeeperTrashRecords, Remove-TrashedKeeperRecordShares, 
Get-KeeperTrashedRecordDetails,Clear-KeeperTrash
Export-ModuleMember -Alias ktrash, ktrash-restore, ktrash-unshare, ktrash-get, ktrash-purge

Export-ModuleMember -Function Export-KeeperVault, Export-KeeperMembership, Import-KeeperMembership, Import-KeeperVault
Export-ModuleMember -Alias kexport, kdwnmbs, kapplymbs, kimport

Export-ModuleMember -Function Get-KeeperActionReport
Export-ModuleMember -Alias action-report

Export-ModuleMember -Function Get-KeeperShareReport, Get-KeeperSharedRecordsReport
Export-ModuleMember -Alias ksrr

Export-ModuleMember -Function Get-KeeperRiskManagementReport
Export-ModuleMember -Alias risk-report

Export-ModuleMember -Function Get-KeeperNSFList, Get-KeeperNSFFolderList, Get-KeeperNSFRecordList, Get-KeeperNSFRecord, Get-KeeperNSFRecordDetails
Export-ModuleMember -Alias nsf-list, nsf-folders, nsf-records, nsf-get, nsf-record-details

Export-ModuleMember -Function New-KeeperNSFFolder, New-KeeperNSFFolders, Set-KeeperNSFFolderAccess, Share-KeeperNSFFolderAccesses, Update-KeeperNSFFolderAccesses, Unshare-KeeperNSFFolderAccesses, Set-KeeperNSFFolder, Set-KeeperNSFFolders, Remove-KeeperNSFFolder, Remove-KeeperNSFFolders
Export-ModuleMember -Alias nsf-mkdir, nsf-mkdirs, nsf-share-folder, nsf-share-folders, nsf-update-folder-access, nsf-unshare-folders, nsf-rndir, nsf-folders-update, nsf-rmdir, nsf-rmdirs

Export-ModuleMember -Function Add-KeeperNSFRecord, Add-KeeperNSFRecords, Edit-KeeperNSFRecord, Edit-KeeperNSFRecords, Set-KeeperNSFRecordAccess, Share-KeeperNSFRecords, Unshare-KeeperNSFRecords, Set-KeeperNSFRecordPermission,
Remove-KeeperNSFRecord, Remove-KeeperNSFRecords, Link-KeeperNSFRecord, Link-KeeperNSFRecords, Unlink-KeeperNSFRecords, Transfer-KeeperNSFRecordOwnership,
Get-KeeperNSFShortcut, Set-KeeperNSFShortcutKeep
Export-ModuleMember -Alias nsf-record-add, nsf-records-add, nsf-record-update, nsf-records-update, nsf-share-record, nsf-share-records, nsf-unshare-records, nsf-record-permission,
nsf-rm, nsf-records-rm, nsf-ln, nsf-lns, nsf-unln, nsf-transfer-record,
nsf-shortcut-list, nsf-shortcut-keep

Export-ModuleMember -Function Sync-KeeperEpm,
Get-KeeperEpmDeploymentList, Get-KeeperEpmDeployment, Add-KeeperEpmDeployment,
Update-KeeperEpmDeployment, Remove-KeeperEpmDeployment, Get-KeeperEpmDeploymentDownload,
Get-KeeperEpmApprovalList, Get-KeeperEpmApproval, Approve-KeeperEpmApproval, Deny-KeeperEpmApproval, Remove-KeeperEpmApproval
Export-ModuleMember -Alias kepm-sync,
kepm-deployment-list, kepm-deployment-view, kepm-deployment-add, kepm-deployment-edit, kepm-deployment-delete, kepm-deployment-download,
kepm-approval-list, kepm-approval-view, kepm-approval-approve, kepm-approval-deny, kepm-approval-remove

Export-ModuleMember -Function Get-KeeperEpmAgentList, Get-KeeperEpmAgent, Update-KeeperEpmAgent, Remove-KeeperEpmAgent, Get-KeeperEpmAgentCollection,
Get-KeeperEpmCollectionList, Get-KeeperEpmCollection, Add-KeeperEpmCollection,
Update-KeeperEpmCollection, Remove-KeeperEpmCollection, Connect-KeeperEpmCollection,
Disconnect-KeeperEpmCollection, Remove-KeeperEpmCollectionsByType
Export-ModuleMember -Alias kepm-agent-list, kepm-agent-view, kepm-agent-edit, kepm-agent-delete, kepm-agent-collection,
kepm-collection-list, kepm-collection-view, kepm-collection-add, kepm-collection-edit,
kepm-collection-delete, kepm-collection-connect, kepm-collection-disconnect, kepm-collection-wipeout

Export-ModuleMember -Function Get-KeeperEpmPolicyList, Get-KeeperEpmPolicy, Add-KeeperEpmPolicy,
Update-KeeperEpmPolicy, Remove-KeeperEpmPolicy, Get-KeeperEpmPolicyAgent, Add-KeeperEpmPolicyCollection
Export-ModuleMember -Alias kepm-policy-list, kepm-policy-view, kepm-policy-add, kepm-policy-edit,
kepm-policy-delete, kepm-policy-remove, kepm-policy-agents, kepm-policy-assign

Export-ModuleMember -Function Sync-KeeperPam, Get-KeeperPamGatewayList, New-KeeperPamGateway,
Set-KeeperPamGateway, Remove-KeeperPamGateway, Set-KeeperPamGatewayMaxInstances,
Get-KeeperPamRotationList, Get-KeeperPamRotationInfo, Set-KeeperPamRotation,
Get-KeeperPamRotationScript, Add-KeeperPamRotationScript, Set-KeeperPamRotationScript, Remove-KeeperPamRotationScript,
Get-KeeperPamConfig, New-KeeperPamConfig, Set-KeeperPamConfig, Remove-KeeperPamConfig, New-KeeperPamWorkflow, Get-KeeperPamWorkflow, Update-KeeperPamWorkflow, Remove-KeeperPamWorkflow, Add-KeeperPamWorkflowApprover, Remove-KeeperPamWorkflowApprover, Get-KeeperPamWorkflowState, Get-KeeperPamWorkflowMyAccess,
Invoke-KeeperPamActionRotate, Get-KeeperPamActionJobInfo, Set-KeeperPamConnection, Set-KeeperPamRbi, Invoke-KeeperPamLaunch
Export-ModuleMember -Alias pam-sync, pam-gateway-list, pam-gw-list, pam-gateway-new, pam-gw-new,
pam-gateway-edit, pam-gw-edit, pam-gateway-remove, pam-gw-remove, pam-gateway-rm,
pam-gateway-set-max-instances, pam-gw-set-max-instances,
pam-rotation-list, pam-rot-list, pam-rotation-info, pam-rot-info,
pam-rotation-edit, pam-rot-edit, pam-rotation-new, pam-rot-new, pam-rotation-script-list, pam-rot-script-list,
pam-rotation-script-add, pam-rot-script-add,
pam-rotation-script-edit, pam-rot-script-edit,
pam-rotation-script-delete, pam-rot-script-delete,
pam-config-list, pam-cfg-list, pam-config-new, pam-cfg-new,
pam-config-edit, pam-cfg-edit, pam-config-remove, pam-cfg-remove, pam-config-rm, pam-workflow-new, pam-wf-new, pam-workflow-read, pam-wf-read, pam-workflow-edit, pam-wf-edit, pam-workflow-delete, pam-wf-delete, pam-workflow-add-approver, pam-wf-add-approver, pam-workflow-remove-approver, pam-wf-remove-approver, pam-workflow-state, pam-wf-state, pam-workflow-my-access, pam-wf-my-access,
pam-action-rotate, pam-action-job-info, pam-connection-edit, pam-rbi-edit, pam-launch
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
