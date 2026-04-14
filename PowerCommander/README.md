### Reference Keeper Commander Powershell module
To install PowerCommander from PowerShell Gallery
```
Install-Module -Name PowerCommander
```

To run the PowerCommander module from the source copy PowerCommander\ directory to 
* `%USERPROFILE%\Documents\WindowsPowerShell\Modules` Per User
* `C:\Program Files\WindowsPowerShell\Modules` All users

### Optional: SQLite vault storage (-UseOfflineStorage)

To persist the vault cache between sessions, use `Connect-Keeper -UseOfflineStorage` (optionally with `-VaultDatabasePath`). Keep `KeeperSdk.dll` and `KeeperBiometrics.dll` in the **PowerCommander module folder**. Copy the **same SQLite assemblies Commander uses** into `PowerCommander\StorageUtils\` (validated and loaded only when you use `-UseOfflineStorage`):

- `Microsoft.Data.Sqlite.dll`
- `SQLitePCLRaw.batteries_v2.dll`, `SQLitePCLRaw.core.dll`, `SQLitePCLRaw.provider.e_sqlite3.dll`
- Native library: `e_sqlite3.dll`

Put **only** these files in `StorageUtils` — not `KeeperSdk.dll`, `*.pdb`, or a full `dotnet publish` output. 

Offline storage checks **only** these files (Windows). Copy them from a **Commander** `net8.0` build (same SQLite layout: managed DLLs plus `runtimes\win-x64\native\e_sqlite3.dll` copied next to the other SQLite assemblies as `e_sqlite3.dll` under `StorageUtils`).

Default vault database file: **`keeper_powercommander.sqlite`** next to your config (or in the current directory if no `-Config`). Commander continues to use **`keeper_db.sqlite`** in its config folder, so the two do not share the same SQLite file unless you point `-VaultDatabasePath` to the same path.


### Cmdlets
| Cmdlet name                                             | Alias            | Description
|---------------------------------------------------------|------------------|----------------------------
| [Connect-Keeper](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/login-commands#powercommander)                                         | kc               | Login to Keeper server
| [Sync-Keeper](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/miscellaneous-commands#power-commander-2)                                             | ks               | Sync with Keeper server 
| [Disconnect-Keeper](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/login-commands#powercommander-1)                                       | kq               | Logout and clear the data
| [Get-KeeperInformation](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/login-commands#power-commander)                                   | kwhoami          | Print account license information
| [Get-KeeperLocation](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/folder-commands#power-commander-6)                                      | kpwd             | Print current Keeper folder
| [Set-KeeperLocation](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/folder-commands#power-commander-6)                                      | kcd              | Change Keeper folder
| [Get-KeeperChildItem](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/miscellaneous-commands#power-commander-1)                                     | kdir             | Display subfolder and record names in the current Keeper folder
| [Get-KeeperObject](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/miscellaneous-commands#power-commander-1)                                        | ko               | Get Keeper object by Uid
| [Get-KeeperRecord](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/miscellaneous-commands#power-commander-1)                                        | kr               | Enumerate all records
| [Get-KeeperSharedFolder](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/shared-folder-commands#power-commander)                                 | ksf              | Enumerate all shared folders
| [Add-KeeperRecord](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/record-commands#powercommander)                                        | kadd             | Add/Modify Keeper record
| [Remove-KeeperRecord](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/record-commands#powercommander-2)                                     | kdel             | Delete Keeper record
| [Get-KeeperRecordPassword](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/miscellaneous-commands#power-commander-12)                                |                  | Get password of a keeper record if present 
| [Get-KeeperRecordType](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/record-type-commands#powercommander)                                    | krti             | Get Record Type Information
| [New-KeeperRecordType](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/record-type-commands#powercommander-1)                                    |                  | Creates a new custom record type
| [Edit-KeeperRecordType](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/record-type-commands#powercommander-2)                                   |                  | Modifies the existing custom record type
| [Remove-KeeperRecordType](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/record-type-commands#powercommander-3)                                 |                  | Removes the custom record type
| [Import-KeeperRecordTypes](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/import-export-commands#powercommander-5)                                |                  | loads new custom record types from file
| [Export-KeeperRecordTypes](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/import-export-commands#powercommander-4)                                |                  | exports custom record types from keeper to a file
| [Add-KeeperFolder](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/folder-commands#power-commander-4)                                        | kmkdir           | Create Keeper folder
| [Edit-KeeperFolder](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/folder-commands#power-commander-5)                                       |                  | Edit Keeper folder
| [Remove-KeeperFolder](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/folder-commands#dotnet-sdk-2)                                     | krmdir           | Remove Keeper folder
| [Get-KeeperFolder](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/folder-commands#power-commander-7)                                        | kgetfolder       | Get detailed information about a Keeper folder
| [Get-KeeperFolders](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/folder-commands#power-commander)                                       | kfolders         | List all folders in the vault with filtering options
| [Move-RecordToFolder](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/folder-commands#power-commander-1)                                     | kmv              | Move records to Keeper folder
| [Copy-KeeperToClipboard](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/record-commands#power-commander-3)                                  | kcc              | Copy record password to clipboard
| [Show-TwoFactorCode](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/miscellaneous-commands#power-commander-11)                                      | 2fa              | Display Two Factor Code 
| [Copy-KeeperFileAttachment](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/record-commands/attachment-commands#powercommander)                               | kda              | Download file attachments 
| [Copy-KeeperFileAttachmentToStream](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/record-commands#clipboard-copy-command)                       |                  | Download file attachement to stream
| [Remove-KeeperFileAttachment](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/record-commands/attachment-commands#powercommander-1)                             | krfa             | Remove file attachment from record
| [Copy-FileToKeeperRecord](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/record-commands/attachment-commands#power-commander)                                 |                  | Upload file attachment to a record
| [Get-KeeperDeviceSettings](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/miscellaneous-commands/this-device-commands#powercommander)                               |                  | Print the current device settings
| [Set-KeeperDeviceSettings](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/miscellaneous-commands/this-device-commands#powercommander-1)                                | this-device      | Modifies the current device settings
| [Get-KeeperPasswordVisible](Get-KeeperPasswordVisible)                               |                  | Show/hide secret fields setting
| [Set-KeeperPasswordVisible](Get-KeeperPasswordVisible)                               |                  | Sets whether password fields should be visible or not

### Trash Management Cmdlets
| Cmdlet name                                             | Alias            | Description
|---------------------------------------------------------|------------------|----------------------------
| [Get-KeeperTrashList](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/trash-commands#power-commander)                                    | ktrash           | List deleted records in trash
| [Get-KeeperTrashedRecordDetails](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/trash-commands#power-commander-2)                          | ktrash-get       | Get details of a deleted record
| [Restore-KeeperTrashRecords](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/trash-commands#power-commander-1)                              | ktrash-restore   | Restore deleted records from trash
| [Remove-TrashedKeeperRecordShares](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/trash-commands#power-commander-3)                        | ktrash-unshare   | Remove shares from deleted records
| [Clear-KeeperTrash](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/trash-commands#power-commander-4)                                       | ktrash-purge     | Permanently delete all records in trash

### Import/Export Cmdlets
| Cmdlet name                                             | Alias            | Description
|---------------------------------------------------------|------------------|----------------------------
| [Export-KeeperVault](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/import-export-commands#powercommander-1)                                      | kexport        | Export vault records and shared folders to JSON file
| [Import-KeeperVault](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/import-export-commands)                                      | kimport        | Import vault data from JSON file
| [Export-KeeperMembership](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/import-export-commands#powercommander-2)                                 | kdwnmbs        | Download shared folder and team membership data to JSON file
| [Import-KeeperMembership](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/import-export-commands#powercommander-3)                                 | kapplymbs      | Load shared folder membership from JSON file into Keeper

### Biometric Cmdlets
| Cmdlet name                                             | Alias            | Description
|---------------------------------------------------------|------------------|----------------------------
| [Assert-KeeperBiometricCredential](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/login-commands/biometric-login-commands)                        |                  | Checks if a biometric credential exists for the current user
| [Register-KeeperBiometricCredential](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/login-commands/biometric-login-commands)                      |                  | Registers a new biometric credential (Windows Hello/WebAuthn)
| [Show-KeeperBiometricCredentials](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/login-commands/biometric-login-commands)                         |                  | Lists all biometric credentials registered for the current user
| [Unregister-KeeperBiometricCredential](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/login-commands/biometric-login-commands)                    |                  | Removes a biometric credential from the current user 


### Sharing Cmdlets
| Cmdlet name                                             | Alias            | Description
|---------------------------------------------------------|------------------|----------------------------
| [Show-KeeperRecordShare](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/miscellaneous-commands#power-commander-12)                                  | kshrsh           | Show a record sharing information
| [Grant-KeeperRecordAccess](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/sharing-commands/record-share-command#power-commander)                                | kshr             | Share a record with user
| [Revoke-KeeperRecordAccess](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/sharing-commands/record-share-command#power-commander-2)                               | kushr            | Remove record share from user
| [Revoke-KeeperSharesWithUser](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/sharing-commands/record-share-command#power-commander-1)                             | kcancelshare     | Cancel all record shares with a user
| [Move-KeeperRecordOwnership](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/sharing-commands/record-share-command#power-commander-3)                              | ktr              | Transfer record ownership to user
| [Grant-KeeperSharedFolderAccess](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/sharing-commands#power-commander)                          | kshf             | Add a user or team to a shared folder
| [Revoke-KeeperSharedFolderAccess](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/sharing-commands/shared-folder-commands#power-commander-2)                         | kushf            | Remove a user or team from a shared folder
| [Get-KeeperOneTimeShare](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/sharing-commands#power-commander-2)                                  | kotsg            | Get One-Time Shares for a record
| [New-KeeperOneTimeShare](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/sharing-commands#power-commander-1)                                  | kotsn            | Create One-Time Share
| [Remove-KeeperOneTimeShare](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/sharing-commands#power-commander-3)                               | kotsr            | Remove One-Time Share

### Enterprise Cmdlets
| Cmdlet name                                             | Alias            | Description
|---------------------------------------------------------|------------------|----------------------------
| [Sync-KeeperEnterprise](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/enterprise-management-commands#powercommander)                                   | ked              | Sync Keeper enterprise information
| [Get-KeeperEnterpriseInfoTree](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/enterprise-management-commands/enterprise-info-commands#powercommander)                            | keitree          | Shows hierarchy of nodes with counts or lists of users, roles, and teams per node.
| [Get-KeeperEnterpriseInfoNode](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/enterprise-management-commands/enterprise-info-commands#powercommander-1)                            | kein             | Outputs nodes with parent path, user/team/role counts, and optionally user/team/role lists and provisioning.
| [Get-KeeperEnterpriseInfoUser](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/enterprise-management-commands/enterprise-info-commands#powercommander-2)                            | keiu             | Outputs users with status, node, roles, teams, and optional columns.
| [Get-KeeperEnterpriseInfoTeam](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/enterprise-management-commands/enterprise-info-commands#powercommander-3)                            | keit             | Outputs teams with restricts (Read/Write/Share), node, user/role counts, and optional user/role lists.
| [Get-KeeperEnterpriseInfoRole](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/enterprise-management-commands/enterprise-info-commands#powercommander-4)                            | keir             | Outputs roles with node, user/team counts, admin flag, and optional user/team lists.
| [Get-KeeperEnterpriseInfoManagedCompany](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/enterprise-management-commands/enterprise-info-commands#powercommander-5)                  | keimc            | Outputs managed company information. Available when logged in as MSP.
| Export-KeeperAuditLog                                 | kal              | Exports enterprise audit events to JSON, syslog, Splunk, Sumo, Azure Log Analytics, or a syslog port. Supports Keeper record-backed config and incremental export state.
| [Get-KeeperEnterpriseNode](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/enterprise-management-commands/enterprise-info-commands#powercommander-5)                                | ken              | Enumerate all enterprise nodes
| [Get-KeeperEnterpriseUser](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/enterprise-management-commands/enterprise-user-commands#powercommander)                                | keu              | Enumerate all enterprise users
| [Get-KeeperEnterpriseTeam](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/enterprise-management-commands/enterprise-team-commands#powercommander)                                | ket              | Enumerate all enterprise teams
| [Get-KeeperEnterpriseTeamUser](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/enterprise-management-commands/enterprise-team-commands#powercommander)                            | ketu             | Get a list of enterprise users for team
| [Get-KeeperEnterpriseTeams](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/enterprise-management-commands/enterprise-team-commands#powercommander)                               | list-team        | List all enterprise teams (with optional filters)
| [Get-KeeperAvailableTeam](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/enterprise-management-commands/enterprise-team-commands#powercommander)                                 | kat              | Get available teams (for sharing and membership)
| [New-KeeperEnterpriseTeam](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/enterprise-management-commands/enterprise-team-commands#powercommander-1)                                | keta             | Create Team
| [Add-KeeperEnterpriseTeamMember](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/enterprise-management-commands/enterprise-team-commands#powercommander-4)                          |                  | Add a list of enterprise users to a team
| [Remove-KeeperEnterpriseTeamMember](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/enterprise-management-commands/enterprise-team-commands#powercommander-4)                       |                  | Remove a list of enterprise users from a team
| [Update-KeeperEnterpriseTeamUser](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/enterprise-management-commands/enterprise-user-commands#powercommander-8)                         |                  | Update team member role (admin/user) for a user in a team
| [New-KeeperEnterpriseNode](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/enterprise-management-commands/enterprise-node-commands#powercommander-1)                                | kena             | Create Node
| [Edit-KeeperEnterpriseNode](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/enterprise-management-commands/enterprise-node-commands#powercommander-2)                               | kenu             | Update Node (rename, move, or enable node isolation)
| [Remove-KeeperEnterpriseNode](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/enterprise-management-commands/enterprise-node-commands#powercommander-2)                             | kend             | Delete Enterprise Node
| [Invoke-KeeperEnterpriseNodeWipeOut](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/enterprise-management-commands/enterprise-node-commands#powercommander-6)                      | kenwipe          | Wipe out node and all its content (users, roles, teams, subnodes)
| [Set-KeeperEnterpriseNodeCustomInvitation](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/enterprise-management-commands/enterprise-node-commands#powercommander-5)                |                  | Set custom invitation email template for an Enterprise Node
| [Get-KeeperEnterpriseNodeCustomInvitation](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/enterprise-management-commands/enterprise-node-commands#powercommander-7)                |                  | Get custom invitation email template for an Enterprise Node
| [Set-KeeperEnterpriseNodeCustomLogo](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/enterprise-management-commands/enterprise-node-commands#powercommander-4)                      |                  | Upload custom logo for an Enterprise Node
| [Add-KeeperEnterpriseUser](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/enterprise-management-commands/enterprise-user-commands#powercommander-1)                                | invite-user      | Invite User to Enterprise
| [Invoke-ResendKeeperEnterpriseInvite](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/enterprise-management-commands/enterprise-user-commands#powercommander-6)                    |                  | Resend enterprise invitation email to a user
| [Lock-KeeperEnterpriseUser](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/enterprise-management-commands/enterprise-user-commands#powercommander-4)                               | lock-user        | Lock Enterprise User
| [Unlock-KeeperEnterpriseUser](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/enterprise-management-commands/enterprise-user-commands#powercommander-4)                             | unlock-user      | Unlock Enterprise User
| [Move-KeeperEnterpriseUser](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/enterprise-management-commands/transfer-user-commands#powercommander)                               |transfer-user     | Transfer user vault to another user (-FromUser, -TargetUser; -Force to skip confirmation)
| [Remove-KeeperEnterpriseUser](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/enterprise-management-commands/enterprise-user-commands#powercommander-3)                             | delete-user      | Delete Enterprise User
| [Update-KeeperEnterpriseUser](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/enterprise-management-commands/enterprise-user-commands#powercommander-9)                             |                  | Update enterprise user (node, full name, job title, locale)
| [Set-KeeperEnterpriseUserMasterPasswordExpire](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/enterprise-management-commands/enterprise-user-commands#powercommander-7)            |                  | Expire master password for enterprise user
| [Get-KeeperEnterpriseRole](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/enterprise-management-commands/enterprise-role-commands#powercommander)                                | ker              | Enumerate all enterprise roles
| [Get-KeeperEnterpriseRoleUsers](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/enterprise-management-commands/enterprise-role-commands#powercommander)                           | keru             | Get a list of enterprise users for role
| [Get-KeeperEnterpriseRoleTeams](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/enterprise-management-commands/enterprise-role-commands#powercommander)                           | kert             | Get a list of enterprise teams for role 
| [Get-KeeperEnterpriseAdminRole](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/enterprise-management-commands/enterprise-role-commands#powercommander-4)                           | kerap            | Enumerate all enterprise role admin permissions
| [Set-KeeperEnterpriseRole](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/enterprise-management-commands/enterprise-role-commands#powercommander-2)                                | kers             | Update Enterprise Role properties (NewUserInherit, VisibleBelow, DisplayName)
| [New-KeeperEnterpriseRole](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/enterprise-management-commands/enterprise-role-commands#powercommander-1)                                | keradd           | Create a new enterprise role in the Keeper Enterprise
| [Remove-KeeperEnterpriseRole](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/enterprise-management-commands/enterprise-role-commands#powercommander-3)                             | kerdel           | Delete an enterprise role from the Keeper Enterprise
| [Copy-KeeperEnterpriseRole](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/enterprise-management-commands/enterprise-role-commands#powercommander-6)                               | kercopy          | Copy a role (enforcements, users, teams) to another node
| [Grant-KeeperEnterpriseRoleToUser](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/enterprise-management-commands/enterprise-role-commands#powercommander-5)                        | kerua            | Add a user to an Enterprise Role
| [Revoke-KeeperEnterpriseRoleFromUser](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/enterprise-management-commands/enterprise-role-commands#powercommander-5)                     | kerur            | Remove a user from an Enterprise Role
| [Grant-KeeperEnterpriseRoleToTeam](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/enterprise-management-commands/enterprise-role-commands#powercommander-7)                        | kerta            | Add a team to an Enterprise Role
| [Revoke-KeeperEnterpriseRoleFromTeam](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/enterprise-management-commands/enterprise-role-commands#powercommander-7)                     | kertr            | Remove a team from an Enterprise Role
| [Add-KeeperEnterpriseRoleManagedNode](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/enterprise-management-commands/enterprise-role-commands#powercommander-8)                     |                  | Add a managed node to an Enterprise Role
| [Update-KeeperEnterpriseRoleManagedNode](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/enterprise-management-commands/enterprise-role-commands#powercommander-9)                  |                  | Update managed node settings for an Enterprise Role
| [Remove-KeeperEnterpriseRoleManagedNode](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/enterprise-management-commands/enterprise-role-commands#powercommander-10)                  |                  | Remove a managed node from an Enterprise Role
| [Add-KeeperEnterpriseRolePrivilege](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/enterprise-management-commands/enterprise-role-commands#powercommander-11)                       |                  | Add privileges to a managed node for an Enterprise Role
| [Remove-KeeperEnterpriseRolePrivilege](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/enterprise-management-commands/enterprise-role-commands#powercommander-12)                    |                  | Remove privileges from a managed node for an Enterprise Role
| [Add-KeeperEnterpriseRoleEnforcement](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/enterprise-management-commands/enterprise-role-commands#powercommander-13)                     |                  | Add enforcement policies to an Enterprise Role
| [Update-KeeperEnterpriseRoleEnforcement](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/enterprise-management-commands/enterprise-role-commands#powercommander-14)                  |                  | Update enforcement policies for an Enterprise Role
| [Remove-KeeperEnterpriseRoleEnforcement](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/enterprise-management-commands/enterprise-role-commands#powercommander-15)                  |                  | Remove enforcement policies from an Enterprise Role
| [Get-KeeperNodeName]()                                      |                  | Return Name of current Enterprise Node
| [Get-KeeperNodePath]()                                      |                  | Return path of current Enterprise Node
| [Get-KeeperRoleName]()                                      |                  | Get Display Name of Enterprise Role
| [Switch-KeeperMC](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/msp-management-commands#powercommander-5)                                         | switch-to-mc     | Switch to Managed Company (by name or ID)
| [Switch-KeeperMSP](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/msp-management-commands#powercommander-7)                                        | switch-to-msp    | Switch back to MSP
| [Get-KeeperManagedCompany](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/msp-management-commands#powercommander)                                | kmc              | MSP info: list managed companies (default), or -Restriction (permits), or -Pricing (BI). Use -Detailed for full MC list; -ManagedCompany to filter; -Format / -Output for table, json, csv
| [New-KeeperManagedCompany](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/msp-management-commands#powercommander-2)                                | kamc             | Create Managed Company (-Name, -PlanId, -MaximumSeats; optional -Storage, -Addons, -Node)
| [Remove-KeeperManagedCompany](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/msp-management-commands#powercommander-4)                             | krmc             | Remove Managed Company (by name or ID; -Force to skip confirmation)
| [Edit-KeeperManagedCompany](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/msp-management-commands#powercommander-3)                               | kemc             | Edit Managed Company (name, plan, seats, storage, add-ons; -AddAddon / -RemoveAddon)
| [Copy-KeeperMCRole](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/msp-management-commands#powercommander-6)                                       | msp-copy-role    | Copy role(s) with enforcements from MSP to one or more Managed Companies (-Role by name or ID, -ManagedCompany by name or ID)
| [Get-MspBillingReport](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/msp-management-commands#powercommander-8)                                    |                  | Generate MSP Consumption Billing Statement (-Month, -Year; -ShowDate, -ShowCompany; -Format table/json/csv, -Output path)
| Get-KeeperMspLegacyReport                               | msp-legacy-report | Generate MSP legacy billing report. Supports predefined date ranges (-Range) or custom dates (-From, -To); -Format table/json/csv, -Output path

### Device Approval Cmdlets
| Cmdlet name                                             | Alias            | Description
|---------------------------------------------------------|------------------|----------------------------
| [Get-PendingKeeperDeviceApproval](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/enterprise-management-commands/device-approve-commands#powercommander)                         |                  | List pending device approval requests with details (email, device ID, device name, client version, IP address). Supports table, CSV, and JSON output formats
| [Approve-KeeperDevice](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/enterprise-management-commands/device-approve-commands#powercommander-1)                                    |                  | Approve pending device requests by device ID (partial match) or user email. Supports -TrustedIp to filter by trusted IP addresses
| [Deny-KeeperDevice](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/enterprise-management-commands/device-approve-commands#powercommander-2)                                       |                  | Deny pending device requests by device ID (partial match) or user email

### BreachWatch Cmdlets
| Cmdlet name                                             | Alias            | Description
|---------------------------------------------------------|------------------|----------------------------
| [Get-KeeperBreachWatchList](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/breachwatch-commands#powercommander)                               | kbw              | List passwords which are breached based on breachwatch
| [Test-PasswordAgainstBreachWatch](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/breachwatch-commands#powercommander-2)                         | kbwp             | check a given password against breachwatch passwords
| [Set-KeeperBreachWatchRecordIgnore](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/breachwatch-commands#powercommander-3)                       | kbwi             | Ignore a given record from breachwatch alerts
| [Get-KeeperIgnoredBreachWatchRecords](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/breachwatch-commands#powercommander)                     | kbwig            | List ignored breachwatch records

### Secret Manager Cmdlets
| Cmdlet name                                             | Alias            | Description
|---------------------------------------------------------|------------------|----------------------------
| [Get-KeeperSecretManagerApp](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/secrets-manager-commands/secrets-manager-app-commands#powercommander)                              | ksm              | Enumerate all Keeper Secret Manager Applications
| [Add-KeeperSecretManagerApp](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/secrets-manager-commands/secrets-manager-app-commands#powercommander-1)                              | ksm-create       | Add a Keeper Secret Manager Application
| [Remove-KeeperSecretManagerApp](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/secrets-manager-commands/secrets-manager-app-commands#powercommander-3)                           | ksm-delete       | Delete a Keeper Secret Manager Application
| [Grant-KeeperSecretManagerFolderAccess](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/secrets-manager-commands/secrets-manager-share-commands#powercommander)                   | ksm-share        | Add a shared folder to KSM Application
| [Revoke-KeeperSecretManagerFolderAccess](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/secrets-manager-commands/secrets-manager-share-commands#powercommander-1)                  | ksm-unshare      | Remove a Shared Folder from KSM Application
| [Add-KeeperSecretManagerClient](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/secrets-manager-commands/secrets-manager-client-commands#powercommander)                           |ksm-addclient     | Add a client/device to KSM Application
| [Remove-KeeperSecretManagerClient](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/secrets-manager-commands/secrets-manager-client-commands#powercommander-1)                        | ksm-rmclient     | Remove a client/device from KSM Application
| [Grant-KeeperAppAccess](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/secrets-manager-commands/secrets-manager-app-commands#powercommander-4)                                   |                  | Grant Keeper Secret Manager Application Access to a user
| [Revoke-KeeperAppAccess](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/secrets-manager-commands/secrets-manager-app-commands#powercommander-5)                                  |                  | Revoke Keeper Secret Manager Application Access from a user


### Reporting Cmdlets
| Cmdlet name                                             | Alias            | Description
|---------------------------------------------------------|------------------|----------------------------
| [Get-KeeperPasswordReport](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/miscellaneous-commands#power-commander-12)                                |                  | Retrieves password report based on policy and strengths
| [Get-KeeperFileReport](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/record-commands#power-commander-5)                                    | file-report      | List records with file attachments and optionally verify download accessibility
| [Find-KeeperDuplicateRecords](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/record-commands#power-commander-4)                             | find-duplicates  | Find records with duplicate passwords or other criteria
| [Get-KeeperRecordHistory](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks/sdk-command-reference/record-commands#power-commander-2)                                 | krh              | Get version history for a Keeper record
| Get-KeeperAuditReport                                   | kar              | Run an enterprise audit trail report
| Get-KeeperUserReport                                    | user-report      | Run an enterprise user report
| Get-KeeperShareReport                                   |                  | Show a report of shared records and shared folders with multiple modes: summary, per-record detail, per-user, owner report, and shared folders listing
| Get-KeeperSharedRecordsReport                           | ksrr             | Report shared records showing share type (Direct/Folder/Team), who each record is shared with, and permissions. Use -AllRecords for non-owned records, -ShowTeamUsers to expand teams
| Get-KeeperActionReport                                  | action-report    | Generate a report of users based on activity status (no-logon, no-update, locked, invited, no-recovery) and optionally apply admin actions (lock, delete, transfer). Supports -DaysSince, -Node, -DryRun, -Force, -Columns, -Format, -Output
| Get-KeeperSecurityAuditReport                           |                  | Generate enterprise security audit reports in table, JSON, or CSV with optional node filtering, BreachWatch view, save, and repair options
| Get-KeeperBreachWatchReport                             | bw-report        | Generate the enterprise BreachWatch report and push updated summary data to Keeper


#### Examples

1. Connect To Keeper Account
    ```powershell
    PS > Connect-Keeper
         Keeper Username: email_address@company.com
            ... Password:
    ```
2. List the content of Keeper folder
    ```
    PS > kdir
    
        Vault Folder: \
    
    
    Mode    UID                      Name
    ----    ---                      ----
    f-----  b3TMAYfOWJqNxeLjlA6v_g   dasdasd
    f----S  BvHeHGkdRJfhGaRcI-J5Ww   shared
    -r-AO-  5qx_urh2EsrL0wBdi34nFw   Web
    -r---S  ktY3jEBqwFDi9UYZSxmIpw   Control
    ```
    - **f** - folder
    - **r** - record
    - **S** - shared
    - **A** - file attachments
    - **O** - owner

3. Show Two Factor Code for all records in the current Keeper folder
    ```
    PS > kdir -ObjectType Record | Show-TwoFactorCode
    ```

4. Show Two Factor Code for all records in the Vault.
    ```
    PS > kr|2fa
    ```
     where 
    * `kr` is alias for `Get-KeeperRecord` 
    * `2fa` is alias for `Show-TwoFactorCode`

5. Copy record password to clipboard
    ```
    PS > 'contro' | kcc
    ``` 
    where 
    * `contro` is a substring of the record title. See last entry of `kdir` output in example #2 
    * `kcc` is alias for `Copy-KeeperToClipboard`
    
    or
    ```
    PS > 'ktY3jEBqwFDi9UYZSxmIpw' | kcc
    ```
   `'ktY3jEBqwFDi9UYZSxmIpw'` is the Record UID of the same record

6. Add/Modify Keeper record
    ```
    PS > kadd -Title 'Record for John Doe' -GeneratePassword login=email@company.com url=https://company.com 'User Name=John Doe' 
    ```
    creates a legacy record in Keeper 
    ```
    PS > kadd -RecordType login -Title 'Record for John Doe' -GeneratePassword login=email@company.com url=https://company.com 'User Name=John Doe' 
    ```
    creates a record of `login` type in Keeper 
    ```
    PS > $address = @{"street1" = "123 Main St."; "city" = "Neitherville"; "state" = "CA"; "zip" = "12345"}
    PS > kadd -RecordType address -Title 'Home Address' -address $address phone.Home='(555)123-4567' name="Doe, John"
    ```
    ```
    PS > kadd -Uid <RECORD UID> -GeneratePassword 
    ```
    generates a new password for existing record

    Pre-defined fields supported by both legacy and typed records
    * `login`       Login
    * `password`    Password
    * `url`         Website Address

7. Copy owned record to folder
    ```
    PS > Get-KeeperChildItem -ObjectType Record | Move-RecordToFolder 'Shared Folder'
    ```
    copies all records in the current Keeper folder to the folder with name 'Shared Folder'

8. Get detailed information about a folder
    ```
    PS > Get-KeeperFolder 'Shared Folder'
    ```
    or using the alias
    ```
    PS > kgetfolder 'b3TMAYfOWJqNxeLjlA6v_g'
    ```
    where `b3TMAYfOWJqNxeLjlA6v_g` is the Folder UID
    
    You can also use a path:
    ```
    PS > Get-KeeperFolder '/Shared Folder/SubFolder'
    ```

9. List all enterprise users
    ```
    PS > Get-KeeperEnterpriseUser
    ```

10. Create a new Managed Company
    ```
    PS> New-KeeperManagedCompany -Name "Company Name" -PlanId enterprisePlus -Allocated 5
    ```

11. Switch to a new Managed Company
    ```
    PS> switch-to-mc "Company Name"
    ```

12. List deleted records in trash
    ```
    PS > Get-KeeperTrashList
    ```
    or using the alias
    ```
    PS > ktrash
    ```
    Filter by pattern:
    ```
    PS > ktrash -Pattern "test*"
    ```

13. Get details of a deleted record
    ```
    PS > Get-KeeperTrashedRecordDetails -RecordUid "QGMaKCr9ksOOkhIMSvIWtg"
    ```
    or using the alias
    ```
    PS > ktrash-get "QGMaKCr9ksOOkhIMSvIWtg"
    ```

14. Restore deleted records from trash
    ```
    PS > Restore-KeeperTrashRecords -Records "QGMaKCr9ksOOkhIMSvIWtg"
    ```
    or using patterns and alias
    ```
    PS > ktrash-restore -Records "test*", "MyRecord" -Force
    ```

15. Remove shares from deleted records
    ```
    PS > Remove-TrashedKeeperRecordShares -Records "QGMaKCr9ksOOkhIMSvIWtg"
    ```
    or remove shares from all orphaned records
    ```
    PS > ktrash-unshare -Records "*" -Force
    ```

16. List pending device approval requests
    ```
    PS > Get-PendingKeeperDeviceApproval
    ```
    Export to CSV format
    ```
    PS > Get-PendingKeeperDeviceApproval -Format csv -Output devices.csv
    ```
    Reload and display in JSON format
    ```
    PS > Get-PendingKeeperDeviceApproval -Reload -Format json
    ```

17. Approve device by user email
    ```
    PS > Approve-KeeperDevice -Match "user@example.com"
    ```
    Approve device by device ID (partial match)
    ```
    PS > Approve-KeeperDevice -Match "a1b2c3"
    ```
    Approve all pending devices
    ```
    PS > Approve-KeeperDevice
    ```
    Reload and approve
    ```
    PS > Approve-KeeperDevice -Match "user@example.com" -Reload
    ```

18. Deny device by user email
    ```
    PS > Deny-KeeperDevice -Match "user@example.com"
    ```
    Deny device by device ID (partial match)
    ```
    PS > Deny-KeeperDevice -Match "a1b2c3"
    ```
    Deny all pending devices
    ```
    PS > Deny-KeeperDevice
    ```

19. Approve devices from trusted IP addresses only
    ```
    PS > Approve-KeeperDevice -TrustedIp
    ```
    Approve devices for specific user from trusted IPs only
    ```
    PS > Approve-KeeperDevice -Match "user@example.com" -TrustedIp
    ```

20. Resend enterprise invitation
    ```
    PS > Invoke-ResendKeeperEnterpriseInvite -User "user@example.com"
    ```

21. Expire master password for enterprise user
    ```
    PS > Set-KeeperEnterpriseUserMasterPasswordExpire -User "user@example.com"
    ```

22. Add managed node to enterprise role
    ```
    PS > Add-KeeperEnterpriseRoleManagedNode -Role "AdminRole" -Node "Sales"
    ```

23. Add privileges to managed node
    ```
    PS > Add-KeeperEnterpriseRolePrivilege -Role "AdminRole" -Node "Sales" -Privilege "MANAGE_USERS", "MANAGE_TEAMS"
    ```

24. Add enforcement to enterprise role
    ```
    PS > Add-KeeperEnterpriseRoleEnforcement -Role "AdminRole" -Enforcement "TWO_FACTOR_DURATION_WEB=3600"
    ```

25. Wipe out enterprise node (remove all users, roles, teams, subnodes under the node)
    ```
    PS > Invoke-KeeperEnterpriseNodeWipeOut -Node "Sales"
    ```
    or using alias (prompts for confirmation)
    ```
    PS > kenwipe -Node "Sales"
    ```
    Skip confirmation
    ```
    PS > Invoke-KeeperEnterpriseNodeWipeOut -Node "Sales" -Force
    ```

26. Set custom invitation template for enterprise node
    ```
    PS > Set-KeeperEnterpriseNodeCustomInvitation -Node "Sales" -JsonFilePath "C:\invitation.json"
    ```

27. Get custom invitation template for enterprise node
    ```
    PS > Get-KeeperEnterpriseNodeCustomInvitation -Node "Sales"
    ```

28. Set custom logo for enterprise node
    ```
    PS > Set-KeeperEnterpriseNodeCustomLogo -Node "Sales" -LogoFilePath "C:\logo.png"
    ```

29. Permanently delete all records in trash
    ```
    PS > Clear-KeeperTrash
    ```
    or using alias
    ```
    PS > ktrash-purge
    ```
    Skip confirmation prompt
    ```
    PS > Clear-KeeperTrash -Force
    ```

30. Copy enterprise role to another node
    ```
    PS > Copy-KeeperEnterpriseRole -SourceRole "Test-App" -TargetNode "dev" -NewRoleName "second dev"
    ```
    or using alias (copies enforcements, users, and teams from the source role)
    ```
    PS > kercopy -SourceRole "Test-App" -TargetNode "dev" -NewRoleName "second dev"
    ```
    Copy only enforcements and teams (no users)
    ```
    PS > Copy-KeeperEnterpriseRole -SourceRole "AdminRole" -TargetNode 123456789 -NewRoleName "AdminRole-Copy" -CopyUsers $false
    ```

31. Run an audit trail report
    ```
    PS > Get-KeeperAuditReport
    ```
    or using the alias
    ```
    PS > kar
    ```
    Returns the last 100 raw audit events (Created, Username, Event, Message).

32. Export audit log events with a Keeper config record
    ```
    PS > Export-KeeperAuditLog -Target splunk
    ```
    or using the alias
    ```
    PS > kal -Target splunk
    ```
    On first run, prompts to create a Keeper record and stores the target settings plus `last_event_time` so later runs export incrementally.
33. Generate MSP legacy billing report
    ```
    PS > Get-KeeperMspLegacyReport
    ```
    or using aliases
    ```
    PS > msp-legacy-report
    ```
    Returns the legacy license adjustment log for the last 30 days.
    Use a predefined date range
    ```
    PS > Get-KeeperMspLegacyReport -Range last_7_days
    ```
    Use a custom date range
    ```
    PS > Get-KeeperMspLegacyReport -From "2025-01-01" -To "2025-06-30"
    ```
    Export as CSV to a file
    ```
    PS > Get-KeeperMspLegacyReport -Range last_month -Format csv -Output "legacy_report.csv"
    ```
34. Run a security audit report for the enterprise
    ```
    PS > Get-KeeperSecurityAuditReport
    ```
    Export to JSON
    ```
    PS > Get-KeeperSecurityAuditReport -Format json -Output security-audit.json
    ```
    Filter to a node subtree
    ```
    PS > Get-KeeperSecurityAuditReport -Node "Sales"
    ```

35. Run the BreachWatch enterprise report
    ```
    PS > Get-KeeperBreachWatchReport
    ```
    or using the alias
    ```
    PS > bw-report
    ```

36. Run an action report on enterprise users
    ```
    PS > Get-KeeperActionReport
    ```
    or using the alias
    ```
    PS > action-report
    ```
    Shows users who haven't logged in for 30 days. Use `-Target` to change status filter, `-DaysSince` for time period, `-ApplyAction` to lock/delete/transfer users.
    ```
    PS > action-report -Target locked -ApplyAction delete -DryRun
    ```
    Preview deleting locked users without executing.

37. Share report - summary of all shares grouped by target
    ```
    PS > Get-KeeperShareReport
    ```
    Show owner report with share dates and team member expansion
    ```
    PS > Get-KeeperShareReport -Owner -ShareDate -ShowTeamUsers
    ```
    Show shared folders listing
    ```
    PS > Get-KeeperShareReport -Folders
    ```
38. Shared records report - flat listing of all shared records with share details
    ```
    PS > Get-KeeperSharedRecordsReport
    ```
    or using aliases
    ```
    PS > ksrr
    ```
    Include all shared records (not just owned)
    ```
    PS > Get-KeeperSharedRecordsReport -AllRecords
    ```
    Expand team shares to individual members
    ```
    PS > Get-KeeperSharedRecordsReport -ShowTeamUsers
    ```
    Scope to a specific folder
    ```
