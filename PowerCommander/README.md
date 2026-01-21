### Reference Keeper Commander Powershell module
To install PowerCommander from PowerShell Gallery
```
Install-Module -Name PowerCommander
```

To run the PowerCommander module from the source copy PowerCommander\ directory to 
* `%USERPROFILE%\Documents\WindowsPowerShell\Modules` Per User
* `C:\Program Files\WindowsPowerShell\Modules` All users

### Cmdlets
| Cmdlet name                                             | Alias            | Description
|---------------------------------------------------------|------------------|----------------------------
| Connect-Keeper                                          | kc          | Login to Keeper server
| Sync-Keeper                                             | ks          | Sync with Keeper server 
| Disconnect-Keeper                                       | kq          | Logout and clear the data
| Get-KeeperLocation                                      | kpwd        | Print current Keeper folder
| Set-KeeperLocation                                      | kcd         | Change Keeper folder
| Get-KeeperChildItem                                     | kdir        | Display subfolder and record names in the current Keeper folder
| Get-KeeperObject                                        | ko          | Get Keeper object by Uid
| Get-KeeperRecord                                        | kr          | Enumerate all records
| Get-KeeperSharedFolder                                  | ksf         | Enumerate all shared folders
| Add-KeeperRecord                                        | kadd        | Add/Modify Keeper record
| Get-KeeperRecordPassword                                |             | Get password of a keeper record if present 
| Get-KeeperRecordType                                    | krti        | Get Record Type Information
| New-KeeperRecordType                                    |             | Creates a new custom record type
| Edit-KeeperRecordType                                   |             | Modifies the existing custom record type
| Remove-KeeperRecordType                                 |             | Removes the custom record type
| Import-KeeperRecordTypes                                |             | loads new custom record types from file
| Export-KeeperRecordTypes                                |             | exports custom record types from keeper to a file
| Remove-KeeperRecord                                     | kdel        | Delete Keeper record
| Move-RecordToFolder                                     | kmv         | Move records to Keeper folder
| Add-KeeperFolder                                        | kmkdir      | Create Keeper folder
| Get-KeeperFolder                                        | kgetfolder  | Get detailed information about a Keeper folder
| Get-KeeperFolders                                       | kfolders    | List all folders in the vault with filtering options
| Edit-KeeperFolder                                       |             | Edit Keeper folder
| Remove-KeeperFolder                                     | krmdir      | Remove Keeper folder
| Copy-KeeperToClipboard                                  | kcc         | Copy record password to clipboard
| Show-TwoFactorCode                                      | 2fa         | Display Two Factor Code 
| Copy-KeeperFileAttachment                               | kda         | Download file attachments 
| Remove-KeeperFileAttachment                             | krfa        | Remove file attachment from record
| Copy-KeeperFileAttachmentToStream                       |             | Download file attachement to stream
| Copy-FileToKeeperRecord                                 |             | Upload file attachment to a record
| Get-KeeperInformation                                   | kwhoami     | Print account license information
| Get-KeeperDeviceSettings                                |             | Print the current device settings
| Set-KeeperDeviceSettings                                | this-device | Modifies the current device settings
| Get-KeeperPasswordVisible                               |             | Show/hide secret fields setting
| Set-KeeperPasswordVisible                               |             | Sets whether password fields should be visible or not
| Get-KeeperPasswordReport                                |             | Retrieves password report based on policy and strengths

### Trash Management Cmdlets
| Cmdlet name                                             | Alias            | Description
|---------------------------------------------------------|------------------|----------------------------
| Get-KeeperTrashList                                     | ktrash         | List deleted records in trash
| Get-KeeperTrashedRecordDetails                          | ktrash-get     | Get details of a deleted record
| Restore-KeeperTrashRecords                              | ktrash-restore | Restore deleted records from trash
| Remove-TrashedKeeperRecordShares                        | ktrash-unshare | Remove shares from deleted records
| Clear-KeeperTrash                                       | ktrash-purge   | Permanently delete all records in trash

### Import/Export Cmdlets
| Cmdlet name                                             | Alias            | Description
|---------------------------------------------------------|------------------|----------------------------
| Export-KeeperVault                                      | kexport        | Export vault records and shared folders to JSON file
| Export-KeeperMembership                                 | kdwnmbs        | Download shared folder and team membership data to JSON file

### Biometric Cmdlets
| Cmdlet name                                             | Alias            | Description
|---------------------------------------------------------|------------------|----------------------------
| Assert-KeeperBiometricCredential                        |             | Checks if a biometric credential exists for the current user
| Register-KeeperBiometricCredential                      |             | Registers a new biometric credential (Windows Hello/WebAuthn)
| Show-KeeperBiometricCredentials                         |             | Lists all biometric credentials registered for the current user
| Unregister-KeeperBiometricCredential                    |             | Removes a biometric credential from the current user 


### Sharing Cmdlets
| Cmdlet name                                             | Alias            | Description
|---------------------------------------------------------|------------------|----------------------------
| Show-KeeperRecordShare                                  | kshrsh      | Show a record sharing information
| Grant-KeeperRecordAccess                                | kshr        | Share a record with user
| Revoke-KeeperRecordAccess                               | kushr       | Remove record share from user
| Move-KeeperRecordOwnership                              | ktr         | Transfer record ownership to user
| Grant-KeeperSharedFolderAccess                          | kshf        | Add a user or team to a shared folder
| Revoke-KeeperSharedFolderAccess                         | kushf       | Remove a user or team from a shared folder
| Get-KeeperAvailableTeam                                 | kat         | Get available teams
| Get-KeeperOneTimeShare                                  | kotsg       | Get One-Time Shares for a record
| New-KeeperOneTimeShare                                  | kotsn       | Create One-Time Share
| Remove-KeeperOneTimeShare                               | kotsr       | Remove One-Time Share

### Enterprise Cmdlets
| Cmdlet name                                             | Alias            | Description
|---------------------------------------------------------|------------------|----------------------------
| Sync-KeeperEnterprise                                   | ked         | Sync Keeper enterprise information
| Get-KeeperEnterpriseNode                                | ken         | Enumerate all enterprise nodes
| Get-KeeperEnterpriseUser                                | keu         | Enumerate all enterprise users
| Get-KeeperEnterpriseTeam                                | ket         | Enumerate all enterprise teams
| Get-KeeperEnterpriseTeamUser                            | ketu        | Get a list of enterprise users for team
| Add-KeeperEnterpriseTeamMember                          |             | Add a list of enterprise users to a team
| Remove-KeeperEnterpriseTeamMember                       |             | Remove a list of enterprise users from a team
| New-KeeperEnterpriseNode                                | kena        | Create Node
| Edit-KeeperEnterpriseNode                               | kenu        | Update Node (rename, move, or enable node isolation)
| Remove-KeeperEnterpriseNode                             | kend        | Delete Enterprise Node
| Set-KeeperEnterpriseNodeCustomInvitation                |             | Set custom invitation email template for an Enterprise Node
| Get-KeeperEnterpriseNodeCustomInvitation                |             | Get custom invitation email template for an Enterprise Node
| Set-KeeperEnterpriseNodeCustomLogo                      |             | Upload custom logo for an Enterprise Node
| Add-KeeperEnterpriseUser                                | invite-user | Invite User to Enterprise
| Invoke-ResendKeeperEnterpriseInvite                     |             | Resend enterprise invitation email to a user
| New-KeeperEnterpriseTeam                                | keta        | Create Team
| Lock-KeeperEnterpriseUser                               | lock-user   | Lock Enterprise User
| Unlock-KeeperEnterpriseUser                             | unlock-user | Unlock Enterprise User
| Move-KeeperEnterpriseUser                               |transfer-user| Transfer user account to another user
| Remove-KeeperEnterpriseUser                             | delete-user | Delete Enterprise User
| Set-KeeperEnterpriseUserMasterPasswordExpire            |             | Expire master password for enterprise user
| Get-KeeperEnterpriseRole                                | ker         | Enumerate all enterprise roles
| Get-KeeperEnterpriseRoleUsers                           | keru        | Get a list of enterprise users for role
| Get-KeeperEnterpriseRoleTeams                           | kert        | Get a list of enterprise teams for role 
| Get-KeeperEnterpriseAdminRole                           | kerap       | Enumerate all enterprise role admin permissions
| Set-KeeperEnterpriseRole                                | kers        | Update Enterprise Role properties (NewUserInherit, VisibleBelow, DisplayName)
| New-KeeperEnterpriseRole                                | keradd      | Create a new enterprise role in the Keeper Enterprise
| Remove-KeeperEnterpriseRole                             | kerdel      | Delete an enterprise role from the Keeper Enterprise
| Grant-KeeperEnterpriseRoleToUser                        | kerua       | Add a user to an Enterprise Role
| Revoke-KeeperEnterpriseRoleFromUser                     | kerur       | Remove a user from an Enterprise Role
| Grant-KeeperEnterpriseRoleToTeam                        | kerta       | Add a team to an Enterprise Role
| Revoke-KeeperEnterpriseRoleFromTeam                     | kertr       | Remove a team from an Enterprise Role
| Add-KeeperEnterpriseRoleManagedNode                     |             | Add a managed node to an Enterprise Role
| Update-KeeperEnterpriseRoleManagedNode                  |             | Update managed node settings for an Enterprise Role
| Remove-KeeperEnterpriseRoleManagedNode                  |             | Remove a managed node from an Enterprise Role
| Add-KeeperEnterpriseRolePrivilege                       |             | Add privileges to a managed node for an Enterprise Role
| Remove-KeeperEnterpriseRolePrivilege                    |             | Remove privileges from a managed node for an Enterprise Role
| Add-KeeperEnterpriseRoleEnforcement                     |             | Add enforcement policies to an Enterprise Role
| Update-KeeperEnterpriseRoleEnforcement                  |             | Update enforcement policies for an Enterprise Role
| Remove-KeeperEnterpriseRoleEnforcement                  |             | Remove enforcement policies from an Enterprise Role
| Switch-KeeperMC                                         |switch-to-mc | Switch to Managed Company 
| Switch-KeeperMSP                                        |switch-to-msp| Switch back to MSP
| Get-KeeperManagedCompany                                | kmc         | Enumerate all enterprise managed companies
| New-KeeperManagedCompany                                | kamc        | Create Managed Company
| Remove-KeeperManagedCompany                             | krmc        | Remove Managed Company
| Edit-KeeperManagedCompany                               | kemc        | Edit Managed Company
| Get-MspBillingReport                                    |             | Run MSP Billing Report
| Get-KeeperNodeName                                      |             | Return Name of current Enterprise Node
| Get-KeeperRoleName                                      |             | Get Display Name of Enterprise Role

### Device Approval Cmdlets
| Cmdlet name                                             | Alias            | Description
|---------------------------------------------------------|------------------|----------------------------
| Get-PendingKeeperDeviceApproval                         |             | List pending device approval requests with details (email, device ID, device name, client version, IP address). Supports table, CSV, and JSON output formats
| Approve-KeeperDevice                                    |             | Approve pending device requests by device ID (partial match) or user email. Supports -TrustedIp to filter by trusted IP addresses
| Deny-KeeperDevice                                       |             | Deny pending device requests by device ID (partial match) or user email

### BreachWatch Cmdlets
| Cmdlet name                                             | Alias            | Description
|---------------------------------------------------------|------------------|----------------------------
| Get-KeeperBreachWatchList                               | kbw         | List passwords which are breached based on breachwatch
| Test-PasswordAgainstBreachWatch                         | kbwp        | check a given password against breachwatch passwords
| Set-KeeperBreachWatchRecordIgnore                       | kbwi        | Ignore a given record from breachwatch alerts
| Get-KeeperIgnoredBreachWatchRecords                     | kbwig       | List ignored breachwatch records

### Secret Manager Cmdlets
| Cmdlet name                                             | Alias            | Description
|---------------------------------------------------------|------------------|----------------------------
| Get-KeeperSecretManagerApp                              | ksm         | Enumerate all Keeper Secret Manager Applications
| Add-KeeperSecretManagerApp                              | ksm-create  | Add a Keeper Secret Manager Application
| Remove-KeeperSecretManagerApp                           | ksm-delete  | Delete a Keeper Secret Manager Application
| Grant-KeeperSecretManagerFolderAccess                   | ksm-share   | Add a shared folder to KSM Application
| Revoke-KeeperSecretManagerFolderAccess                  | ksm-unshare | Remove a Shared Folder from KSM Application
| Add-KeeperSecretManagerClient                           |ksm-addclient| Add a client/device to KSM Application
| Remove-KeeperSecretManagerClient                        | ksm-rmclient| Remove a client/device from KSM Application
| Grant-KeeperAppAccess                                   |             | Grant Keeper Secret Manager Application Access to a user
| Revoke-KeeperAppAccess                                  |             | Revoke Keeper Secret Manager Application Access from a user


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

25. Set custom invitation template for enterprise node
    ```
    PS > Set-KeeperEnterpriseNodeCustomInvitation -Node "Sales" -JsonFilePath "C:\invitation.json"
    ```

26. Get custom invitation template for enterprise node
    ```
    PS > Get-KeeperEnterpriseNodeCustomInvitation -Node "Sales"
    ```

27. Set custom logo for enterprise node
    ```
    PS > Set-KeeperEnterpriseNodeCustomLogo -Node "Sales" -LogoFilePath "C:\logo.png"
    ```

28. Permanently delete all records in trash
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
