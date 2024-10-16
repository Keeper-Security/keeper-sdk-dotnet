### Reference Keeper Commander Powershell module
To install PowerCommander from PowerShell Gallery
```
Install-Module -Name PowerCommander
```

To run the PowerCommander module from the source copy PowerCommander\ directory to 
* `%USERPROFILE%\Documents\WindowsPowerShell\Modules` Per User
* `C:\Program Files\WindowsPowerShell\Modules` All users

### Cmdlets
| Cmdlet name                            | Alias       | Description
|----------------------------------------|-------------|----------------------------
| Connect-Keeper                         | kc          | Login to Keeper server
| Sync-Keeper                            | ks          | Sync with Keeper server 
| Disconnect-Keeper                      |             | Logout and clear the data
| Get-KeeperLocation                     | kpwd        | Print current Keeper folder
| Set-KeeperLocation                     | kcd         | Change Keeper folder
| Get-KeeperChildItem                    | kdir        | Display subfolder and record names in the current Keeper folder
| Get-KeeperObject                       | ko          | Get Keeper object by Uid
| Get-KeeperRecord                       | kr          | Enumerate all records
| Get-KeeperSharedFolder                 | ksf         | Enumerate all shared folders
| Add-KeeperRecord                       | kadd        | Add/Modify Keeper record
| Get-KeeperRecordType                   | krti        | Get Record Type Information
| Remove-KeeperRecord                    | kdel        | Delete Keeper record
| Move-RecordToFolder                    | kmv         | Move records to Keeper folder
| Add-KeeperFolder                       | kmkdir      | Create Keeper folder
| Remove-KeeperFolder                    | krmdir      | Remove Keeper folder
| Copy-KeeperToClipboard                 | kcc         | Copy record password to clipboard
| Show-TwoFactorCode                     | 2fa         | Display Two Factor Code 
| Copy-KeeperFileAttachment              | kda         | Download file attachments 
| Copy-KeeperFileAttachmentToStream      |             | Download file attachement to stream
| Copy-FileToKeeperRecord                |             | Upload file attachment to a record
| Get-KeeperInformation                  | kwhoami     | Print account license information <sup style="color:red">(new)</sup>
| Get-KeeperDeviceSettings               |             | Print the current device settings <sup style="color:red">(new)</sup>
| Set-KeeperDeviceSettings               | this-device | Modifies the current device settings <sup style="color:red">(new)</sup>


### Sharing Cmdlets
| Cmdlet name                            | Alias       | Description
|----------------------------------------|-------------|----------------------------
| Show-KeeperRecordShare                 | kshrsh      | Show a record sharing information
| Grant-KeeperRecordAccess               | kshr        | Share a record with user
| Revoke-KeeperRecordAccess              | kushr       | Remove record share from user
| Move-KeeperRecordOwnership             | ktr         | Transfer record ownership to user
| Grant-KeeperSharedFolderAccess         | kshf        | Add a user or team to a shared folder
| Revoke-KeeperSharedFolderAccess        | kushf       | Remove a user or team from a shared folder
| Get-KeeperAvailableTeam                | kat         | Get available teams
| Get-KeeperOneTimeShare                 | kotsg       | Get One-Time Shares for a record
| New-KeeperOneTimeShare                 | kotsn       | Create One-Time Share
| Remove-KeeperOneTimeShare              | kotsr       | Remove One-Time Share

### Enterprise Cmdlets
| Cmdlet name                            | Alias       | Description
|----------------------------------------|-------------|----------------------------
| Sync-KeeperEnterprise                  | ked         | Sync Keeper enterprise information
| Get-KeeperEnterpriseNode               | ken         | Enumerate all enterprise nodes
| Get-KeeperEnterpriseUser               | keu         | Enumerate all enterprise users
| Get-KeeperEnterpriseTeam               | ket         | Enumerate all enterprise teams
| Get-KeeperEnterpriseTeamUser           | ketu        | Get a list of enterprise users for team
| New-KeeperEnterpriseNode               | kena        | Create Node <sup style="color:red">(new)</sup>
| Add-KeeperEnterpriseUser               | invite-user | Invite User to Enterprise <sup style="color:red">(new)</sup>
| Lock-KeeperEnterpriseUser              | lock-user   | Lock Enterprise User
| Unlock-KeeperEnterpriseUser            | unlock-user | Unlock Enterprise User
| Move-KeeperEnterpriseUser              |transfer-user| Transfer user account to another user
| Remove-KeeperEnterpriseUser            | delete-user | Delete Enterprise User
| Get-KeeperEnterpriseRole               | ker         | Enumerate all enterprise roles <sup style="color:red">(new)</sup>
| Get-KeeperEnterpriseRoleUsers          | keru        | Get a list of enterprise users for role <sup style="color:red">(new)</sup>
| Get-KeeperEnterpriseRoleTeams          | kert        | Get a list of enterprise teams for role <sup style="color:red">(new)</sup>
| Get-KeeperEnterpriseAdminRole          | kerap       | Enumerate all enterprise role admin permissions <sup style="color:red">(new)</sup>
| Get-KeeperMspLicenses                  | msp-license | Return MSP licenses
| Switch-KeeperMC                        |switch-to-mc | Switch to Managed Company <sup style="color:red">(new)</sup>
| Switch-KeeperMSP                       |switch-to-msp| Switch back to MSP <sup style="color:red">(new)</sup>
| Get-KeeperManagedCompany               | kmc         | Enumerate all enterprise managed companies
| New-KeeperManagedCompany               | kamc        | Create Managed Company
| Remove-KeeperManagedCompany            | krmc        | Remove Managed Company
| Edit-KeeperManagedCompany              | kemc        | Edit Managed Company
| Get-MspBillingReport                   |             | Run MSP Billing Report

### Secret Manager Cmdlets
| Cmdlet name                            | Alias       | Description
|----------------------------------------|-------------|----------------------------
| Get-KeeperSecretManagerApp             | ksm         | Enumerate all Keeper Secret Manager Applications
| Add-KeeperSecretManagerApp             | ksm-create  | Add a Keeper Secret Manager Application
| Grant-KeeperSecretManagerFolderAccess  | ksm-share   | Add a shared folder to KSM Application
| Revoke-KeeperSecretManagerFolderAccess | ksm-unshare | Remove a Shared Folder from KSM Application
| Add-KeeperSecretManagerClient          |ksm-addclient| Add a client/device to KSM Application
| Remove-KeeperSecretManagerClient       | ksm-rmclient| Remove a client/device from KSM Application


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

8. List all enterprise users
    ```
    PS > Get-KeeperEnterpriseUser
    ```

9. Create a new Managed Company
    ```
    PS> New-KeeperManagedCompany -Name "Company Name" -PlanId enterprisePlus -Allocated 5
    ```

10. Switch to a new Managed Company
    ```
    PS> switch-to-mc "Company Name"
    ```