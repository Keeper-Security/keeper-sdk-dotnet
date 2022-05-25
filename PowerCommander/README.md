### Reference Keeper Commander Powershell module

To install the PowerCommander module copy PowerCommander\ directory to 
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
| Get-KeeperChildItems                   | kdir        | Display subfolder and record names in the current Keeper folder
| Get-KeeperObject                       | ko          | Get Keeper object by Uid
| Get-KeeperRecords                      | kr          | Enumerate all records
| Get-KeeperSharedFolders                | ksf         | Enumerate all shared folders
| Add-KeeperRecord                       | kadd        | Add/Modify Keeper record
| Remove-KeeperRecord                    | kdel        | Delete Keeper record
| Move-RecordToFolder                    | kmv         | Move records to Keeper folder
| Add-KeeperFolder                       | kmkdir      | Create Keeper folder
| Remove-KeeperFolder                    | krmdir      | Remove Keeper folder
| Copy-KeeperToClipboard                 | kcc         | Copy record password to clipboard
| Show-TwoFactorCode                     | 2fa         | Display Two Factor Code 

### Sharing Cmdlets
| Cmdlet name                            | Alias       | Description
|----------------------------------------|-------------|----------------------------
| Show-KeeperRecordShares                | kshrsh      | Show a record sharing information
| Grant-KeeperRecordAccess               | kshr        | Share a record with user
| Revoke-KeeperRecordAccess              | kushr       | Remove record share from user
| Grant-KeeperSharedFolderAccess         | kshf        | Add a user or team to a shared foler
| Revoke-KeeperSharedFolderAccess        | kushf       | Remove a user or team from a shared foler

### Enterprise Cmdlets
| Cmdlet name                            | Alias       | Description
|----------------------------------------|-------------|----------------------------
| Sync-KeeperEnterprise                  | ked         | Sync Keeper enterprise information
| Get-KeeperEnterpriseNodes              | ken         | Enumerate all enterprise nodes
| Get-KeeperEnterpriseUsers              | keu         | Enumerate all enterprise users
| Lock-KeeperEnterpriseUser              | lock-user   | Lock Enterprise User
| Unlock-KeeperEnterpriseUser            | unlock-user | Unlock Enterprise User
| Move-KeeperEnterpriseUser              |transfer-user| Transfer user account to another user
| Remove-KeeperEnterpriseUser            | delete-user | Delete Enterprise User
| Get-KeeperMspLicenses                  | msp-license | Return MSP licenses
| Get-KeeperManagedCompanies             | kmc         | Enumerate all enterprise managed companies
| New-KeeperManagedCompany               | kamc        | Create Managed Company
| Remove-KeeperManagedCompany            | krmc        | Remove Managed Company
| Edit-KeeperManagedCompany              | kemc        | Edit Managed Company

### Secret Manager Cmdlets
| Cmdlet name                            | Alias       | Description
|----------------------------------------|-------------|----------------------------
| Get-KeeperSecretManagerApps            | ksm         | Enumerate all Keeper Secret Manager Applications
| New-KeeperSecretManagerApp             | ksm-create  | Create Keeper Secret Manager Application
| Grant-KeeperSecretManagerFolderAccess  | ksm-share   | Add shared folder to KSM Application
| Revoke-KeeperSecretManagerFolderAccess | ksm-unshare | Remove Shared Folder from KSM Application

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
    * `kr` is alias for `Get-KeeperRecords` 
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
    PS > Get-KeeperEnterpriseUsers
    ```

9. Create a new Managed Company
    ```
    PS> New-KeeperManagedCompany -Name "Company Name" -PlanId enterprisePlus -Allocated 5
    ```