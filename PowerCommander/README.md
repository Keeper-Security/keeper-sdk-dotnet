### Reference Keeper Commander Powershell module

To install the PowerCommander module copy PowerCommander\ directory to 
* `%USERPROFILE%\Documents\WindowsPowerShell\Modules` Per User
* `C:\Program Files\WindowsPowerShell\Modules` All users

### Cmdlets

| Cmdlet name               | Alias  | Description
|---------------------------|--------|----------------------------
| Connect-Keeper            | kc     | Login to Keeper server
| Sync-Keeper               | ks     | Sync with Keeper server 
| Disconnect-Keeper         |        | Logout and clear the data
| Get-KeeperLocation        | kpwd   | Print current Keeper folder
| Set-KeeperLocation        | kcd    | Change Keeper folder
| Get-KeeperChildItems      | kdir   | Display subfolder and record names in the current Keeper folder
| Get-KeeperRecords         | kr     | Enumerate all records
| Get-KeeperSharedFolders   | ksf    | Enumerate all shared folders
| Add-KeeperRecord          | kadd   | Add/Modify Keeper record
| Remove-KeeperRecord       | kdel   | Delete Keeper record
| Add-KeeperFolder          | kmkdir | Create Keeper Folder
| Remove-KeeperFolder       | krmdir | Remove Keeper Folder
| Move-RecordToFolder       | kmv    | Move owned record to Keeper folder
| Copy-KeeperToClipboard    | kcc    | Copy record password to clipboard
| Show-TwoFactorCode        | 2fa    | Display Two Factor Code 


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
