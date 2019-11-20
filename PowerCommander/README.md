### Reference Keeper Commander Powershell module

To install the PowerCommander module copy PowerCommander\ directory to 
* `%USERPROFILE%\WindowsPowerShell\Modules` Per User
* `C:\Program Files\WindowsPowerShell\Modules` All users

### Cmdlets

| Cmdlet name             | Alias | Description
|-------------------------|-------|----------------------------
| Connect-Keeper          | kc    | Login to Keeper server
| Sync-Keeper             | ks    | Sync with Keeper server 
| Disconnect-Keeper       |       | Logout and clear the data
| Get-KeeperLocation      | kpwd  | Print current Keeper folder
| Set-KeeperLocation      | kcd   | Change Keeper folder
| Get-KeeperChildItems    | kdir  | Display subfolder and record names in the current Keeper folder
| Get-KeeperRecords       | kr    | Enumerate all records
| Copy-KeeperToClipboard  | kcc   | Copy record password to clipboard
| Show-TwoFactorCode      | 2fa   | Display Two Factor Code 

## Examples
1. Connect To Keeper Account
`PS > Connect-Keeper
     Keeper Username: email_address@company.com
        ... Password:
`
2. List the content of Keeper root folder
`PS > kdir

    Vault Folder: \


Mode    UID                      Name
----    ---                      ----
f-----  b3TMAYfOWJqNxeLjlA6v_g   dasdasd
f----S  BvHeHGkdRJfhGaRcI-J5Ww   shared
-r-AO-  5qx_urh2EsrL0wBdi34nFw   Web
-r---S  ktY3jEBqwFDi9UYZSxmIpw   Control
` 
f - folder
r - record
S - shared
A - file attachments
O - owner

3. Show Two Factor Code for the records in the current Keeper folder
`PS > kdir -ObjectType Record | Show-TwoFactorCode`

4. Show Two Factor Code for all record in the Vault.
`PS > kr|2fa`  where 
`kr` is alias for `Get-KeeperRecords` and
`2fa` is alias for `Show-TwoFactorCode`

5. Copy record password to clipboard
`PS > 'contro' | kcc` where 
`contro` is a substring of record title. See example #2 last entry of `kdir` output
`kcc` is alias for `Copy-KeeperToClipboard`