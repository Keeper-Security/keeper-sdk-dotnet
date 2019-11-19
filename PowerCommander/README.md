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
| Get-KeeperLocation      | kpwd  | 
| Set-KeeperLocation      | kcd   |
| Get-KeeperChildItems    | kdir  |
| Get-KeeperObject        | ko    |
| Get-KeeperRecords       | kr    | Enumerate all records
| Copy-KeeperToClipboard  | kcc   | Copy record password to clipboard