# PowerShell Script example

## Example to retrieve and modify password of the record

```PowerShell
#  Connect to Keeper and Login. (see note on Persistent Login below)
kc

# Retrieve all record objects and store them into $records variable
$records = kr

# Print values of the records
$records

# create variable of a record title to search for
$titleToSearch = "MSSQL READ ONLY USER"

# Find a record by it's title and store it to the variable 
$foundRecord = $records | where Title -EQ $titleToSearch


# Modify password of the record
Add-KeeperRecord -UpdateOnly -Title foundRecord.Title -Password "NEW PASSWORD"

```

Configure Peristent Login (to run script silently and don't ask for credentials on each run)

1. Download .NET version of Commander from [latest release](https://github.com/Keeper-Security/keeper-sdk-dotnet/releases)

2. Using Command Propmpt run `Commander.exe` to login to Keeper

3. Enable peristent login in this account by running following Commander commands:
    
    a. `this-device register` - Register key of this device
    
    b. `this-device ip_disable_auto_approve off` - Enable IP Auto Approval
    
    c. `this-device persistent_login on` - Enable Peristent Login

Once above steps executed, Commander will create `C:\Users\[USER]\Documents\.keeper\config.json` configuration file.

>_NOTE: Keep in mind that Persistent Login will stop working once the same user logins somewhere else._
>      
>_To enable Persistent Login again, just perform step #2, which will update config.json file with new session code (aka clone code)_

## Configure Machine to run Commander PowerShell commands

1. One-time: Prepare PowerShell to make sure it can execute Powershell Scripts that were just downloaded.
   
   Run below command in a PowerShell as Administrator (All consequent commands should be run as a regular user)

   ```PowerShell
   Set-ExecutionPolicy RemoteSigned
   ```

2. Download or clone .Net and PowerShell SDK from [GitHub](https://github.com/Keeper-Security/keeper-sdk-dotnet)
3. Create directory for PowerShell modules that will be owned by the user:
   ```PowerShell
   $path = "C:\Users\[USER]\Documents\WindowsPowerShell\Modules"
    If(!(Test-Path $path))
    {
        New-Item -ItemType Directory -Force -Path $path
    }
    ```
4. Copy PowerCommander that was cloned from GitHub to the PowerShell modules folder:

    ```PowerShell
    Copy-Item -Path "[Clonned keeper-sdk-dotnet folder]\PowerCommander" -Destination "C:\Users\[USER]\Documents\WindowsPowerShell\Modules" -Recurse
    ```

5. Unblock .dll and script files to being able to execute on machine:

    ```PowerShell
    dir -Path "C:\Users\[USER]\Source\keeper-sdk-dotnet\PowerCommander" -Recurse | Unblock-File
    ```