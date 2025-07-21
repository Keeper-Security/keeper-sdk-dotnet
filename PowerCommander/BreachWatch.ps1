#requires -Version 5.1

function Get-KeeperBreachWatchList {
    <#
    .SYNOPSIS
    Lists Keeper records flagged by BreachWatch as Weak or Breached.

    .DESCRIPTION
    Retrieves Keeper records in your vault that have been identified by BreachWatch as having weak or breached passwords.
    You can filter to only show records you own, include all records, and display results with numbering.

    .PARAMETER OwnedOnly
    Show only records owned by you.

    .PARAMETER All
    Show all BreachWatch-flagged records, even if there are more than 32 (default output is limited for readability).

    .PARAMETER Numbered
    Display a serial number column in the output.

   .EXAMPLE
    Get-KeeperBreachWatchList
    Lists up to 32 records in your vault flagged as Weak or Breached by BreachWatch.

    .EXAMPLE
    Get-KeeperBreachWatchList -OwnedOnly
    Lists only the records you own that are flagged by BreachWatch.

    .EXAMPLE
    Get-KeeperBreachWatchList -All -Numbered
    Lists all BreachWatch-flagged records with a serial number column.

    .NOTES
    This function helps you quickly identify and review records in your Keeper vault that require attention due to password weaknesses or breaches.
    #>
    [CmdletBinding()]
    param(
        [Parameter()][Switch]$OwnedOnly,
        [Parameter()][Switch]$All,
        [Parameter()][Switch]$Numbered,
        [Parameter()][string]$VaultContextVar = "Global:KeeperVaultContext"
    )

    [KeeperSecurity.Vault.VaultOnline]$vault = getVault

    $recordUids = $vault.BreachWatchRecords() |
        Where-Object { $_.Status -in @("Weak", "Breached") } |
        Select-Object -ExpandProperty RecordUid

    $records = $vault.KeeperRecords |
        Where-Object {
            $recordUids -contains $_.Uid -and
            (-not $OwnedOnly -or $_.Owner)
        }

    if ($records.Count -gt 0) {
        $table = New-Object System.Collections.Generic.List[object]
        $index = 1

        foreach ($r in $records | Sort-Object Title) {
            $row = if ($Numbered) {
                [PSCustomObject]@{
                    "S.No"       = $index++
                    "Record UID" = $r.Uid
                    "Title"      = $r.Title
                    "Description"= [KeeperSecurity.Utils.RecordTypesUtils]::KeeperRecordPublicInformation($r)
                }
            } else {
                [PSCustomObject]@{
                    "Record UID" = $r.Uid
                    "Title"      = $r.Title
                    "Description"= [KeeperSecurity.Utils.RecordTypesUtils]::KeeperRecordPublicInformation($r)
                }
            }
            $table.Add($row)
        }

        $total = $table.Count
        if (-not $All.IsPresent -and $total -gt 32) {
            $table = $table[0..29]
        }

        $table | Format-Table -AutoSize

        if ($table.Count -lt $total) {
            Write-Host ""
            Write-Host "$($total - $table.Count) records skipped."
        }
    } else {
        Write-Host "No breached records detected"
    }

    $scannedUids = $vault.BreachWatchRecords() | Select-Object -ExpandProperty RecordUid
    $notScanned = $vault.KeeperRecords |
        Where-Object { $_.Owner -and ($scannedUids -notcontains $_.Uid) -and $_.GetType() -ne [KeeperSecurity.Vault.ApplicationRecord] }

    $hasPasswordsToScan = $false
    foreach ($record in $notScanned) {
        $loadedRecord = $null
        if ($vault.TryLoadKeeperRecord($record.Uid, [ref]$loadedRecord)) {
            $pw = Get-KeeperRecordPassword -Record $loadedRecord -Silent
            if ($pw) {
                $hasPasswordsToScan = $true
                break
            }
        }
    }

    if ($hasPasswordsToScan) {
        Write-Host "`nSome passwords in your vault have not been scanned.`nUse `"breachwatch scan`" to check against the Dark Web database."
    }
}

function Test-PasswordAgainstBreachWatch {
    <#
    .SYNOPSIS
    Checks passwords against the BreachWatch database for breaches.

    .DESCRIPTION
    Tests one or more passwords against Keeper's BreachWatch database to determine if they have been compromised 
    in known data breaches. Passwords can be provided as parameters or entered securely via prompt.

    .PARAMETER Passwords
    One or more passwords (as SecureString) to check. If not provided, you will be prompted to enter a password securely.

    .PARAMETER ShowPassword
    Display the actual password in the results instead of masking it with asterisks.

    .EXAMPLE
    Test-PasswordAgainstBreachWatch
    Prompts for a password securely and checks it against the BreachWatch database.

    .EXAMPLE
    $pwd1 = ConvertTo-SecureString "password123" -AsPlainText -Force
    Test-PasswordAgainstBreachWatch -Passwords $pwd1
    Checks the specified password against the BreachWatch database.

    .EXAMPLE
    $pwd = Read-Host "Enter password" -AsSecureString
    Test-PasswordAgainstBreachWatch -Passwords $pwd -ShowPassword
    Prompts for a password securely and displays the actual password in results.

    .NOTES
    This function requires an active Keeper vault session and a BreachWatch-enabled Enterprise account.
    Passwords are processed securely and are not stored or logged.
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true)]
        [SecureString[]]$Passwords,
        
        [Parameter()]
        [Switch]$ShowPassword,
        
        [Parameter()]
        [string]$VaultContextVar = "Global:KeeperVaultContext"
    )

    begin {
        [KeeperSecurity.Vault.VaultOnline]$vault = getVault
        $passwordList = New-Object System.Collections.Generic.List[string]
    }

    process {
        if ($Passwords) {
            foreach ($secPwd in $Passwords) {
                if ($null -ne $secPwd -and $secPwd.Length -gt 0) {
                    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secPwd)
                    try {
                        $password = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
                        if (-not [string]::IsNullOrEmpty($password)) {
                            $passwordList.Add($password)
                        }
                    }
                    finally {
                        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
                    }
                }
            }
        }
    }

    end {
        if ($vault.Auth.AuthContext.License.AccountType -ne 2) {
            Write-Host "BreachWatch is not available for this account type."
            Write-Host "BreachWatch requires an Enterprise license."
            return
        }

        if ($passwordList.Count -eq 0) {
            $securePassword = Read-Host "Password to Check" -AsSecureString
            if ($null -eq $securePassword -or $securePassword.Length -eq 0) {
                return
            }
            
            $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
            try {
                $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
                if (-not [string]::IsNullOrEmpty($plainPassword)) {
                    $passwordList.Add($plainPassword)
                }
            }
            finally {
                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
            }
        }

        try {
            $initTask = [KeeperSecurity.BreachWatch.BreachWatch]::InitializeBreachWatch($vault.Auth)
            $initTask.Wait()

            if ([KeeperSecurity.BreachWatch.BreachWatch]::PasswordToken.Length -eq 0) {
                return
            }

            Write-Host "Scanning $($passwordList.Count) password(s)..."

            $passwordEntries = [System.Collections.Generic.List[ValueTuple[string, byte[]]]]::new()
            
            foreach ($password in $passwordList) {
                $tuple = [ValueTuple[string, byte[]]]::new($password, $null)
                $passwordEntries.Add($tuple)
            }
            
            $cancellationToken = [System.Threading.CancellationToken]::None
            $tasks = [KeeperSecurity.BreachWatch.BreachWatch]::ScanPasswordsAsync($passwordEntries, $cancellationToken)
            $tasks.Wait()
            $results = $tasks.Result
            $euids = New-Object System.Collections.Generic.List[byte[]]

            Write-Host "Processing $($results.Count) result(s)..."

            foreach ($result in $results) {
                $password = $result.Item1
                $status = $result.Item2

                if ($null -ne $status.Euid -and -not $status.Euid.IsEmpty) {
                    $euids.Add($status.Euid.ToByteArray())
                }

                $displayPassword = if ($ShowPassword) { $password } else { "*" * $password.Length }
                $statusText = if ($status.BreachDetected) { "WEAK" } else { "GOOD" }
                $score = [KeeperSecurity.BreachWatch.PasswordUtils]::PasswordScore($password)
                
                $strengthText = switch ($score) {
                    { $_ -lt 40 } { "Very Weak" }
                    { $_ -lt 60 } { "Weak" }
                    { $_ -lt 80 } { "Fair" }
                    { $_ -lt 90 } { "Good" }
                    { $_ -ge 90 } { "Strong" }
                }
                
                Write-Host ("{0,16}: {1} | Strength: {2} (Score: {3})" -f $displayPassword, $statusText, $strengthText, $score)
            }

            if ($euids.Count -gt 0) {
                $deleteTask = [KeeperSecurity.BreachWatch.BreachWatch]::DeleteEuids($euids)
                $deleteTask.Wait()
            }
        }
        catch [KeeperSecurity.BreachWatch.BreachWatchException] {
            $ex = $_.Exception
            if ($ex.Message.Contains("Invalid payload")) {
                Write-Host "BreachWatch Invalid Payload Error: $($ex.Message)"
                Write-Host ""
                Write-Host "Attempting to re-initialize BreachWatch tokens..."
                
                try {
                    $reinitTask = [KeeperSecurity.BreachWatch.BreachWatch]::ReInitializeBreachWatch($vault.Auth)
                    $reinitTask.Wait()
                    Write-Host "BreachWatch tokens re-initialized. Please try the command again."
                }
                catch {
                    Write-Host "Failed to re-initialize BreachWatch tokens: $($_.Exception.Message)"
                    Write-Host "This may indicate an account permissions issue or temporary server problem."
                }
            }
            else {
                Write-Host "BreachWatch error: $($ex.Message)"
            }
        }
        catch {
            Write-Host "Error scanning passwords: $($_.Exception.Message)"
            Write-Host "Exception type: $($_.Exception.GetType().FullName)"
            if ($_.Exception.InnerException) {
                Write-Host "Inner error: $($_.Exception.InnerException.Message)"
                Write-Host "Inner exception type: $($_.Exception.InnerException.GetType().FullName)"
            }
        }
    }
}

Set-Alias -Name kbw -Value Get-KeeperBreachWatchList
Set-Alias -Name kbwp -Value Test-PasswordAgainstBreachWatch
