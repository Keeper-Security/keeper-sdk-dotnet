#requires -Version 5.1

function Get-KeeperRecord {
    <#
	.Synopsis
	Get Keeper Records

	.Parameter Uid
	Record UID

	.Parameter Filter
	Return matching records only
#>
    [CmdletBinding()]
    [OutputType([KeeperSecurity.Vault.KeeperRecord[]])]
    Param (
        [string] $Uid,
        [string] $Filter
    )

    [KeeperSecurity.Vault.VaultOnline]$vault = getVault
    if ($Uid) {
        [KeeperSecurity.Vault.KeeperRecord] $record = $null
        if ($vault.TryGetKeeperRecord($uid, [ref]$record)) {
            $record
        }
    }
    else {
        foreach ($record in $vault.KeeperRecords) {
            if ($Filter) {
                $match = $($record.Uid, $record.TypeName, $record.Title, $record.Notes) | Select-String $Filter | Select-Object -First 1
                if (-not $match) {
                    continue
                }
            }
            $record
        }
    }
}
New-Alias -Name kr -Value Get-KeeperRecord


function Copy-KeeperToClipboard {
    <#
	.Synopsis
	Copy record field or password to clipboard or output

	.Parameter Record
	Record UID, title, or any object containing property Uid

	.Parameter Field
	Record field to copy. Supports: Login, Password, URL, Notes, or any custom field name. Default is Password.

	.Parameter Output
	Output destination: Clipboard (default), Stdout, StdoutHidden, Variable

	.Parameter Username
	Match login name to help select the correct record when multiple records have the same title

	.Parameter Login
	Copy login field instead of password

	.Parameter Totp
	Copy TOTP code instead of password

	.Parameter CopyUid
	Copy record UID instead of password

	.Parameter Name
	Variable name when Output is set to Variable

	.Parameter Revision
	Use specific record revision from history (1 = previous, 2 = two versions ago, etc.). Default uses current version.
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)] $Record,
        [string] $Field = 'Password',
        [string] [ValidateSet('Clipboard', 'Stdout', 'StdoutHidden', 'Variable')] $Output = 'Clipboard',
        [string] $Username,
        [Alias('l')][switch] $Login,
        [Alias('t')][switch] $Totp,
        [switch] $CopyUid,
        [string] $Name,
        [Alias('r')][int] $Revision = -1
    )
    Process {
        if ($Record -is [Array]) {
            if ($Record.Count -ne 1) {
                Write-Error -Message 'Only one record is expected'
                return
            }
            $Record = $Record[0]
        }

        [KeeperSecurity.Vault.VaultOnline]$vault = getVault

        $uid = $null
        if ($Record -is [String]) {
            $uid = $Record
        }
        elseif ($null -ne $Record.Uid) {
            $uid = $Record.Uid
        }

        function Get-RecordField($r, $fieldName) {
            if ($fieldName -ieq 'notes') {
                if ($r -is [KeeperSecurity.Vault.PasswordRecord]) { return $r.Notes }
                if ($r -is [KeeperSecurity.Vault.TypedRecord]) { return $r.Notes }
                return ""
            }

            if ($r -is [KeeperSecurity.Vault.PasswordRecord]) {
                switch -Regex ($fieldName) {
                    '^login$' { return $r.Login }
                    '^password$' { return $r.Password }
                    '^url$' { return $r.Link }
                    default {
                        $cf = $r.Custom | Where-Object { $_.Name -ieq $fieldName } | Select-Object -First 1
                        if ($cf) { return $cf.Value }
                        return ""
                    }
                }
            }
            if ($r -is [KeeperSecurity.Vault.TypedRecord]) {
                $type = switch -Regex ($fieldName) {
                    '^login$' { 'login' }
                    '^password$' { 'password' }
                    '^url$' { 'url' }
                    default { $fieldName }
                }
                $f = $r.Fields | Where-Object { $_.FieldName -ieq $type -or $_.FieldLabel -ieq $type } | Select-Object -First 1
                if (-not $f) { 
                    $f = $r.Custom | Where-Object { $_.FieldName -ieq $type -or $_.FieldLabel -ieq $type } | Select-Object -First 1 
                }
                if ($f) {
                    $val = $f.ObjectValue
                    if ($val -is [System.Collections.IEnumerable] -and $val -isnot [string]) {
                        return ($val | ForEach-Object { $_.ToString() }) -join ", "
                    }
                    return $val
                }
            }
            return ""
        }

        $found = $false
        if ($uid) {
            [KeeperSecurity.Vault.KeeperRecord] $rec = $null
            if (-not $vault.TryGetKeeperRecord($uid, [ref]$rec)) {
                $allRecords = @($vault.KeeperRecords)
                
                $match = @($allRecords | Where-Object { $_.Title -ieq $uid })

                if ($match.Count -eq 0) {
                    $match = @($allRecords | Where-Object { $_.Title -like "*$uid*" })
                }
                
                if ($Username -and $match.Count -gt 0) {
                    $match = @($match | Where-Object { (Get-RecordField $_ 'Login') -ieq $Username })
                }
                
                if ($match.Count -eq 1) {
                    $rec = $match[0]
                }
                elseif ($match.Count -gt 1) {
                    Write-Warning "Multiple records found for '$uid'. Use -Username or UID."
                    Write-Host ("{0,-30} {1,-30} {2}" -f "Title", "Login", "UID") -ForegroundColor Cyan
                    Write-Host ("{0,-30} {1,-30} {2}" -f "-----", "-----", "---") -ForegroundColor Gray
                    foreach ($m in $match) {
                        Write-Host ("{0,-30} {1,-30} {2}" -f $m.Title, (Get-RecordField $m 'Login'), $m.Uid)
                    }
                    return $null
                }
            }
            if ($rec) {
                $found = $true
                $originalUid = $rec.Uid
                
                if ($Revision -gt 0) {
                    try {
                        $history = $vault.GetRecordHistory($rec.Uid).GetAwaiter().GetResult()
                        if ($null -eq $history -or $Revision -ge $history.Length) {
                            Write-Error "Invalid revision: $Revision (record has $($history.Length - 1) historical revisions, valid range: 1-$($history.Length - 1))"
                            return
                        }
                        $rec = $history[$Revision].KeeperRecord
                    } catch {
                        Write-Error "Failed to get record history: $_"
                        return
                    }
                }
                
                $itemName = $Field
                $value = $null
                
                if ($CopyUid) {
                    $itemName = "UID"
                    $value = $originalUid
                }
                elseif ($Login) {
                    $itemName = "Login"
                    $value = Get-RecordField $rec 'Login'
                }
                elseif ($Totp) {
                    $itemName = "TOTP"
                    $totpUrl = if ($rec -is [KeeperSecurity.Vault.PasswordRecord]) { $rec.Totp }
                               elseif ($rec -is [KeeperSecurity.Vault.TypedRecord]) { Get-RecordField $rec 'oneTimeCode' }
                               else { $null }
                    if ($totpUrl) {
                        try {
                            $totpResult = [KeeperSecurity.Utils.CryptoUtils]::GetTotpCode($totpUrl)
                            if ($totpResult) { $value = $totpResult.Item1 }
                        } catch {
                            Write-Warning "Failed to generate TOTP code: $_"
                        }
                    }
                }
                else {
                    $value = Get-RecordField $rec $Field
                }

                if (-not [string]::IsNullOrWhiteSpace($value)) {
                    switch ($Output) {
                        'Stdout' {
                            $value
                        }
                        'StdoutHidden' {
                            $origFg = [Console]::ForegroundColor
                            $origBg = [Console]::BackgroundColor
                            try {
                                [Console]::ForegroundColor = [ConsoleColor]::Red
                                [Console]::BackgroundColor = [ConsoleColor]::Red
                                Write-Host $value
                            } finally {
                                [Console]::ForegroundColor = $origFg
                                [Console]::BackgroundColor = $origBg
                            }
                        }
                        'Variable' {
                            if (-not $Name) {
                                Write-Error "-Name parameter is required when Output is set to 'Variable'"
                                return
                            }
                            [Environment]::SetEnvironmentVariable($Name, $value)
                            Write-Output "$itemName is set to variable `"$Name`""
                        }
                        default {
                            if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -eq [System.Threading.ApartmentState]::MTA) {
                                $escapedValue = $value -replace "'", "''"
                                powershell -sta -Command "Set-Clipboard -Value '$escapedValue'"
                            }
                            else {
                                Set-Clipboard -Value $value
                            }
                            Write-Output "Copied to clipboard: $itemName for $($rec.Title)"
                        }
                    }
                    
                    if ($itemName -eq 'Password') {
                        try { $vault.AuditLogRecordCopyPassword($originalUid) } catch { }
                    }
                }
                else {
                    Write-Output "Record $($rec.Title) has no $itemName"
                }
            }
        }
        if (-not $found) {
            Write-Error -Message "Cannot find a Keeper record: $Record"
        }
    }
}
New-Alias -Name kcc -Value Copy-KeeperToClipboard
New-Alias -Name find-password -Value Copy-KeeperToClipboard

function Get-KeeperPasswordVisible {
    <#
	.Synopsis
	Show/hide secret fields
#>
    if ($Script:PasswordVisible) {
        $true
    }
    else {
        $false
    }
}

function Set-KeeperPasswordVisible {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseShouldProcessForStateChangingFunctions", "")]
    Param ([switch] $Visible)
    $Script:PasswordVisible = $Visible.IsPresent
}

function Show-TwoFactorCode {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)] $Records
    )

    Begin {
        [KeeperSecurity.Vault.VaultOnline]$vault = getVault
        $totps = @()
    }

    Process {
        foreach ($r in $Records) {
            $uid = $null

            if ($r -is [String]) {
                $uid = $r
            }
            elseif ($null -ne $r.Uid) {
                $uid = $r.Uid
            }
            if ($uid) {
                [KeeperSecurity.Vault.KeeperRecord] $rec = $null
                if ($vault.TryGetKeeperRecord($uid, [ref]$rec)) {
                    if ($rec -is [KeeperSecurity.Vault.PasswordRecord]) {
                        if ($rec.ExtraFields) {
                            foreach ($ef in $rec.ExtraFields) {
                                if ($ef.FieldType -eq 'totp') {
                                    $totps += [PSCustomObject]@{
                                        RecordUid = $rec.Uid
                                        Title     = $rec.Title
                                        TotpData  = $ef.Custom['data']
                                    }
                                }
                            }
                        }
                    }
                    elseif ($rec -is [KeeperSecurity.Vault.TypedRecord]) {
                        $recordTypeField = New-Object KeeperSecurity.Vault.RecordTypeField 'oneTimeCode', $null
                        [KeeperSecurity.Vault.ITypedField]$recordField = $null
                        if ([KeeperSecurity.Vault.VaultDataExtensions]::FindTypedField($rec, $recordTypeField, [ref]$recordField)) {
                            $data = $recordField.TypedValue
                            if ($data) {
                                $totps += [PSCustomObject]@{
                                    RecordUid = $rec.Uid
                                    Title     = $rec.Title
                                    TotpData  = $data
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    End {
        $output = @()
        foreach ($totp in $totps) {
            [Tuple[string, int, int]]$code = [KeeperSecurity.Utils.CryptoUtils]::GetTotpCode($totp.TotpData)
            if ($code) {
                $output += [PSCustomObject]@{
                    PSTypeName  = 'TOTP.Codes'
                    RecordTitle = $totp.Title
                    TOTPCode    = $code.Item1
                    Elapsed     = $code.Item2
                    Left        = $code.Item3 - $code.Item2
                }
            }
        }
        $output | Format-Table
    }
}
New-Alias -Name 2fa -Value Show-TwoFactorCode

function Get-KeeperRecordPassword {
    <#
    .SYNOPSIS
    Gets the password from a Keeper record by name, title, UID, or record object.
    
    .DESCRIPTION
    This function provides a convenient way to extract passwords from Keeper records.
    It accepts either a record object directly, or a string identifier (UID, name, or title)
    and automatically resolves it to extract the password field.
    
    .PARAMETER Record
    The record input. Accepts:
    - KeeperRecord object (PasswordRecord or TypedRecord)
    - String containing record UID, name, or title
    
    .PARAMETER Silent
    Suppresses error and warning messages. Useful for conditional password retrieval.
    
    .OUTPUTS
    String. The actual password value, or $null if not found.
    
    .EXAMPLE
    # Basic usage with record name
    $password = Get-KeeperRecordPassword -Record "Gmail Account"
    
    .EXAMPLE
    # Using record UID
    $password = Get-KeeperRecordPassword -Record "ABC123DEF456GHI789"
    
    .EXAMPLE
    # Using record object
    $record = Get-KeeperRecord -Uid "ABC123"
    $password = Get-KeeperRecordPassword -Record $record
    
    .EXAMPLE
    # Silent mode for conditional retrieval
    $password = Get-KeeperRecordPassword -Record "MightNotExist" -Silent
    if ($password) {
        # Use password...
    }
    
    .EXAMPLE
    # Practical automation example
    $websites = @("Gmail", "Facebook", "Twitter")
    foreach ($site in $websites) {
        $password = Get-KeeperRecordPassword -Record $site -Silent
        if ($password) {
            Write-Host "Retrieved password for $site"
            # Perform authentication...
        }
    }
    
    .NOTES
    This function is designed for programmatic use and always returns the actual password.
    
    Key features:
    - Handles both PasswordRecord and TypedRecord types
    - Flexible input: accepts UIDs, names, titles, or record objects
    - Smart resolution: exact title matches preferred over partial matches
    - Error handling: warnings for multiple matches, errors for missing records
    - Silent mode: suppresses output for conditional logic
    
    For password display visibility control, use the existing Get-KeeperPasswordVisible
    and Set-KeeperPasswordVisible commands which affect other parts of the system.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        $Record,
        
        [Parameter()]
        [switch]$Silent
    )
    
    try {
        [KeeperSecurity.Vault.VaultOnline]$vault = getVault
        [KeeperSecurity.Vault.KeeperRecord]$keeperRecord = $null
        
        # Check if input is already a KeeperRecord object
        if ($Record -is [KeeperSecurity.Vault.KeeperRecord]) {
            $keeperRecord = $Record
        }
        # Otherwise, treat it as a string identifier and resolve it
        elseif ($Record -is [string]) {
            # First try to get record by UID
            if ($vault.TryGetKeeperRecord($Record, [ref]$keeperRecord)) {
                # Found by UID
            }
            else {
                # If UID lookup fails, search by name/title
                $entries = Get-KeeperChildItem -Filter $Record -ObjectType Record
                if ($entries -and $entries.Count -gt 0) {
                    if ($entries.Count -eq 1) {
                        $vault.TryGetKeeperRecord($entries[0].Uid, [ref]$keeperRecord) | Out-Null
                    }
                    else {
                        # Multiple matches found - look for exact title match first
                        $tempRecord = $null
                        foreach ($entry in $entries) {
                            if ($vault.TryGetKeeperRecord($entry.Uid, [ref]$tempRecord)) {
                                if ($tempRecord.Title -eq $Record) {
                                    $keeperRecord = $tempRecord
                                    break
                                }
                            }
                        }
                        # If no exact match, use the first one but warn user
                        if (-not $keeperRecord -and $vault.TryGetKeeperRecord($entries[0].Uid, [ref]$keeperRecord)) {
                            if (-not $Silent) {
                                Write-Warning "Multiple records found matching '$Record'. Using first match: '$($keeperRecord.Title)'"
                            }
                        }
                    }
                }
            }
        }
        else {
            if (-not $Silent) {
                Write-Error "Invalid record parameter. Must be a KeeperRecord object or string identifier." -ErrorAction Stop
            }
            return $null
        }
        
        # Check if we found a record
        if ($null -eq $keeperRecord) {
            if (-not $Silent) {
                Write-Error "Record not found: '$Record'" -ErrorAction Stop
            }
            return $null
        }
        
        # Extract password based on record type
        $password = $null
        if ($keeperRecord -is [KeeperSecurity.Vault.PasswordRecord]) {
            $password = $keeperRecord.Password
        }
        elseif ($keeperRecord -is [KeeperSecurity.Vault.TypedRecord]) {
            $recordField = $keeperRecord.Fields | Where-Object FieldName -eq 'password' | Select-Object -First 1
            if (-not $recordField) {
                $recordField = $keeperRecord.Custom | Where-Object FieldName -eq 'password' | Select-Object -First 1
            }
            if ($recordField) {
                $password = $recordField.ObjectValue
            }
        }
        
        if ($null -eq $password -or $password -eq '') {
            if (-not $Silent) {
                Write-Warning "Record '$($keeperRecord.Title)' does not have a password field or password is empty."
            }
            return $null
        }
        
        # Verbose output
        if (($ShowErrorsPreference -eq 'Continue' -or $VerbosePreference -eq 'Continue') -and -not $Silent) {
            Write-Verbose "Retrieved password from record '$($keeperRecord.Title)'"
        }
        
        return $password
    }
    catch {
        if (-not $Silent) {
            Write-Error "Error retrieving password for record '$Record': $($_.Exception.Message)" -ErrorAction Stop
        }
        return $null
    }
}

$Keeper_RecordTypeNameCompleter = {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    $result = @()
    [KeeperSecurity.Vault.VaultOnline]$vault = $Script:Context.Vault
    if ($vault) {
        $toComplete = $wordToComplete + '*'
        foreach ($rt in $vault.RecordTypes) {
            if ($rt.Name -like $toComplete) {
                $result += $rt.Name
            }
        }
    }
    if ($result.Count -gt 0) {
        return $result
    }
    else {
        return $null
    }

}

function ConvertTo-TimeSpan {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Period
    )
    
    if ([string]::IsNullOrWhiteSpace($Period)) {
        throw "Period cannot be empty"
    }
    
    if ($Period -match '^(\d+)(.*)$') {
        $num = [int]$Matches[1]
        $interval = $Matches[2].ToLower().Trim()
        
        switch ($interval) {
            { $_ -in @("mi", "m", "minutes", "minute") } { 
                return [TimeSpan]::FromMinutes($num) 
            }
            { $_ -in @("h", "hours", "hour") } { 
                return [TimeSpan]::FromHours($num) 
            }
            { $_ -in @("d", "days", "day") } { 
                return [TimeSpan]::FromDays($num) 
            }
            { $_ -in @("mo", "months", "month") } { 
                return [TimeSpan]::FromDays($num * 30) 
            }
            { $_ -in @("y", "years", "year") } { 
                return [TimeSpan]::FromDays($num * 365) 
            }
            default {
                throw "$interval is not allowed as a unit for the timeout value. Valid units are 'years/y, months/mo, days/d, hours/h, minutes/mi/m'."
            }
        }
    }
    else {
        throw "Invalid period format: $Period"
    }
}

function New-SelfDestructShare {
    param(
        [Parameter(Mandatory = $true)]
        [KeeperSecurity.Vault.VaultOnline]$Vault,
        
        [Parameter(Mandatory = $true)]
        [KeeperSecurity.Vault.KeeperRecord]$Record,
        
        [Parameter(Mandatory = $true)]
        [TimeSpan]$ExpireIn
    )
    
    $tr = [KeeperSecurity.Vault.KeeperRecord]$Record
    
    try {
        $clientKey = [KeeperSecurity.Utils.CryptoUtils]::GenerateEncryptionKey()
        $hmac = New-Object System.Security.Cryptography.HMACSHA512 -ArgumentList @(,$clientKey)
        $clientId = $hmac.ComputeHash([System.Text.Encoding]::UTF8.GetBytes("KEEPER_SECRETS_MANAGER_CLIENT_ID"))
        $hmac.Dispose()
        
        $uidBase64 = $tr.Uid.Replace('-', '+').Replace('_', '/')
        switch ($uidBase64.Length % 4) {
            2 { $uidBase64 += '==' }
            3 { $uidBase64 += '=' }
        }
        $uidBytes = [Convert]::FromBase64String($uidBase64)
        
        $clientKeyBase64 = [Convert]::ToBase64String($clientKey)
        $clientKeyBase64Url = $clientKeyBase64.Replace('+', '-').Replace('/', '_').TrimEnd('=')
        
        $rq = New-Object Authentication.AddExternalShareRequest
        $rq.RecordUid = [Google.Protobuf.ByteString]::CopyFrom($uidBytes)
        $rq.ClientId = [Google.Protobuf.ByteString]::CopyFrom($clientId)
        $rq.EncryptedRecordKey = [Google.Protobuf.ByteString]::CopyFrom([KeeperSecurity.Utils.CryptoUtils]::EncryptAesV2($tr.RecordKey, $clientKey))
        $rq.AccessExpireOn = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() + [long]$ExpireIn.TotalMilliseconds
        $rq.IsSelfDestruct = $true
        
        $task = $Vault.Auth.ExecuteAuthRest("vault/external_share_add", $rq)
        $task.GetAwaiter().GetResult()
        
        $builder = New-Object System.UriBuilder $Vault.Auth.Endpoint.Server
        $builder.Path = "/vault/share"
        $builder.Scheme = "https"
        $builder.Port = -1 
        $builder.Fragment = $clientKeyBase64Url
        
        return $builder.ToString()
    }
    catch {
        throw "Failed to create self-destruct external share: $($_.Exception.Message)"
    }
}

function Add-KeeperRecord {
    <#
	.Synopsis
	Creates or Modifies a Keeper record in the current folder.

	.Parameter Uid
	Record UID. If provided the existing record to be updated. Otherwise record is added.

	.Parameter RecordType
	Record Type (if account supports record types).

	.Parameter Title
	Record Title. Mandatory field for added record.

	.Parameter Notes
	Record Notes.

	.Parameter GeneratePassword
	Generate random password.

	.Parameter SelfDestruct
	Time period for self-destruct share URL. The record will be deleted after the specified time. Format: <NUMBER>[m|mi|h|d|mo|y] (e.g., 5m, 2h, 1d)
    Month is considered as 30 days
    year is considered as 365 days

	.Parameter Fields
	A list of record Fields. See DESCRIPTION
    
    .DESCRIPTION
    Record field format [NAME=VALUE] or [-name $value]
    if field starts with `-` then the following parameter contains field value 
    otherwise NAME=VALUE pattern is assumed

	Predefined fields are
	login 			Login Name
	password        Password
	url				Web Address

	Any other name is added to Custom Fields
    
    Typed records only:

    A field has [TYPE.LABEL] format. A TYPE or LABEL can be omitted.
    Field Type        Description            Value Type     Examples
    ===========       ==================     ==========     =====================================
    date              Unix epoch time.       integer        1668639533000 | 03/23/2022
    host              host name / port       object         @{hostName=''; port=''} 
                                                            192.168.1.2:4321
    address           Address                object         @{street1=""; street2=""; city="";
                                                              state=""; zip=""; country=""}
                                                            123 Main St, SmallTown, CA 12345, USA
    phone             Phone                  object         @{region=""; number=""; ext=""; type=""}
                                                            Mobile: US (555)555-1234
    name              Person name            object         @{first=""; middle=""; last=""}
                                                            Doe, John Jr. | Jane Doe
    paymentCard       Payment Card           object         @{cardNumber=""; cardExpirationDate=""; 
                                                              cardSecurityCode=""}
                                                            4111111111111111 04/2026 123
    bankAccount       Bank Account           object         @{accountType=""; routingNumber=""; 
                                                              accountNumber=""}
                                                            Checking: 123456789 987654321
    keyPair           Key Pair               object         @{publicKey=""; privateKey=""}

    oneTimeCode       TOTP URL               string         otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP
    note              Masked multiline text  string         
    multiline         Multiline text         string         
    secret            Masked text            string         
    login             Login                  string                                         
    email             Email                  string         'name@company.com'                                
    password          Password               string         
    url               URL                    string         https://google.com/
    text              Free form text         string         This field type generally has a label

    .EXAMPLE 
    PS> $password = Read-Host -AsSecureString -Prompt "Enter Password"
    PS> Add-KeeperRecord -Title "New Record" login=username -password $password

    .EXAMPLE
    PS> $h = @{hostName='google.com'; port='123'} 
	PS> Add-KeeperRecord -Uid ... -"host.Google Host" $h 

    .EXAMPLE
	PS> Add-KeeperRecord -Uid ... "host.Google Host=google.com:123" 

    .EXAMPLE
    PS> $rsa = [System.Security.Cryptography.RSA]::Create(2048)
    PS> $privateKey = [Convert]::ToBase64String($rsa.ExportPkcs8PrivateKey())
    PS> $publicKey = [Convert]::ToBase64String($rsa.ExportRSAPublicKey())
    PS> $keyPair = @{privateKey=$privateKey; publicKey=$publicKey}
    PS> Add-KeeperRecord -Uid ... -keyPair $keyPair

    .EXAMPLE
    PS> Add-KeeperRecord -Title "Temp Record" -RecordType login login=user@example.com password=secret123 -SelfDestruct 5m
    Creates a record with a 5-minute self-destruct timer and returns a share URL.
#>

    [CmdletBinding(DefaultParameterSetName = 'add')]
    Param (
        [Parameter()] [switch] $GeneratePassword,
        [Parameter(ParameterSetName = 'add')] [string] $RecordType,
        [Parameter(ParameterSetName = 'add')] [string] $Folder,
        [Parameter(ParameterSetName = 'edit', Mandatory = $True)] [string] $Uid,
        [Parameter()] [string] $Title,
        [Parameter()] [string] $Notes,
        [Parameter()] [string] $SelfDestruct,
        [Parameter(ValueFromRemainingArguments = $true)] $Extra
    )

    Begin {
        [KeeperSecurity.Vault.VaultOnline]$vault = getVault
        [KeeperSecurity.Vault.KeeperRecord]$record = $null

        $fields = @{}
        $fieldName = $null
        foreach ($var in $Extra) {
            if ($var -match '^-') {
                $fieldName = $var.Substring(1)
                if ($var -match ':$') {
                    $fieldName = $fieldName.Substring(0, $fieldName.Length - 1)
                }
            }
            elseif ($null -ne $fieldName) {
                $fields[$fieldName] = $var
                $fieldName = $null
            }
            else {
                if ($var -match '^([^=]+)=(.*)?') {
                    $n = $Matches[1].Trim()
                    $v = $Matches[2].Trim()
                    if ($n -and $v) {
                        $fields[$n] = $v
                    }
                }
            }
        }
    }

    Process {
        if ($Uid) {
            if (-not $vault.TryGetKeeperRecord($Uid, [ref]$record)) {
                $objs = Get-KeeperChildItem -ObjectType Record | Where-Object Name -eq $Uid
                if ($objs.Length -gt 1) {
                    $vault.TryGetKeeperRecord($objs[0].Uid, [ref]$record)
                }
            }
            if (-not $record) {
                Write-Error -Message "Record `"$Uid`" not found" -ErrorAction Stop
                return
            }
        }
        else {
            if (!$Title) {
                Write-Error -Message "-Title parameter is required" -ErrorAction Stop
            }
            if (-not $RecordType -or $RecordType -eq 'legacy') {
                $record = New-Object KeeperSecurity.Vault.PasswordRecord
            }
            else {
                $record = New-Object KeeperSecurity.Vault.TypedRecord $RecordType
                [KeeperSecurity.Utils.RecordTypesUtils]::AdjustTypedRecord($vault, $record)
            }
        }
        if ($Title) {
            $record.Title = $Title
        }

        if ($Notes -is [string]) {
            if ($Notes.Length -gt 0 -and $Notes[0] -eq '+') {
                $Notes = $record.Notes + "`n" + $Notes.Substring(1)
            }
            elseif ($Notes -eq '-') {
                $Notes = ''
            }
            $record.Notes = $Notes
        }

        if ($GeneratePassword.IsPresent) {
            $fields['password'] = [Keepersecurity.Utils.CryptoUtils]::GenerateUid()
        }

        foreach ($fieldName in $fields.Keys) {
            $fieldValue = $fields[$fieldName]
            $fieldLabel = ''
            if ($fieldName -match '^([^.]+)(\..+)?$') {
                if ($Matches[1] -and $Matches[2]) {
                    $fieldName = $Matches[1].Trim()
                    $fieldLabel = $Matches[2].Trim().Substring(1)
                }
            }
            if ($fieldName -match '^\$') {
                $fieldName = $fieldName.Substring(1).Trim()
            }
            if ($fieldValue -is [securestring]) {
                $fieldValue = (New-Object PSCredential 'a', $fieldValue).GetNetworkCredential().Password
            }
            if ($record -is [KeeperSecurity.Vault.PasswordRecord]) {
                switch ($fieldName) {
                    'login' { $record.Login = $fieldValue }
                    'password' { $record.Password = $fieldValue }
                    'url' { $record.Link = $fieldValue }
                    Default {
                        if ($fieldLabel) {
                            if ($fieldName -eq 'text') {
                                $fieldName = $fieldLabel
                            }
                            else {
                                $fieldName = "${fieldName}:${fieldLabel}"
                            }
                        }
                        if ($fieldValue) {
                            $record.SetCustomField($fieldName, $fieldValue) | Out-Null
                        }
                        else {
                            $record.DeleteCustomField($fieldName) | Out-Null
                        }
                    }
                }
            }
            elseif ($record -is [KeeperSecurity.Vault.TypedRecord]) {
                if (-not $fieldLabel) {
                    [KeeperSecurity.Vault.RecordField]$recordField = $null
                    if (-not [KeeperSecurity.Vault.RecordTypesConstants]::TryGetRecordField($fieldName, [ref]$recordField)) {
                        $fieldLabel = $fieldName
                        $fieldName = 'text'
                    }
                }
                $recordTypeField = New-Object KeeperSecurity.Vault.RecordTypeField $fieldName, $fieldLabel
                [KeeperSecurity.Vault.ITypedField]$typedField = $null
                if ([KeeperSecurity.Vault.VaultDataExtensions]::FindTypedField($record, $recordTypeField, [ref]$typedField)) {
                }
                else {
                    if ($fieldValue) {
                        $typedField = [KeeperSecurity.Vault.VaultDataExtensions]::CreateTypedField($fieldName, $fieldLabel)
                        if ($typedField) {
                            $record.Custom.Add($typedField)
                        }
                    }
                }
                if ($typedField) {
                    if ($fieldValue) {
                        $typedField.ObjectValue = $fieldValue
                    }
                    else {
                        $typedField.DeleteValueAt(0)
                    }
                }
            }
        }
    }
    End {
        if ($record.Uid) {
            $task = $vault.UpdateRecord($record)
            $task.GetAwaiter().GetResult()
            Write-Host "Record updated: $($record.Uid)"
        }
        else {
            $folderUid = $Script:Context.CurrentFolder
            if ($Folder) {
                $folderNode = resolveKeeperFolder -Identifier $Folder -Vault $vault -SupportPaths
                $folderUid = $folderNode.FolderUid
            }

            $task = $vault.CreateRecord($record, $folderUid)
            $createdRecord = $task.GetAwaiter().GetResult()
            
            if (-not [string]::IsNullOrEmpty($SelfDestruct)) {
                try {
                    $destructTime = ConvertTo-TimeSpan -Period $SelfDestruct
                    $shareUrl = New-SelfDestructShare -Vault $vault -Record $createdRecord -ExpireIn $destructTime
                    Write-Host "Record created with self-destruct enabled ($($destructTime.TotalMinutes) minutes)"
                    Write-Host "Share URL: $shareUrl"
                }
                catch {
                    Write-Error "Failed to create self-destruct share: $($_.Exception.Message)"
                }
            }
            else {
                Write-Host "Record created: $($createdRecord.Uid)"
            }
        }
    }
}
New-Alias -Name kadd -Value Add-KeeperRecord
Register-ArgumentCompleter -CommandName Add-KeeperRecord -ParameterName Folder -ScriptBlock $Keeper_FolderPathRecordCompleter
Register-ArgumentCompleter -CommandName Add-KeeperRecord -ParameterName RecordType -ScriptBlock $Keeper_RecordTypeNameCompleter


function Remove-KeeperRecord {
    <#
	.Synopsis
	Removes Keeper record.

	.Parameter Name
	Folder name or Folder UID
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseShouldProcessForStateChangingFunctions", "")]
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    Param (
        [Parameter(Position = 0, Mandatory = $true)][string] $Name
    )

    [KeeperSecurity.Vault.VaultOnline]$vault = getVault

    $folderUid = $null
    $recordUid = $null
    [KeeperSecurity.Vault.KeeperRecord] $record = $null
    if ($vault.TryGetKeeperRecord($Name, [ref]$record)) {
        $recordUid = $record.Uid
        if (-not $vault.RootFolder.Records.Contains($recordUid)) {
            foreach ($f in $vault.Folders) {
                if ($f.Records.Contains($recordUid)) {
                    $folderUid = $f.FolderUid
                    break
                }
            }
        }
    }
    if (-not $recordUid) {
        $objs = Get-KeeperChildItem -ObjectType Record | Where-Object Name -eq $Name
        if (-not $objs) {
            Write-Error -Message "Record `"$Name`" does not exist"
            return
        }
        if ($objs.Length -gt 1) {
            Write-Error -Message "There are more than one records with name `"$Name`". Use Record UID do delete the correct one."
            return
        }
        $recordUid = $objs[0].Uid
        $folderUid = $Script:Context.CurrentFolder
    }

    $recordPath = New-Object KeeperSecurity.Vault.RecordPath
    $recordPath.RecordUid = $recordUid
    $recordPath.FolderUid = $folderUid
    $task = $vault.DeleteRecords(@($recordPath))
    $task.GetAwaiter().GetResult() | Out-Null
}
New-Alias -Name kdel -Value Remove-KeeperRecord

function Move-RecordToFolder {
    <#
	.Synopsis
	Moves records to Folder.

	.Parameter Record
	Record UID, Path or any object containing property Uid.

	.Parameter Folder
	Folder Name, Path, or UID
#>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]$Records,
        [Parameter(Position = 0, Mandatory = $true)][string]$Folder,
        [Parameter()][switch]$Link
    )

    Begin {
        [KeeperSecurity.Vault.VaultOnline]$vault = getVault
        $folderNode = resolveKeeperFolder -Identifier $Folder -Vault $vault -SupportPaths
        $sourceRecords = @()
    }

    Process {
        foreach ($r in $Records) {
            if ($null -ne $r.Uid) {
                $r = $r.Uid
            }
            [KeeperSecurity.Vault.FolderNode]$folder = $null
            [KeeperSecurity.Vault.KeeperRecord]$record = $null
            if ($vault.TryGetKeeperRecord($r, [ref]$record)) {
                if ($record -is [KeeperSecurity.Vault.PasswordRecord] -or $record -is [KeeperSecurity.Vault.TypedRecord]) {
                    if ($folderNode.FolderUid -and $vault.RootFolder.Records.Contains($record.Uid)) {
                        $folder = $vault.RootFolder
                    }
                    else {
                        foreach ($fol in $vault.Folders) {
                            if ($fol.FolderUid -eq $folderNode.FolderUid) {
                                continue
                            }
                            if ($fol.Records.Contains($record.Uid)) {
                                $folder = $fol
                                break
                            }
                        }
                    }
                }
                else {
                    Write-Error "`$r`" record type is not supported." -ErrorAction Stop
                }
            }
            else {
                [KeeperSecurity.Vault.FolderNode]$fol = $null
                if (-not $vault.TryGetFolder($Script:Context.CurrentFolder, [ref]$fol)) {
                    $fol = $vault.RootFolder
                }

                $comps = splitKeeperPath $r
                $folder, $rest = parseKeeperPath $comps $vault $fol
                if (-not $rest) {
                    Write-Error "`"$r`" should be a record" -ErrorAction Stop
                }
                [KeeperSecurity.Vault.KeeperRecord]$rec = $null
                foreach ($recordUid in $folder.Records) {
                    if ($vault.TryGetKeeperRecord($recordUid, [ref]$rec)) {
                        if ($rec.Title -eq $rest) {
                            if ($rec -is [KeeperSecurity.Vault.PasswordRecord] -or $rec -is [KeeperSecurity.Vault.TypedRecord]) {
                                $record = $rec
                                break
                            }
                        }
                    }
                }
            }

            if (-not $record -or -not $folder) {
                Write-Error "Record `"$r`" cannot be found" -ErrorAction Stop
            }

            $rp = New-Object KeeperSecurity.Vault.RecordPath
            $rp.RecordUid = $record.Uid
            $rp.FolderUid = $folder.FolderUid
            $sourceRecords += $rp
        }
    }
    End {
        if (-not $sourceRecords) {
            Write-Error "There are no records to move" -ErrorAction Stop
        }
        $vault.MoveRecords($sourceRecords, $folderNode.FolderUid, $Link.IsPresent).GetAwaiter().GetResult() | Out-Null
        $vault.ScheduleSyncDown([System.TimeSpan]::FromSeconds(0)).GetAwaiter().GetResult() | Out-Null
    }
}
New-Alias -Name kmv -Value Move-RecordToFolder
Register-ArgumentCompleter -CommandName Move-RecordToFolder -ParameterName Folder -ScriptBlock $Keeper_FolderPathRecordCompleter


function Get-KeeperRecordType {
    <#
	.Synopsis
	Get Record/Field Type Information

    .Parameter ShowFields
	Show Field Types

	.Parameter Name
	Record Type Name
#>

    [CmdletBinding()]
    Param (
        [switch] $ShowFields,
        [Parameter(Position = 0, Mandatory = $false)][string] $Name
    )

    [KeeperSecurity.Vault.VaultOnline]$vault = getVault

    if ($ShowFields.IsPresent) {
        [KeeperSecurity.Vault.RecordTypesConstants]::RecordFields | Where-Object { -not $Name -or $_.Name -eq $Name } | Sort-Object Name
    }
    else {
        $vault.RecordTypes | Where-Object { -not $Name -or $_.Name -eq $Name } | Sort-Object Name
    }
}
New-Alias -Name krti -Value Get-KeeperRecordType

function New-KeeperRecordType {
    <#
    .SYNOPSIS
        Add a new custom Keeper Record Type.

    .DESCRIPTION
        Adds a custom record type to the Vault. Record type definition can be passed as a JSON string or a file reference prefixed with '@'.

    .PARAMETER Data
        Required. Record type definition as a JSON string or file reference (prefix with '@' for file path).

    .EXAMPLE
        New-KeeperRecordType -Data '@("C:\record_type.json")'

    .EXAMPLE
        New-KeeperRecordType -Data '{\"$id\":\"myCustomType_dotnet_test\",\"description\":\"My custom record\",\"fields\":[{\"$ref\":\"login\"},{\"$ref\":\"password\"}]}'

    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)][string] $Data
    )

    [KeeperSecurity.Vault.VaultOnline]$vault = getVault

    if ($Data.StartsWith("@")) {
        $path = $Data.TrimStart("@").Trim('"')
        try {
            $fullPath = [System.IO.Path]::GetFullPath($path)
        }
        catch {
            Write-Error "Invalid file path: $path" -ErrorAction Stop
        }

        if (-not (Test-Path $fullPath)) {
            Write-Error "File not found: $fullPath" -ErrorAction Stop
        }

        $Data = Get-Content $fullPath -Raw
    }

    try {
        $recordTypeId = $vault.AddRecordType($Data).GetAwaiter().GetResult()
        Write-Host "Created Record Type ID: $recordTypeId"
    }
    catch {
        Write-Error "Error adding record type: $($_.Exception.Message)" -ErrorAction Stop
    }
}

function Edit-KeeperRecordType {
    <#
    .SYNOPSIS
        Update an existing custom Keeper Record Type.

    .DESCRIPTION
        Updates a custom record type in the Vault. The updated record type definition is passed as a JSON string or file reference prefixed with '@'. The record type ID to update must be provided separately.

    .PARAMETER RecordTypeId 
        Required. The UID of the record type to update.

    .PARAMETER Data
        Required. Record type definition as a JSON string or file reference (prefix with '@' for file path).

    .EXAMPLE
        Edit-KeeperRecordType -RecordTypeId '22500' -Data '@("C:\record_type_update.json")'

    .EXAMPLE
        Edit-KeeperRecordType -RecordTypeId '22500' -Data '{\"$id\":\"myCustomType_dotnet_test\",\"description\":\"My custom record\",\"fields\":[{\"$ref\":\"login\"},{\"$ref\":\"password\"}]}'
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)][string] $RecordTypeId,
        [Parameter(Mandatory = $true)][string] $Data
    )

    [KeeperSecurity.Vault.VaultOnline]$vault = getVault

    if ($Data.StartsWith("@")) {
        $path = $Data.TrimStart("@").Trim('"')
        try {
            $fullPath = [System.IO.Path]::GetFullPath($path)
        }
        catch {
            Write-Error "Invalid file path: $path" -ErrorAction Stop
        }

        if (-not (Test-Path $fullPath)) {
            Write-Error "File not found: $fullPath" -ErrorAction Stop
        }

        $Data = Get-Content $fullPath -Raw
    }

    try {
       
        $result = $vault.UpdateRecordTypeAsync($RecordTypeId, $Data).GetAwaiter().GetResult()
        Write-Host "Updated Record Type ID: $result"
    }
    catch {
        Write-Error "Error updating record type: $($_.Exception.Message)" -ErrorAction Stop
    }
}

function Remove-KeeperRecordType {
    <#
    .SYNOPSIS
        Delete a custom Keeper Record Type by its ID.

    .DESCRIPTION
        Removes a custom record type from the Vault. Only the Record Type ID is required.

    .PARAMETER RecordTypeId
        Required. The UID of the record type to delete.

    .EXAMPLE
        Remove-KeeperRecordType -RecordTypeId <recordTypeId>
    #>

    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "High")]
    Param (
        [Parameter(Mandatory = $true)][string] $RecordTypeId
    )

    [KeeperSecurity.Vault.VaultOnline]$vault = getVault

    try {
        if ($PSCmdlet.ShouldProcess("RecordTypeId '$RecordTypeId'", "Delete record type")) {
            $result = $vault.DeleteRecordTypeAsync($RecordTypeId).GetAwaiter().GetResult()
            Write-Host "Deleted Record Type ID: $result"
        }
    }
    catch {
        Write-Error "Error deleting record type: $($_.Exception.Message)" -ErrorAction Stop
    }
}

function Test-RecordTypeFile {
    param (
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )

    if (-not (Test-Path $FilePath)) {
        throw "Record type file not found: $FilePath"
    }

    $json = Get-Content $FilePath -Raw | ConvertFrom-Json
    if (-not $json.record_types) {
        throw "Missing 'record_types' array in the file."
    }

    return $json.record_types
}

function Get-ExistingRecordTypes {
    [KeeperSecurity.Vault.VaultOnline]$vault = getVault
    $types = $vault.RecordTypes
    $map = @{}

    foreach ($type in $types) {
        if ($type.Name) {
            $map[$type.Name] = $type
        }
    }

    return $map
}

function ConvertTo-CustomRecordTypeObject {
    param (
        [Parameter(Mandatory = $true)]
        $InputRecordType
    )

    $fields = @()
    foreach ($f in $InputRecordType.fields) {
        $field = @{ '$ref' = $f.'$type' }
        if ($f.label) {
            $field["label"] = $f.label
        }
        if ($f.Required -eq $true) {
            $field["required"] = $true
        }
        $fields += ,$field
    }

    return @{
        '$id' = $InputRecordType.record_type_name
        description = $InputRecordType.description
        categories = $InputRecordType.categories
        fields = $fields
    }
}


function Import-KeeperRecordTypes {
<#
.SYNOPSIS
    Imports custom record types into Keeper from a JSON file.

.DESCRIPTION
    This command reads a JSON file containing custom record type definitions and uploads new record types to the Keeper vault.
    Existing record types (based on name) are skipped. It reports the number of successfully uploaded, skipped, and failed imports.

.PARAMETER FilePath
    The full path to the JSON file containing record type definitions. The file must contain a `record_types` array at the root.

.EXAMPLE
    Import-KeeperRecordTypes -FilePath "C:\configs\custom_record_types.json"

    Loads and uploads custom record types from the specified file.

.EXAMPLE
    Import-KeeperRecordTypes -FilePath "./data/types.json"

    Works with relative paths as well.

.OUTPUTS
    [System.Collections.Generic.List[string]]
    Returns a list of successfully uploaded record type IDs.

.NOTES
    Requires the Add-KeeperRecordType and Get-KeeperRecordTypes functions to be available in the current session.
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0, HelpMessage = "Path to the JSON file containing record types.")]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath
    )

    $uploadedRecordTypeIds = @()
    $existingRecordTypeIds = @()
    $failedRecordTypeIds = @()
    $uploadCount = 0

    try {
        $newRecordTypes = Test-RecordTypeFile -FilePath $FilePath
        $existingTypes = Get-ExistingRecordTypes

        foreach ($recordType in $newRecordTypes) {
            if ($existingTypes.ContainsKey($recordType.record_type_name)) {
                $existingRecordTypeIds += $recordType.record_type_name
                continue
            }

            try {
                $parsed = ConvertTo-CustomRecordTypeObject -InputRecordType $recordType
                $json = $parsed | ConvertTo-Json -Depth 10 -Compress
                $recordTypeId = New-KeeperRecordType -Data $json
                $uploadedRecordTypeIds += $recordTypeId
                $uploadCount++
            }
            catch {
                Write-Warning "Failed to upload record type '$($recordType.record_type_name)': $_"
                $failedRecordTypeIds += $recordType.record_type_name
                continue
            }
        }

        Write-Host "Record types loaded: $uploadCount"
        Write-Host "Existing Record Types (skipped): $($existingRecordTypeIds -join ', ')" 
        Write-Host "Failed Record Types: $($failedRecordTypeIds -join ', ')"
    }
    catch {
        throw "Import failed: $_"
    }

    return $uploadedRecordTypeIds
}

function Export-KeeperRecordTypes {
    <#
    .SYNOPSIS
    Downloads custom record types from Keeper Vault to a JSON file.
    .PARAMETER Source
    The source of record types to export from.
    .PARAMETER FileName
    Optional. The name of the file to write to. Defaults to 'record_types.json'.
    .PARAMETER SSHKeyAsFile
    Optional. Prefer store SSH keys as file attachments rather than fields on a record.
    .EXAMPLE
    Download-KeeperRecordTypes -Source keeper -FileName 'types.json' -SSHKeyAsFile
    .EXAMPLE
    Download-KeeperRecordTypes
    #>

    param (
        [string]$Source,

        [string]$FileName = "record_types.json",

        [switch]$SSHKeyAsFile
    )

    try {
        [KeeperSecurity.Vault.VaultOnline]$vault = getVault
        $vault.SyncDown() | Out-Null
        if ($null -eq $Source){
            $Source = 'keeper'
        }
        $recordTypes = $vault.RecordTypes | Where-Object { $_.Scope -eq "Enterprise" }
        $recordTypesForDownload = @()

        foreach ($recordType in $recordTypes) {
            $custom = @{
                record_type_name = $recordType.Name
                fields = @()
            }
            if($null -ne $recordType.Description){
                $custom.description = $recordType.Description
            }

            $needFileRef = $SSHKeyAsFile.IsPresent
            foreach ($field in $recordType.Fields) {
                if ($needFileRef -and $field.FieldName.ToString() -eq "keyPair") {
                    $needFileRef = $true;
                    continue
                }

                $fieldObj = @{
                    '$type' = $field.FieldName.ToString()
                    label = $field.FieldLabel
                }
                if ($field.Required -eq $true)
                {
                    $fieldObj.required = $field.Required
                }
                $custom.fields += $fieldObj
            }

            if ($needFileRef) {
                $hasFileRef = $custom.fields | Where-Object { $_.'$type' -eq "fileRef" }
                if (-not $hasFileRef) {
                    $custom.fields += @{ '$type' = "fileRef" }
                }
            }

            $recordTypesForDownload += $custom
        }

        if ($recordTypesForDownload.Count -gt 0) {
            $json = ConvertTo-Json @{ record_types = $recordTypesForDownload } -Depth 10
            Set-Content -Path $FileName -Value $json -Encoding UTF8
            Write-Host "Downloaded $($recordTypesForDownload.Count) record types to '$(Resolve-Path $FileName)'"
        } else {
            Write-Warning "No record types were downloaded."
        }
    }
    catch {
        Write-Error "Error during download: $_"
    }
}

function Get-KeeperPasswordReport {
<#
.SYNOPSIS
    Generate comprehensive password security report for Keeper records.

.DESCRIPTION
    Analyzes passwords in Keeper records and generates a security report showing password complexity metrics.
    Can filter by folder and apply password policy filters to show only non-compliant passwords.

.PARAMETER Policy
    Password complexity policy as comma-separated values: Length,Lower,Upper,Digits,Special
    Default: "12,2,2,2,0" (shows all records with metrics)
    When specified, filters to show only failing records.

.PARAMETER Folder
    Optional folder path or UID to limit analysis to specific folder

.PARAMETER Length
    Minimum password length (when specified, filters to failing records only)

.PARAMETER Lower
    Minimum lowercase characters (when specified, filters to failing records only)

.PARAMETER Upper
    Minimum uppercase characters (when specified, filters to failing records only)

.PARAMETER Digits
    Minimum digits count (when specified, filters to failing records only)

.PARAMETER Special
    Minimum special characters (when specified, filters to failing records only)

.PARAMETER ShowErrors
    Show detailed error messages for records that cannot be processed

.EXAMPLE
    Get-KeeperPasswordReport
    Shows password report for all records with default policy metrics

.EXAMPLE
    Get-KeeperPasswordReport -Policy "16,3,3,3,1"
    Shows only records that fail the specified policy requirements

.EXAMPLE
    Get-KeeperPasswordReport -Folder "MyFolder" -Length 12 -Upper 2
    Shows records in MyFolder that don't meet length >= 12 and upper >= 2 requirements

.OUTPUTS
    Formatted table showing Record UID, Title, Description, and password complexity metrics
#>
    [CmdletBinding()]
    param (
        [string]$Policy = "",
        [string]$Folder = "",
        [int]$Length = 0,
        [int]$Lower = 0,
        [int]$Upper = 0,
        [int]$Digits = 0,
        [int]$Special = 0,
        [switch]$ShowErrors
    )

    [KeeperSecurity.Vault.VaultOnline]$vault = getVault
    
    $policyString = "12,2,2,2,0"
    $filterToFailingOnly = $false
    
    if ($Policy -ne "") {
        $policyString = $Policy
        $filterToFailingOnly = $true
    }
    elseif ($Length -gt 0 -or $Lower -gt 0 -or $Upper -gt 0 -or $Digits -gt 0 -or $Special -gt 0) {
        $len = if ($Length -gt 0) { $Length } else { 12 }
        $policyString = "$len,$Lower,$Upper,$Digits,$Special"
        $filterToFailingOnly = $true
    }

    try {
        $policyParts = $policyString -split ','
        if ($policyParts.Count -lt 5) {
            throw "Policy must contain at least 5 comma-separated integers"
        }
        
        $reqLength = [int]$policyParts[0].Trim()
        $reqLower = [int]$policyParts[1].Trim()
        $reqUpper = [int]$policyParts[2].Trim()
        $reqDigits = [int]$policyParts[3].Trim()
        $reqSpecial = [int]$policyParts[4].Trim()
    }
    catch {
        Write-Error "Invalid policy format. Use: Length,Lower,Upper,Digits,Special (e.g., '12,2,2,2,0')"
        return
    }

    Write-Host "     Password Length: $reqLength"
    Write-Host "Lowercase characters: $reqLower"
    Write-Host "Uppercase characters: $reqUpper"
    Write-Host "              Digits: $reqDigits"
    if ($reqSpecial -gt 0) {
        Write-Host "    Special characters: $reqSpecial"
    }
    Write-Host ""

    $records = @()
    
    if ($Folder -ne "") {
        $folderNode = $null
        if ($vault.TryGetFolder($Folder, [ref]$folderNode)) {
            foreach ($recordUid in $folderNode.Records) {
                $record = $null
                if ($vault.TryGetKeeperRecord($recordUid, [ref]$record)) {
                    $records += $record
                }
            }
        }
        else {
            $foundFolder = $false
            foreach ($folder in $vault.Folders) {
                if ($folder.Name -eq $Folder) {
                    foreach ($recordUid in $folder.Records) {
                        $record = $null
                        if ($vault.TryGetKeeperRecord($recordUid, [ref]$record)) {
                            $records += $record
                        }
                    }
                    $foundFolder = $true
                    break
                }
            }
            if (-not $foundFolder) {
                Write-Error "Invalid folder: $Folder"
                return
            }
        }
    }
    else {
        foreach ($record in $vault.KeeperRecords) {
            if ($record.Version -eq 2 -or $record.Version -eq 3) {
                $records += $record
            }
        }
    }

    $recordsWithPasswords = @()
    foreach ($record in $records) {
        try {
            $password = Get-KeeperRecordPassword -Record $record -Silent
            if ($password -and $password.Trim().Length -gt 0) {
                $recordsWithPasswords += @{
                    Record = $record
                    Password = $password.Trim()
                }
            }
        }
        catch {
            if ($ShowErrors) {
                Write-Warning "Skipping record $($record.Uid) due to error: $($_.Exception.Message)"
            }
            continue
        }
    }

    if ($recordsWithPasswords.Count -eq 0) {
        Write-Host "No records with passwords found."
        return
    }

    $results = @()
    $specialChars = "!@#`$%()+;<>=?[]{}^.,"
    
    foreach ($item in $recordsWithPasswords) {
        $record = $item.Record
        $password = $item.Password
        
        try {
            if ([string]::IsNullOrWhiteSpace($password)) {
                continue
            }

            $description = ""
            if ($record -is [KeeperSecurity.Vault.PasswordRecord]) {
                $description = $record.Login
            }
            elseif ($record -is [KeeperSecurity.Vault.TypedRecord]) {
                $loginField = $record.Fields | Where-Object { $_.FieldName -eq "login" } | Select-Object -First 1
                if ($loginField -and $loginField.Count -gt 0) {
                    $description = $loginField.Values[0]
                }
            }

            $length = $password.Length
            $lowerCount = ($password.ToCharArray() | Where-Object { [char]::IsLower($_) }).Count
            $upperCount = ($password.ToCharArray() | Where-Object { [char]::IsUpper($_) }).Count
            $digitCount = ($password.ToCharArray() | Where-Object { [char]::IsDigit($_) }).Count
            $specialCount = ($password.ToCharArray() | Where-Object { $specialChars.Contains($_) }).Count

            if ($filterToFailingOnly) {
                $meetsPolicy = $length -ge $reqLength -and 
                              $lowerCount -ge $reqLower -and 
                              $upperCount -ge $reqUpper -and 
                              $digitCount -ge $reqDigits -and 
                              $specialCount -ge $reqSpecial
                
                if ($meetsPolicy) {
                    continue
                }
            }

            $results += [PSCustomObject]@{
                'Record UID' = $record.Uid
                'Title' = $record.Title
                'Description' = $description
                'Length' = $length
                'Lower' = $lowerCount
                'Upper' = $upperCount
                'Digits' = $digitCount
                'Special' = $specialCount
            }
        }
        catch {
            if ($ShowErrors) {
                Write-Warning "Skipping record $($record.Uid) due to error: $($_.Exception.Message)"
            }
        }
    }

    if ($results.Count -gt 0) {
        $results | Format-Table -AutoSize
    }
    else {
        if ($filterToFailingOnly) {
            Write-Host "All passwords meet the specified policy requirements."
        }
        else {
            Write-Host "No valid password records found for analysis."
        }
    }
}

function Get-RecordFields {
    <#
    .SYNOPSIS
    Extract common fields from a Keeper record.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [KeeperSecurity.Vault.KeeperRecord]$Record
    )

    process {
        switch ($Record.GetType().Name) {
            'PasswordRecord' {
                $customFields = if ($Record.Custom) {
                    ($Record.Custom | Sort-Object Name | ForEach-Object { "$($_.Name):$($_.Value)" }) -join ";"
                } else { "" }

                return @{
                    Login    = $Record.Login
                    Password = $Record.Password
                    Url      = $Record.Link
                    Notes    = $Record.Notes
                    Custom   = $customFields
                }
            }
            'TypedRecord' {
                $customFields = if ($Record.Custom) {
                    ($Record.Custom | Sort-Object FieldName | ForEach-Object { 
                        "$($_.FieldName):$(if ($_.ObjectValue) { $_.ObjectValue } else { '' })"
                    }) -join ";"
                } else { "" }

                return @{
                    Login    = Get-TypedFieldValue -Record $Record -FieldName "login"
                    Password = Get-TypedFieldValue -Record $Record -FieldName "password"
                    Url      = Get-TypedFieldValue -Record $Record -FieldName "url"
                    Notes    = $Record.Notes
                    Custom   = $customFields
                }
            }
            default {
                return @{ Login = $null; Password = $null; Url = $null; Notes = $null; Custom = "" }
            }
        }
    }
}

function Get-TypedFieldValue {
    <#
    .SYNOPSIS
    Extract a typed field value from a TypedRecord.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [KeeperSecurity.Vault.TypedRecord]$Record,
        
        [Parameter(Mandatory = $true)]
        [string]$FieldName
    )

    $field = $Record.Fields | Where-Object { $_.FieldName -eq $FieldName } | Select-Object -First 1
    if (-not $field -or -not $field.ObjectValue) { return $null }

    $value = $field.ObjectValue
    if ($value -is [string]) { return $value }
    if ($value -is [System.Collections.IEnumerable]) {
        return ($value | ForEach-Object { $_.ToString() }) -join ","
    }
    return $value.ToString()
}

function Get-ShareHashString {
    <#
    .SYNOPSIS
    Build a hash string from share permissions.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $ShareInfo,
        
        [switch]$IncludePermissions
    )

    $parts = [System.Collections.ArrayList]::new()

    if ($ShareInfo.UserPermissions) {
        foreach ($user in ($ShareInfo.UserPermissions | Sort-Object Username)) {
            if ($IncludePermissions) {
                $permText = if ($user.CanEdit -and $user.CanShare) {
                    "Can Edit & Share"
                } elseif ($user.CanEdit) {
                    "Can Edit"
                } elseif ($user.CanShare) {
                    "Can Share"
                } else {
                    "Read Only"
                }
                [void]$parts.Add("$($user.Username)=$permText")
            } else {
                [void]$parts.Add("$($user.Username)")
            }
        }
    }

    if ($IncludePermissions -and $ShareInfo.SharedFolderPermissions) {
        foreach ($sf in ($ShareInfo.SharedFolderPermissions | Sort-Object SharedFolderUid)) {
            $permText = if ($sf.CanEdit -and $sf.CanShare) {
                "Can Edit & Share"
            } elseif ($sf.CanEdit) {
                "Can Edit"
            } elseif ($sf.CanShare) {
                "Can Share"
            } else {
                "Read Only"
            }
            [void]$parts.Add("sf:$($sf.SharedFolderUid)=$permText")
        }
    }

    return $parts -join ";"
}

function Find-KeeperDuplicateRecords {
    <#
    .SYNOPSIS
    Find duplicate records in Keeper vault.

    .DESCRIPTION
    Locates duplicate records in the vault based on one or more record fields.
    Uses SHA256 hashing to efficiently group records with matching field values.

    .PARAMETER Title
    Match duplicates by title field.

    .PARAMETER Login
    Match duplicates by login field.

    .PARAMETER Password
    Match duplicates by password field.

    .PARAMETER Url
    Match duplicates by URL field.

    .PARAMETER Shares
    Match duplicates by share permissions.

    .PARAMETER Full
    Match duplicates by all fields (title, login, password, url, notes, custom fields, shares).

    .PARAMETER Merge
    Consolidate duplicate records by removing duplicates (keeps first record in each group).

    .PARAMETER Force
    Delete duplicates without confirmation (valid only with -Merge).

    .PARAMETER DryRun
    Simulate removing duplicates without actually removing them (valid only with -Merge).

    .PARAMETER Quiet
    Suppress screen output (valid only with -Force flag; since -Force requires -Merge, effectively requires both).

    .PARAMETER IgnoreSharesOnMerge
    Ignore share-permissions when matching duplicate records for merging.

    .PARAMETER Scope
    Define the scope of the search (vault or enterprise). Default is vault.
    Enterprise scope available only to enterprise account administrators with compliance data-access privileges.

    .PARAMETER RefreshData
    Populate local cache with latest audit data. Valid only when used with -Scope enterprise.

    .PARAMETER Format
    Choose the format of the output (table, csv, json). Default is table.

    .PARAMETER Output
    Export search results to a file.

    .OUTPUTS
    PSCustomObject[] - Array of duplicate record information when not using -Merge.

    .EXAMPLE
    Find-KeeperDuplicateRecords -Title
    Find all records with duplicate titles.

    .EXAMPLE
    Find-KeeperDuplicateRecords -Login -Password
    Find records with matching login AND password.

    .EXAMPLE
    Find-KeeperDuplicateRecords -Full | Export-Csv duplicates.csv
    Export duplicate records to CSV.

    .EXAMPLE
    Find-KeeperDuplicateRecords -Full -Merge -DryRun
    Simulate merging duplicate records.

    .EXAMPLE
    Find-KeeperDuplicateRecords -Full -Merge -Force -Quiet
    Silently remove duplicate records without confirmation.

    .EXAMPLE
    Find-KeeperDuplicateRecords -Merge -IgnoreSharesOnMerge
    Merge duplicates while ignoring share permissions when matching.

    .EXAMPLE
    Find-KeeperDuplicateRecords -Full -Format csv -Output duplicates.csv
    Export duplicate records to a CSV file.

    .EXAMPLE
    Find-KeeperDuplicateRecords -Login -Password -Format json
    Find duplicates and output as JSON.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [switch]$Title,
        [switch]$Login,
        [switch]$Password,
        [switch]$Url,
        [switch]$Shares,
        [switch]$Full,
        [switch]$Merge,
        [switch]$Force,
        [switch]$DryRun,
        [switch]$Quiet,
        [switch]$IgnoreSharesOnMerge,
        
        [ValidateSet('vault', 'enterprise')]
        [string]$Scope = 'vault',
        
        [switch]$RefreshData,
        
        [ValidateSet('table', 'csv', 'json')]
        [string]$Format = 'table',
        
        [string]$Output
    )

    if ($Force -and -not $Merge) {
        Write-Warning "-Force is only valid with -Merge. Ignoring -Force."
        $Force = $false
    }
    
    if ($DryRun -and -not $Merge) {
        Write-Warning "-DryRun is only valid with -Merge. Ignoring -DryRun."
        $DryRun = $false
    }
    
    if ($Quiet -and -not $Force) {
        Write-Warning "-Quiet is only valid with -Force flag. Ignoring -Quiet."
        $Quiet = $false
    }
    
    if ($RefreshData -and $Scope -ne 'enterprise') {
        Write-Warning "-RefreshData is only valid with -Scope enterprise. Ignoring -RefreshData."
        $RefreshData = $false
    }
    
    if ($IgnoreSharesOnMerge -and -not $Merge) {
        Write-Warning "-IgnoreSharesOnMerge is only valid with -Merge. Ignoring -IgnoreSharesOnMerge."
        $IgnoreSharesOnMerge = $false
    }

    if ($Quiet -and $DryRun) {
        Write-Warning "-Quiet is only valid with -Force flag. Ignoring -Quiet."
        $Quiet = $false
    }

    if ($Scope -eq 'enterprise') {
        throw "Enterprise Scope is not yet supported in Powershell. Use -Scope vault"
    }

    [KeeperSecurity.Vault.VaultOnline]$vault = $null
    try {
        $vault = getVault
    }
    catch {
        Write-Error "Failed to get vault. Please ensure you are connected." -ErrorAction Stop
    }
    if (-not $vault) {
        Write-Error "Not connected to Keeper. Please run Connect-Keeper first." -ErrorAction Stop
    }

    $useDefault = -not $Title -and -not $Login -and -not $Password -and -not $Url -and -not $Full
    if ($Merge) { $Full = $true }

    $compareFields = if ($Full) {
        [System.Collections.ArrayList]@("All Fields")
    } else {
        $fields = [System.Collections.ArrayList]::new()
        if ($Title -or $useDefault) { [void]$fields.Add("Title") }
        if ($Login -or $useDefault) { [void]$fields.Add("Login") }
        if ($Password -or $useDefault) { [void]$fields.Add("Password") }
        if ($Url) { [void]$fields.Add("URL") }
        if ($Shares) { [void]$fields.Add("Shares") }
        $fields
    }

    if (-not $Quiet) {
        $compareMessage = "Find duplicated records by: $($compareFields -join ', ')"
        if ($Merge -and $IgnoreSharesOnMerge) {
            $compareMessage += " (ignoring shares for merge)"
        }
        Write-Host $compareMessage
        Write-Host ""
    }

    $shareInfoMap = @{}
    try {
        $recordUidsList = [System.Collections.Generic.List[string]]::new()
        foreach ($rec in $vault.KeeperRecords) {
            $recordUidsList.Add($rec.Uid)
        }
        if ($recordUidsList.Count -gt 0) {
            $sharesList = $vault.GetSharesForRecords($recordUidsList).GetAwaiter().GetResult()
            foreach ($share in $sharesList) {
                $shareInfoMap[$share.RecordUid] = $share
            }
        }
    }
    catch {
        if (-not $Quiet) {
            Write-Warning "Could not load share information: $($_.Exception.Message)"
        }
    }

    $hashMap = @{}
    $recordFieldsCache = @{}
    $sha256 = $null
    
    $hashParts = [System.Collections.Generic.List[string]]::new(10)

    try {
        $sha256 = [System.Security.Cryptography.SHA256]::Create()

        foreach ($record in $vault.KeeperRecords) {
            if ($record.Version -notin @(2, 3)) {
                continue
            }
            
            $fields = Get-RecordFields -Record $record
            $recordFieldsCache[$record.Uid] = $fields

            $hashParts.Clear()
            $shareInfo = $null

            if ($Full) {
                $hashParts.Add($(if ($record.Title) { $record.Title.ToLower() } else { "" }))
                $hashParts.Add($(if ($fields.Login) { $fields.Login.ToLower() } else { "" }))
                $hashParts.Add($(if ($fields.Password) { $fields.Password } else { "" }))
                $hashParts.Add($(if ($fields.Url) { $fields.Url } else { "" }))
                
                $customs = @{}
                
                if ($record -is [KeeperSecurity.Vault.TypedRecord]) {
                    $totpField = $record.Fields | Where-Object { $_.FieldName -eq "oneTimeCode" } | Select-Object -First 1
                    if ($totpField -and $totpField.ObjectValue) {
                        $customs["totp"] = $totpField.ObjectValue.ToString()
                    }
                    
                    if ($record.TypeName) {
                        $customs["type:"] = $record.TypeName
                    }
                    
                    if ($record.Custom) {
                        foreach ($cf in $record.Custom) {
                            if ($cf.FieldName -and $cf.ObjectValue) {
                                $value = $cf.ObjectValue
                                if ($value -is [System.Collections.IEnumerable] -and $value -isnot [string]) {
                                    $sortedItems = @($value | ForEach-Object { $_.ToString() } | Sort-Object)
                                    $value = $sortedItems -join "|"
                                } else {
                                    $value = $value.ToString()
                                }
                                if (-not [string]::IsNullOrWhiteSpace($value)) {
                                    $customs[$cf.FieldName] = $value
                                }
                            }
                        }
                    }
                }
                elseif ($record -is [KeeperSecurity.Vault.PasswordRecord]) {
                    if ($record.Custom) {
                        foreach ($cf in $record.Custom) {
                            if ($cf.Name -and $cf.Value) {
                                $customs[$cf.Name] = $cf.Value
                            }
                        }
                    }
                }
                
                $sortedKeys = $customs.Keys | Sort-Object
                foreach ($key in $sortedKeys) {
                    $hashParts.Add("$key=$($customs[$key])")
                }
                
            }
            else {
                if ($Title -or $useDefault) { 
                    $hashParts.Add($(if ($record.Title) { $record.Title.ToLower() } else { "" }))
                }
                if ($Login -or $useDefault) { 
                    $hashParts.Add($(if ($fields.Login) { $fields.Login.ToLower() } else { "" }))
                }
                if ($Password -or $useDefault) { 
                    $hashParts.Add($(if ($fields.Password) { $fields.Password } else { "" }))
                }
                if ($Url) { 
                    $hashParts.Add($(if ($fields.Url) { $fields.Url } else { "" }))
                }
            }

            $combined = [string]::Join("|", $hashParts)
            if ([string]::IsNullOrWhiteSpace($combined)) { continue }

            $hashBytes = $sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($combined))
            $hashKey = [BitConverter]::ToString($hashBytes).Replace("-", "").ToLower()

            if (-not $hashMap.ContainsKey($hashKey)) { 
                $hashMap[$hashKey] = [System.Collections.Generic.List[object]]::new()
            }
            $hashMap[$hashKey].Add($record)
        }
    }
    finally {
        if ($sha256) { $sha256.Dispose() }
    }

    $duplicateGroups = @($hashMap.Values | Where-Object { $_.Count -gt 1 })

    $shouldPartitionByShares = ($Shares -or $Full) -and -not ($Merge -and $IgnoreSharesOnMerge)
    
    if ($shouldPartitionByShares -and $duplicateGroups.Count -gt 0) {
        $newPartitions = [System.Collections.Generic.List[object]]::new()
        
        foreach ($group in $duplicateGroups) {
            $shareGroups = @{}
            foreach ($record in $group) {
                $shareKey = if ($shareInfoMap.ContainsKey($record.Uid)) {
                    Get-ShareHashString -ShareInfo $shareInfoMap[$record.Uid] -IncludePermissions
                } else { "" }
                
                if (-not $shareGroups.ContainsKey($shareKey)) {
                    $shareGroups[$shareKey] = [System.Collections.Generic.List[object]]::new()
                }
                $shareGroups[$shareKey].Add($record)
            }
            
            foreach ($subGroup in $shareGroups.Values) {
                if ($subGroup.Count -gt 1) {
                    $newPartitions.Add($subGroup)
                }
            }
        }
        
        $duplicateGroups = @($newPartitions)
    }

    if ($duplicateGroups.Count -eq 0) {
        if (-not $Quiet) { Write-Host "No duplicate records found." }
        return
    }

    if ($Merge) {
        $recordsToRemove = [System.Collections.Generic.List[object]]::new()
        foreach ($group in $duplicateGroups) {
            for ($i = 1; $i -lt $group.Count; $i++) {
                $recordsToRemove.Add($group[$i])
            }
        }

        if ($recordsToRemove.Count -eq 0) {
            if (-not $Quiet) { Write-Host "No duplicate records to remove." }
            return
        }

        if ($DryRun) {
            Write-Host "DRY RUN MODE: No records will be removed" -ForegroundColor Yellow
            Write-Host ""
        }

        if (-not $Quiet) {
            Write-Host "The following $($recordsToRemove.Count) duplicate record(s) will be removed:"
            Write-Host ""

            $removeList = $recordsToRemove | ForEach-Object {
                $cachedFields = $recordFieldsCache[$_.Uid]
                [PSCustomObject]@{
                    Title = $_.Title
                    UID   = $_.Uid
                    Login = $cachedFields.Login
                }
            }
            $removeList | Format-Table -AutoSize
        }

        if ($DryRun) {
            Write-Host "DRY RUN: No records were removed." -ForegroundColor Yellow
            return
        }

        if (-not $Force) {
            $response = Read-Host "Do you want to proceed with removing $($recordsToRemove.Count) duplicate record(s)? (y/n)"
            if ($response -notin @('y', 'yes')) {
                Write-Host "Operation cancelled."
                return
            }
        }

        if (-not $Quiet) { Write-Host "Removing duplicate records..." }

        try {
            $recordPaths = [System.Collections.Generic.List[KeeperSecurity.Vault.RecordPath]]::new($recordsToRemove.Count)
            foreach ($rec in $recordsToRemove) {
                $folderUid = ""
                if ($vault.RootFolder.Records.Contains($rec.Uid)) {
                    $folderUid = ""
                } else {
                    foreach ($folder in $vault.Folders) {
                        if ($folder.Records.Contains($rec.Uid)) {
                            $folderUid = $folder.FolderUid
                            break
                        }
                    }
                }
                
                $recordPaths.Add([KeeperSecurity.Vault.RecordPath]@{
                    RecordUid = $rec.Uid
                    FolderUid = $folderUid
                })
            }

            $vault.DeleteRecords($recordPaths).GetAwaiter().GetResult() | Out-Null

            if (-not $Quiet) {
                Write-Host "Successfully removed $($recordsToRemove.Count) duplicate record(s)." -ForegroundColor Green
                Write-Host "Syncing vault..."
            }

            $vault.SyncDown($true).GetAwaiter().GetResult() | Out-Null

            if (-not $Quiet) { Write-Host "Vault synced." -ForegroundColor Green }
        }
        catch {
            Write-Error "Error removing duplicates: $($_.Exception.Message)"
        }

        return
    }

    Write-Host "Duplicates Found:"
    Write-Host ""

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    $groupNum = 1

    foreach ($group in $duplicateGroups) {
        $isFirst = $true
        foreach ($record in $group) {
            $cachedFields = $recordFieldsCache[$record.Uid]

            $owner = ""
            $sharedTo = ""
            if ($shareInfoMap.ContainsKey($record.Uid)) {
                $shareInfo = $shareInfoMap[$record.Uid]
                if ($shareInfo.UserPermissions) {
                    $sharedUsersList = [System.Collections.Generic.List[string]]::new()
                    foreach ($perm in $shareInfo.UserPermissions) {
                        if ($perm.Owner) {
                            $owner = $perm.Username
                        } else {
                            $sharedUsersList.Add($perm.Username)
                        }
                    }
                    $sharedTo = $sharedUsersList -join ", "
                }
            }
            if ([string]::IsNullOrEmpty($owner) -and $record.Owner) {
                $owner = $vault.Auth.Username
            }

            $resultObj = [ordered]@{
                Group       = if ($isFirst) { $groupNum } else { "" }
                Title       = $record.Title
                Login       = $cachedFields.Login
            }
            if ($Url) { $resultObj.Url = $cachedFields.Url }
            $resultObj.UID = $record.Uid
            $resultObj.RecordOwner = $owner
            $resultObj.SharedTo = $sharedTo
            
            $results.Add([PSCustomObject]$resultObj)

            $isFirst = $false
        }
        $groupNum++
    }

    $outputData = $results.ToArray()

    if ($Output) {
        switch ($Format) {
            'csv' {
                $outputData | Export-Csv -Path $Output -NoTypeInformation -Force
                Write-Host "Results exported to: $Output" -ForegroundColor Green 
            }
            'json' {
                $outputData | ConvertTo-Json -Depth 10 | Out-File -FilePath $Output -Force
                Write-Host "Results exported to: $Output" -ForegroundColor Green
            }
            default {
                $outputData | Format-Table -AutoSize | Out-String | Out-File -FilePath $Output -Force
                Write-Host "Results exported to: $Output" -ForegroundColor Green
            }
        }
    }
    return $outputData
}

New-Alias -Name find-duplicates -Value Find-KeeperDuplicateRecords