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
	Copy record password to clipboard or output

	.Parameter Record
	Record UID or any object containing property Uid

	.Parameter Field
	Record field to copy to clipboard. Record password is default.

	.Parameter Output
	Password output destination. Clipboard is default. Use "Stdout" for scripting
#>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)] $Record,
        [string] [ValidateSet('Login' , 'Password', 'URL')] $Field = 'Password',
        [string] [ValidateSet('Clipboard' , 'Stdout')] $Output = 'Clipboard'
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

        $found = $false
        if ($uid) {
            [KeeperSecurity.Vault.KeeperRecord] $rec = $null
            if (-not $vault.TryGetKeeperRecord($uid, [ref]$rec)) {
                $entries = Get-KeeperChildItem -Filter $uid -ObjectType Record
                if ($entries.Uid) {
                    $vault.TryGetRecord($entries[0].Uid, [ref]$rec) | Out-Null
                }
            }
            if ($rec) {
                $found = $true
                $value = ''

                if ($rec -is [KeeperSecurity.Vault.PasswordRecord]) {
                    switch ($Field) {
                        'Login' { $value = $rec.Login }
                        'Password' { $value = $rec.Password }
                        'URL' { $value = $rec.Link }
                    }
                }
                elseif ($rec -is [KeeperSecurity.Vault.TypedRecord]) {
                    $fieldType = ''
                    switch ($Field) {
                        'Login' { $fieldType = 'login' }
                        'Password' { $fieldType = 'password' }
                        'URL' { $fieldType = 'url' }
                    }
                    if ($fieldType) {
                        $recordField = $rec.Fields | Where-Object FieldName -eq $fieldType | Select-Object -First 1
                        if (-not $recordField) {
                            $recordField = $rec.Custom | Where-Object FieldName -eq $fieldType | Select-Object -First 1
                        }
                        if ($recordField) {
                            $value = $recordField.ObjectValue
                        }
                    }
                }

                if ($value) {
                    if ($Output -eq 'Stdout') {
                        $value
                    }
                    else {
                        if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -eq [System.Threading.ApartmentState]::MTA) {
                            powershell -sta "Set-Clipboard -Value '$value'"
                        }
                        else {
                            Set-Clipboard -Value $value
                        }
                        Write-Output "Copied to clipboard: $Field for $($rec.Title)"
                    }
                    if ($Field -eq 'Password') {
                        $vault.AuditLogRecordCopyPassword($rec.Uid)
                    }
                }
                else {
                    Write-Output "Record $($rec.Title) has no $Field"
                }
            }
        }
        if (-not $found) {
            Write-Error -Message "Cannot find a Keeper record: $Record"
        }
    }
}
New-Alias -Name kcc -Value Copy-KeeperToClipboard

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
#>

    [CmdletBinding(DefaultParameterSetName = 'add')]
    Param (
        [Parameter()] [switch] $GeneratePassword,
        [Parameter(ParameterSetName = 'add')] [string] $RecordType,
        [Parameter(ParameterSetName = 'add')] [string] $Folder,
        [Parameter(ParameterSetName = 'edit', Mandatory = $True)] [string] $Uid,
        [Parameter()] [string] $Title,
        [Parameter()] [string] $Notes,
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
        }
        else {
            $folderUid = $Script:Context.CurrentFolder
            if ($Folder) {
                $folderNode = resolveFolderNode $vault $Folder
                $folderUid = $folderNode.FolderUid
            }

            $task = $vault.CreateRecord($record, $folderUid)
        }
        $task.GetAwaiter().GetResult()
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
        $folderNode = resolveFolderNode $vault $Folder
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

function resolveFolderNode {
    Param ([KeeperSecurity.Vault.VaultOnline]$vault, $path)

    [KeeperSecurity.Vault.FolderNode]$folder = $null
    if (-not $vault.TryGetFolder($path, [ref]$folder)) {
        if (-not $vault.TryGetFolder($Script:Context.CurrentFolder, [ref]$folder)) {
            $folder = $vault.RootFolder
        }

        $comps = splitKeeperPath $path
        $folder, $rest = parseKeeperPath $comps $vault $folder
        if ($rest) {
            Write-Error "Folder $path not found" -ErrorAction Stop
        }
    }

    $folder
}

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

    .PARAMETER SSHFileRef
    Optional. Whether to ensure a fileRef field exists when a keyPair is found.

    .EXAMPLE
    Download-KeeperRecordTypes -Source keeper -FileName 'types.json' -SSHFileRef

    .EXAMPLE
    Download-KeeperRecordTypes
    #>

    param (
        [string]$Source,

        [string]$FileName = "record_types.json",

        [switch]$SSHFileRef
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

            $needFileRef = $SSHFileRef.IsPresent
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
            $json = ConvertTo-Json @{ recordTypes = $recordTypesForDownload } -Depth 10
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
