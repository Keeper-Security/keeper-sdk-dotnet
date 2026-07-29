#requires -Version 5.1

. "$PSScriptRoot/NsfBatchSampleData.ps1"

function Script:ConvertTo-NSFJsonValue {
    <#
    .SYNOPSIS
    Converts PowerShell values to Dictionary[string,object] / scalars for NSF record Fields bags
    (KeeperNSFRecordCreateRequest.Fields). For import-file JSON use ConvertTo-ImportJsonValue instead.
    #>
    Param([Parameter(Mandatory = $true)][AllowNull()] $InputObject)

    if ($null -eq $InputObject) { return $null }

    $base = $InputObject
    if ($InputObject -is [System.Management.Automation.PSObject] -and $null -ne $InputObject.PSObject) {
        $bo = $InputObject.PSObject.BaseObject
        if ($null -ne $bo) { $base = $bo }
    }

    if ($base -is [string] -or $base -is [System.ValueType]) {
        return $base
    }

    if ($base -is [System.Collections.IDictionary]) {
        # Use Dictionary[string,object] so NSF create/update Fields accepts custom values.
        $ht = New-Object 'System.Collections.Generic.Dictionary[string,object]'
        foreach ($key in $base.Keys) {
            $ht[[string]$key] = ConvertTo-NSFJsonValue -InputObject $base[$key]
        }
        return $ht
    }

    if ($base -is [System.Collections.IEnumerable]) {
        $list = New-Object 'System.Collections.Generic.List[object]'
        foreach ($item in $base) {
            $list.Add((ConvertTo-NSFJsonValue -InputObject $item)) | Out-Null
        }
        # Leading comma keeps single-element arrays as Object[] (PowerShell otherwise unwraps them).
        return ,$list.ToArray()
    }

    if ($null -ne $InputObject.PSObject -and $InputObject.PSObject.Properties.Count -gt 0) {
        $ht = New-Object 'System.Collections.Generic.Dictionary[string,object]'
        foreach ($prop in $InputObject.PSObject.Properties) {
            $ht[$prop.Name] = ConvertTo-NSFJsonValue -InputObject $prop.Value
        }
        return $ht
    }

    return $base
}

function Script:Resolve-KeeperNSFFieldValue {
    Param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string] $RawValue
    )

    if ([string]::IsNullOrEmpty($RawValue)) { return $RawValue }

    if ($RawValue -clike '$JSON:*') {
        $jsonStr = $RawValue.Substring(6)
        if ([string]::IsNullOrEmpty($jsonStr)) {
            Write-Warning "JSON value cannot be empty. Format: `$JSON:<json_object>"
            return $RawValue
        }
        try {
            $parsed = $jsonStr | ConvertFrom-Json -ErrorAction Stop
        } catch {
            Write-Warning "Invalid JSON value: $($_.Exception.Message)"
            return $RawValue
        }
        return (ConvertTo-NSFJsonValue -InputObject $parsed)
    }

    return $RawValue
}

function Script:Parse-KeeperNSFFieldSpecs {
    Param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]] $FieldSpecs
    )

    $fieldDict = New-Object 'System.Collections.Generic.Dictionary[string,object]'
    $skipped = New-Object 'System.Collections.Generic.List[string]'

    foreach ($f in $FieldSpecs) {
        if ([string]::IsNullOrWhiteSpace($f)) { continue }

        $key = $null
        $val = $null
        $eqIdx = $f.IndexOf('=')
        if ($eqIdx -gt 0) {
            $key = $f.Substring(0, $eqIdx).Trim()
            $val = $f.Substring($eqIdx + 1).Trim()
        }
        else {
            $colonIdx = $f.IndexOf(':')
            if ($colonIdx -gt 0) {
                $key = $f.Substring(0, $colonIdx).Trim()
                $val = $f.Substring($colonIdx + 1).Trim()
                if ($val.Length -ge 2 -and $val[0] -eq '"' -and $val[$val.Length - 1] -eq '"') {
                    $val = $val.Substring(1, $val.Length - 2)
                }
                Write-Host "Warning: Field '$f' uses ':' as delimiter; prefer key=value (e.g. ${key}=${val})." -ForegroundColor Yellow
            }
        }

        if ([string]::IsNullOrEmpty($key)) {
            $skipped.Add($f) | Out-Null
            Write-Host "Warning: Skipping invalid field '$f'. Expected format: key=value" -ForegroundColor Yellow
            continue
        }

        $resolved = Resolve-KeeperNSFFieldValue -RawValue $val
        if ($resolved -is [System.Management.Automation.PSObject] -and $null -ne $resolved.PSObject.BaseObject) {
            $resolved = $resolved.PSObject.BaseObject
        }
        $fieldDict[$key] = $resolved
    }

    return [PSCustomObject]@{
        Dictionary = $fieldDict
        Skipped    = $skipped
        ParsedCount = $fieldDict.Count
    }
}

function Add-KeeperNSFRecord {
    <#
	.Synopsis
	Creates a new Keeper NSF record.

	.Description
	Creates a new record in Keeper NSF using the v3 API.
	Supports setting title, type, notes, folder, and field values.

	.Parameter Title
	Title for the new record.

	.Parameter RecordType
	Record type (e.g. login, general). Defaults to 'login'.

	.Parameter FolderUid
	Optional folder UID to place the record in.
 
	.Parameter Notes
	Optional notes for the record.

	.Parameter Fields
	Optional field values as key=value pairs (e.g. login=admin password=secret url=https://example.com).

	Complex (object-typed) fields can be supplied with the $JSON:<json> indirection token,
	e.g. for a `databaseCredentials` record's `host` field:
	  'host=$JSON:{"hostName":"1.2.3.4","port":"1234"}'
	NOTE: single-quote the spec so PowerShell does not parse $JSON: as a drive-qualified variable.

	.Parameter GeneratePassword
	When present, generates a random password via CryptoUtils.GeneratePassword and stores it on the
	'password' field, overriding any explicit password=... value supplied in -Fields.

	.Parameter GeneratePassphrase
	Generate a random passphrase and store it on the 'password' field, overriding any explicit
	password=... value supplied in -Fields. Cannot be used together with -GeneratePassword.
	When used alone, defaults are: 5 words, "-" separator, useCaps=true, useDigits=true.
	Alias: PassphraseRules.

	.Parameter PassphraseRuleValues
	Optional values for passphrase rules. Supplying values alone (without -GeneratePassphrase) also
	triggers passphrase generation.
	Up to 4 values: WordCount,Separator,UseCaps,UseDigits.
	WordCount must be between 5 and 9.
	Allowed separators: '-', '.', '_', '!', '?', ' ' (space).
	Examples:
	  -GeneratePassphrase -PassphraseRuleValues 5,-,true,true
	  -PassphraseRuleValues 7,-,false,false
	  -PassphraseRuleValues "5, ,true,false"
	  -PassphraseRuleValues 5,' ',true,false

	.EXAMPLE
	PS> Add-KeeperNSFRecord "Test NSF Record" -RecordType login -GeneratePassphrase login=admin
	Creates a login record with a generated passphrase (default: 5 words, "-" separator, caps and digits on).

	.EXAMPLE
	PS> Add-KeeperNSFRecord "Test NSF Record" -PassphraseRuleValues 5,-,true,true login=admin url=https://example.com
	Creates a login record with a custom passphrase and sets login/url fields.

	.EXAMPLE
	PS> Add-KeeperNSFRecord "Test NSF Record" -PassphraseRuleValues "5, ,true,false" login=admin
	Creates a record with a 5-word space-separated passphrase (no caps, no digits).
#>
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $true)]
        [string] $Title,

        [Parameter()]
        [string] $RecordType = 'login',

        [Parameter()]
        [string] $FolderUid,

        [Parameter()]
        [string] $Notes,

        [Parameter()]
        [switch] $GeneratePassword,

        [Parameter()]
        [Alias('PassphraseRules')]
        [switch] $GeneratePassphrase,

        [Parameter()]
        [AllowEmptyCollection()]
        [string[]] $PassphraseRuleValues,

        [Parameter(ValueFromRemainingArguments = $true)]
        [string[]] $Fields
    )

    $generatePassphrase = $GeneratePassphrase.IsPresent -or ($PassphraseRuleValues -and $PassphraseRuleValues.Count -gt 0)

    if ($GeneratePassword.IsPresent -and $generatePassphrase) {
        Write-Host "Error: -GeneratePassword and -GeneratePassphrase cannot be used together." -ForegroundColor Red
        return
    }

    try {
        [KeeperSecurity.Vault.VaultOnline]$vault = getVault
    } catch {
        Write-Host "Error getting vault: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    $fieldDict = $null
    if (($Fields -and $Fields.Count -gt 0) -or $GeneratePassword.IsPresent -or $generatePassphrase) {
        $fieldDict = New-Object 'System.Collections.Generic.Dictionary[string,object]'
        if ($Fields) {
            $parsed = Parse-KeeperNSFFieldSpecs -FieldSpecs $Fields
            foreach ($key in $parsed.Dictionary.Keys) {
                $fieldDict[$key] = $parsed.Dictionary[$key]
            }
        }
        if ($GeneratePassword.IsPresent) {
            $fieldDict['password'] = [KeeperSecurity.Utils.CryptoUtils]::GeneratePassword($null)
        }
        elseif ($generatePassphrase) {
            if (-not (Set-KeeperPassphraseField -FieldDict $fieldDict -PassphraseRuleValues $PassphraseRuleValues)) {
                return
            }
        }
    }

    try {
        $recordUid = $vault.CreateKeeperNSFRecord($Title, $RecordType, $FolderUid, $Notes, $fieldDict).GetAwaiter().GetResult()
        Write-Host "Record '$Title' created successfully (UID: $recordUid)." -ForegroundColor Green
        return $recordUid
    }
    catch {
        Write-Host "Error creating record: $($_.Exception.Message)" -ForegroundColor Red
    }
}

New-Alias -Name nsf-record-add -Value Add-KeeperNSFRecord

function Script:Read-KeeperNSFImportFile {
    Param(
        [Parameter(Mandatory = $true)]
        [string] $JsonText
    )

    if ([string]::IsNullOrWhiteSpace($JsonText)) {
        throw "JSON text cannot be empty."
    }

    try {
        # ConvertFrom-Json + ImportJsonValue preserves nested custom_fields.
        # JsonUtils.ParseJson / DataContractJsonSerializer turns those into empty System.Object.
        $parsed = $JsonText | ConvertFrom-Json -ErrorAction Stop
        $jsonValue = ConvertTo-ImportJsonValue -InputObject $parsed
        if ($null -eq $jsonValue -or $jsonValue.Kind -ne [KeeperSecurity.Commands.ImportJsonValue+JsonKind]::Object) {
            throw "Import JSON root must be an object."
        }

        $jsonValue = Repair-ImportJsonSingleElementArrays -JsonValue $jsonValue
        return [KeeperSecurity.Vault.KeeperImport]::LoadJsonDictionary($jsonValue)
    }
    catch {
        $msg = $_.Exception.Message
        if ($_.Exception.InnerException) {
            $msg = $_.Exception.InnerException.Message
        }
        throw "Invalid import JSON: $msg"
    }
}

function Add-KeeperNSFRecords {
    <#
	.Synopsis
	Creates multiple Keeper NSF records in a single batch API call.

	.Description
	Uses vault/records/v3/add batching (up to 1000 records per request; larger sets are chunked automatically).
	Accepts the same JSON record payload as Import-KeeperVault (kimport) / Export-KeeperVault.

	Each record supports: title, $type, login, password, login_url, notes, custom_fields, folders.
	Place records in an NSF folder via folders[].folder (folder name or UID). Permission fields on folders
	(can_edit, can_share) and shared_folders entries are ignored for NSF batch create.

	.Parameter FilePath
	Path to a UTF-8 JSON import file.

	.Parameter Json
	Inline JSON string (same schema as -FilePath).

	.Parameter DefaultFolderUid
	Optional NSF folder UID applied when a record has no folders[].folder.

	.Parameter DownloadSampleRecords
	Writes a sample batch import JSON file to disk and exits without creating records.
	Requires an authenticated Keeper session. The sample uses the same records section
	shape as Import-KeeperVault / kimport. Edit the file with your own data, then run
	Add-KeeperNSFRecords -FilePath.

	.EXAMPLE
	PS> Add-KeeperNSFRecords -DownloadSampleRecords
	Writes nsf-records-batch.sample.json in the current directory.

	.EXAMPLE
	PS> Add-KeeperNSFRecords -DownloadSampleRecords -FilePath .\my-nsf-batch.json
	Writes a sample batch file to my-nsf-batch.json.

	.EXAMPLE
	PS> Add-KeeperNSFRecords -FilePath .\nsf-records-batch.sample.json

	.EXAMPLE
	PS> Add-KeeperNSFRecords -Json '{"records":[{"title":"Site A","$type":"login","login":"a","password":"secret","login_url":"https://example.com"}]}'

	.EXAMPLE
	PS> Add-KeeperNSFRecords -FilePath .\records.json -DefaultFolderUid "<nsfFolderUid>"

	Example file (same shape as kimport records section; includes login, legacy/general, bankCard,
	databaseCredentials, serverCredentials, sshKeys, address, contact, secureNote, bankAccount):
	{
	  "records": [
	    {
	      "title": "Batch Site A",
	      "$type": "login",
	      "login": "user.a@example.com",
	      "password": "Secret-A-2026!",
	      "login_url": "https://a.example.com",
	      "notes": "Created via NSF batch"
	    },
	    {
	      "title": "Production DB",
	      "$type": "databaseCredentials",
	      "login": "db_user",
	      "password": "Secret-DB-2026!",
	      "custom_fields": {
	        "$host": { "hostName": "192.168.1.10", "port": "1433" },
	        "$databaseType": "sqlServer"
	      }
	    },
	    {
	      "title": "Office",
	      "$type": "address",
	      "custom_fields": {
	        "$address:Work": {
	          "street1": "123 Main Street",
	          "city": "San Jose",
	          "state": "CA",
	          "zip": "95110",
	          "country": "US"
	        }
	      }
	    },
	    {
	      "title": "Legacy Entry",
	      "login": "legacy@example.com",
	      "password": "secret",
	      "notes": "No $type - legacy/general format"
	    }
	  ]
	}

	Use -DownloadSampleRecords to write a full multi-type example file for editing.
#>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium', DefaultParameterSetName = 'File')]
    Param (
        [Parameter(Mandatory = $true, ParameterSetName = 'File')]
        [Parameter(Mandatory = $false, ParameterSetName = 'DownloadSample')]
        [ValidateNotNullOrEmpty()]
        [string] $FilePath,

        [Parameter(Mandatory = $true, ParameterSetName = 'Json')]
        [ValidateNotNullOrEmpty()]
        [string] $Json,

        [Parameter(Mandatory = $false, ParameterSetName = 'DownloadSample')]
        [switch] $DownloadSampleRecords,

        [Parameter()]
        [string] $DefaultFolderUid
    )

    try {
        [KeeperSecurity.Vault.VaultOnline]$vault = getVault
    }
    catch {
        Write-Error "Not connected to Keeper. Please login first."
        return
    }

    if ($DownloadSampleRecords) {
        if (-not $FilePath) {
            $FilePath = 'nsf-records-batch.sample.json'
        }

        $fullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($FilePath)
        $parentDir = Split-Path -Parent $fullPath
        if ($parentDir -and -not (Test-Path -LiteralPath $parentDir)) {
            New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
        }

        $sampleJson = Get-KeeperNSFBatchSampleJson
        $utf8NoBom = New-Object System.Text.UTF8Encoding $false
        [System.IO.File]::WriteAllText($fullPath, $sampleJson, $utf8NoBom)

        Write-Host "Sample NSF batch file written to: $fullPath" -ForegroundColor Green
        Write-Host "Edit the file with your records, then run:"
        Write-Host "    Add-KeeperNSFRecords -FilePath `"$FilePath`""
        if ($DefaultFolderUid) {
            Write-Host "    Add-KeeperNSFRecords -FilePath `"$FilePath`" -DefaultFolderUid `"$DefaultFolderUid`""
        }
        return
    }

    if (-not $FilePath -and -not $Json) {
        Write-Error "FilePath or Json is required when -DownloadSampleRecords is not specified."
        return
    }

    try {
        $importFile = if ($PSCmdlet.ParameterSetName -eq 'File') {
            if (-not (Test-Path -LiteralPath $FilePath)) {
                throw "File not found: $FilePath"
            }
            Read-KeeperNSFImportFile -JsonText (Get-Content -LiteralPath $FilePath -Raw -Encoding UTF8)
        }
        else {
            Read-KeeperNSFImportFile -JsonText $Json
        }

        if (-not $importFile.Records -or $importFile.Records.Length -eq 0) {
            throw "Import file contains no records."
        }

        if ($importFile.SharedFolders -and $importFile.SharedFolders.Length -gt 0) {
            Write-Host "Note: shared_folders in the import file are ignored for NSF batch record create." -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "Error parsing import payload: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    if (-not $PSCmdlet.ShouldProcess("$($importFile.Records.Length) Keeper NSF record(s)", "Create Keeper NSF records")) {
        return
    }

    try {
        Write-Host "Creating $($importFile.Records.Length) Keeper NSF record(s) in batch..."
        $results = $vault.CreateKeeperNSFRecordsFromImport($importFile, $DefaultFolderUid).GetAwaiter().GetResult()

        $ok = @($results | Where-Object { $_.Success })
        $fail = @($results | Where-Object { -not $_.Success })
        Write-Host "Batch complete: $($ok.Count) succeeded, $($fail.Count) failed."
        Write-Host ""

        foreach ($result in $results) {
            if ($result.Success) {
                Write-Host "  [OK]   $($result.Title)  UID: $($result.RecordUid)" -ForegroundColor Green
            }
            else {
                $msg = if ($result.Message) { $result.Message } else { '(no message)' }
                Write-Host "  [FAIL] $($result.Title)  status=$($result.Status)  $msg" -ForegroundColor Red
            }
        }

        return ,@($results)
    }
    catch {
        Write-Host "Error creating records in batch: $($_.Exception.Message)" -ForegroundColor Red
    }
}

New-Alias -Name nsf-records-add -Value Add-KeeperNSFRecords

function Edit-KeeperNSFRecord {
    <#
	.Synopsis
	Updates an existing Keeper NSF record.

	.Description
	Updates the title, type, notes, and/or fields of a Keeper NSF record using the v3 API.
	Only specified parameters are changed; others are preserved.

	.Parameter RecordUid
	UID of the record to update.

	.Parameter Title
	New title for the record.

	.Parameter RecordType
	New record type.

	.Parameter Notes
	New notes for the record.

	.Parameter Fields
	Field values to add or update as key=value pairs (e.g. login=newuser password=newpass).

	Complex (object-typed) fields can be supplied with the $JSON:<json> indirection token,
	e.g. updating a `databaseCredentials` record's `host` field:
	  nsf-record-update <UID> -RecordType databaseCredentials 'host=$JSON:{"hostName":"1.2.3.4","port":"1234"}'
	NOTE: single-quote the spec so PowerShell does not parse $JSON: as a drive-qualified variable.

	.Parameter GeneratePassword
	When present, generates a random password via CryptoUtils.GeneratePassword and stores it on the
	'password' field, overriding any explicit password=... value supplied in -Fields.

	.Parameter GeneratePassphrase
	Generate a random passphrase and store it on the 'password' field, overriding any explicit
	password=... value supplied in -Fields. Cannot be used together with -GeneratePassword.
	When used alone, defaults are: 5 words, "-" separator, useCaps=true, useDigits=true.
	Alias: PassphraseRules.

	.Parameter PassphraseRuleValues
	Optional values for passphrase rules. Supplying values alone (without -GeneratePassphrase) also
	triggers passphrase generation.
	Up to 4 values: WordCount,Separator,UseCaps,UseDigits.
	WordCount must be between 5 and 9.
	Allowed separators: '-', '.', '_', '!', '?', ' ' (space).
	Examples:
	  -GeneratePassphrase -PassphraseRuleValues 5,-,true,true
	  -PassphraseRuleValues 7,-,false,false
	  -PassphraseRuleValues "5, ,true,false"
	  -PassphraseRuleValues 5,' ',true,false

	.EXAMPLE
	PS> Edit-KeeperNSFRecord <recordUid> -GeneratePassphrase
	Regenerates the password field on an existing NSF record using default passphrase rules.

	.EXAMPLE
	PS> Edit-KeeperNSFRecord <recordUid> -PassphraseRuleValues 7,-,false,true
	Regenerates the password field with a 7-word passphrase ("-" separator, no caps, digits on).

	.EXAMPLE
	PS> Edit-KeeperNSFRecord <recordUid> -PassphraseRuleValues 6,.,true,false login=newuser
	Updates login and regenerates password with a 6-word "."-separated passphrase (caps on, digits off).
#>
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $true)]
        [string] $RecordUid,

        [Parameter()]
        [string] $Title,

        [Parameter()]
        [string] $RecordType,

        [Parameter()]
        [string] $Notes,

        [Parameter()]
        [switch] $GeneratePassword,

        [Parameter()]
        [Alias('PassphraseRules')]
        [switch] $GeneratePassphrase,

        [Parameter()]
        [AllowEmptyCollection()]
        [string[]] $PassphraseRuleValues,

        [Parameter(ValueFromRemainingArguments = $true)]
        [string[]] $Fields
    )

    $hasTitle = $PSBoundParameters.ContainsKey('Title')
    $hasType  = $PSBoundParameters.ContainsKey('RecordType')
    $hasNotes = $PSBoundParameters.ContainsKey('Notes')
    $hasFields = $Fields -and $Fields.Count -gt 0
    $generatePassphrase = $GeneratePassphrase.IsPresent -or ($PassphraseRuleValues -and $PassphraseRuleValues.Count -gt 0)

    if ($GeneratePassword.IsPresent -and $generatePassphrase) {
        Write-Host "Error: -GeneratePassword and -GeneratePassphrase cannot be used together." -ForegroundColor Red
        return
    }

    if (-not $hasTitle -and -not $hasType -and -not $hasNotes -and -not $hasFields -and -not $GeneratePassword.IsPresent -and -not $generatePassphrase) {
        Write-Host "Error: At least one of -Title, -RecordType, -Notes, -GeneratePassword, -GeneratePassphrase, or field values must be specified." -ForegroundColor Red
        return
    }

    try {
        [KeeperSecurity.Vault.VaultOnline]$vault = getVault
    } catch {
        Write-Host "Error getting vault: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    $titleParam = if ($hasTitle) { $Title }      else { [NullString]::Value }
    $typeParam  = if ($hasType)  { $RecordType } else { [NullString]::Value }
    $notesParam = if ($hasNotes) { $Notes }      else { [NullString]::Value }

    $fieldDict = $null
    if ($hasFields -or $GeneratePassword.IsPresent -or $generatePassphrase) {
        $fieldDict = New-Object 'System.Collections.Generic.Dictionary[string,object]'
        if ($hasFields) {
            $parsed = Parse-KeeperNSFFieldSpecs -FieldSpecs $Fields
            foreach ($key in $parsed.Dictionary.Keys) {
                $fieldDict[$key] = $parsed.Dictionary[$key]
            }
            if ($parsed.ParsedCount -eq 0 -and -not $GeneratePassword.IsPresent -and -not $generatePassphrase) {
                Write-Host "Error: No valid field values were parsed. Use key=value (e.g. login=a12)." -ForegroundColor Red
                return
            }
        }
        if ($GeneratePassword.IsPresent) {
            $fieldDict['password'] = [KeeperSecurity.Utils.CryptoUtils]::GeneratePassword($null)
        }
        elseif ($generatePassphrase) {
            if (-not (Set-KeeperPassphraseField -FieldDict $fieldDict -PassphraseRuleValues $PassphraseRuleValues)) {
                return
            }
        }
    }

    try {
        [void]$vault.UpdateKeeperNSFRecord($RecordUid, $titleParam, $typeParam, $notesParam, $fieldDict).GetAwaiter().GetResult()
        Write-Host "Record '$RecordUid' updated successfully." -ForegroundColor Green
    }
    catch {
        Write-Host "Error updating record: $($_.Exception.Message)" -ForegroundColor Red
    }
}

New-Alias -Name nsf-record-update -Value Edit-KeeperNSFRecord

function Edit-KeeperNSFRecords {
    <#
	.Synopsis
	Updates multiple Keeper NSF records in a single batch API call.

	.Description
	Uses vault/records/v3/update batching (up to 1000 records per request; larger sets are chunked automatically).
	Accepts the same JSON record payload as Import-KeeperVault (kimport) / Export-KeeperVault / Add-KeeperNSFRecords.
	Each record must include uid. Only provided title, $type, notes, login/password/login_url, and custom_fields are updated.

	.Parameter FilePath
	Path to a UTF-8 JSON import file.

	.Parameter Json
	Inline JSON string (same schema as -FilePath).

	.Parameter DownloadSampleRecords
	Writes a sample batch update JSON file to disk and exits without updating records.
	Requires an authenticated Keeper session. Replace the placeholder UIDs, then run
	Edit-KeeperNSFRecords -FilePath.

	.EXAMPLE
	PS> Edit-KeeperNSFRecords -DownloadSampleRecords
	Writes nsf-records-update-batch.sample.json in the current directory.

	.EXAMPLE
	PS> Edit-KeeperNSFRecords -FilePath .\nsf-records-update-batch.sample.json

	.EXAMPLE
	PS> Edit-KeeperNSFRecords -Json '{"records":[{"uid":"<recordUid>","title":"Renamed","login":"a","password":"secret"}]}'
#>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium', DefaultParameterSetName = 'File')]
    Param (
        [Parameter(Mandatory = $true, ParameterSetName = 'File')]
        [Parameter(Mandatory = $false, ParameterSetName = 'DownloadSample')]
        [ValidateNotNullOrEmpty()]
        [string] $FilePath,

        [Parameter(Mandatory = $true, ParameterSetName = 'Json')]
        [ValidateNotNullOrEmpty()]
        [string] $Json,

        [Parameter(Mandatory = $false, ParameterSetName = 'DownloadSample')]
        [switch] $DownloadSampleRecords
    )

    try {
        [KeeperSecurity.Vault.VaultOnline]$vault = getVault
    }
    catch {
        Write-Error "Not connected to Keeper. Please login first."
        return
    }

    if ($DownloadSampleRecords) {
        if (-not $FilePath) {
            $FilePath = 'nsf-records-update-batch.sample.json'
        }

        $fullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($FilePath)
        $parentDir = Split-Path -Parent $fullPath
        if ($parentDir -and -not (Test-Path -LiteralPath $parentDir)) {
            New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
        }

        $sampleJson = Get-KeeperNSFBatchUpdateSampleJson
        $utf8NoBom = New-Object System.Text.UTF8Encoding $false
        [System.IO.File]::WriteAllText($fullPath, $sampleJson, $utf8NoBom)

        Write-Host "Sample NSF batch update file written to: $fullPath" -ForegroundColor Green
        Write-Host "Replace REPLACE_WITH_EXISTING_RECORD_UID_* values, edit fields, then run:"
        Write-Host "    Edit-KeeperNSFRecords -FilePath `"$FilePath`""
        return
    }

    if (-not $FilePath -and -not $Json) {
        Write-Error "FilePath or Json is required when -DownloadSampleRecords is not specified."
        return
    }

    try {
        $importFile = if ($PSCmdlet.ParameterSetName -eq 'File') {
            if (-not (Test-Path -LiteralPath $FilePath)) {
                throw "File not found: $FilePath"
            }
            Read-KeeperNSFImportFile -JsonText (Get-Content -LiteralPath $FilePath -Raw -Encoding UTF8)
        }
        else {
            Read-KeeperNSFImportFile -JsonText $Json
        }

        if (-not $importFile.Records -or $importFile.Records.Length -eq 0) {
            throw "Import file contains no records."
        }

        if ($importFile.SharedFolders -and $importFile.SharedFolders.Length -gt 0) {
            Write-Host "Note: shared_folders in the import file are ignored for NSF batch record update." -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "Error parsing import payload: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    if (-not $PSCmdlet.ShouldProcess("$($importFile.Records.Length) Keeper NSF record(s)", "Update Keeper NSF records")) {
        return
    }

    try {
        Write-Host "Updating $($importFile.Records.Length) Keeper NSF record(s) in batch..."
        $results = $vault.UpdateKeeperNSFRecordsFromImport($importFile).GetAwaiter().GetResult()

        $ok = @($results | Where-Object { $_.Success })
        $fail = @($results | Where-Object { -not $_.Success })
        Write-Host "Batch complete: $($ok.Count) succeeded, $($fail.Count) failed."
        Write-Host ""

        foreach ($result in $results) {
            if ($result.Success) {
                Write-Host "  [OK]   $($result.Title)  UID: $($result.RecordUid)" -ForegroundColor Green
            }
            else {
                $msg = if ($result.Message) { $result.Message } else { '(no message)' }
                Write-Host "  [FAIL] $($result.Title)  UID: $($result.RecordUid)  status=$($result.Status)  $msg" -ForegroundColor Red
            }
        }

        return ,@($results)
    }
    catch {
        Write-Host "Error updating records in batch: $($_.Exception.Message)" -ForegroundColor Red
    }
}

New-Alias -Name nsf-records-update -Value Edit-KeeperNSFRecords


function Set-KeeperNSFRecordAccess {
    <#
	.Synopsis
	Grant or revoke user access to a Keeper NSF record.

	.Description
	Shares or unshares a Keeper NSF record with a user using the v3 API.
	When granting, encrypts and sends the record key to the recipient.

	.Parameter RecordUid
	UID of the record to share/unshare.

	.Parameter Action
	Action to perform: 'grant' (default) or 'revoke'.

	.Parameter Email
	One or more user email addresses to grant/revoke access.

	.Parameter Role
	Access role for grant action: viewer (default), share-manager, content-manager,
	content-share-manager, full-manager.

	.Parameter ExpireIn
	Optional. Share expiration period from now (e.g. 30d, 6mo, 1y, 24h, 30mi), integer minutes,
	or a TimeSpan. Same as Grant-KeeperRecordAccess.

	.Parameter ExpireAt
	Optional. Absolute share expiration as ISO datetime (e.g. 2027-01-01T00:00:00Z).
#>
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseShouldProcessForStateChangingFunctions", "")]
    Param (
        [Parameter(Position = 0, Mandatory = $true)]
        [string] $RecordUid,

        [Parameter()]
        [ValidateSet('grant', 'revoke')]
        [string] $Action = 'grant',

        [Parameter(Mandatory = $true)]
        [string[]] $Email,

        [Parameter()]
        [ValidateSet('viewer', 'share-manager', 'content-manager', 'content-share-manager', 'full-manager')]
        [string] $Role = 'viewer',

        [Alias('expire-in')]
        [Parameter()]
        [System.Object] $ExpireIn,

        [Alias('expire-at')]
        [Parameter()]
        [string] $ExpireAt
    )

    try {
        [KeeperSecurity.Vault.VaultOnline]$vault = getVault
    } catch {
        Write-Host "Error getting vault: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    [KeeperSecurity.Vault.KeeperNSFRecord]$tmpRecord = $null
    if (-not $vault.TryGetKeeperNSFRecord($RecordUid, [ref]$tmpRecord)) {
        Write-Host "Error: NSF record '$RecordUid' not found." -ForegroundColor Red
        return
    }

    $shareOptions = $null
    if ($Action -eq 'grant' -and ($ExpireIn -or $ExpireAt)) {
        try {
            $expirationDto = Get-ExpirationDate -ExpireIn $ExpireIn -ExpireAt $ExpireAt
        }
        catch {
            Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
            return
        }
        $shareOptions = New-Object KeeperSecurity.Vault.SharedFolderRecordOptions
        $shareOptions.Expiration = $expirationDto
    }

    foreach ($user in $Email) {
        try {
            if ($Action -eq 'grant') {
                [void]$vault.ShareKeeperNSFRecord($RecordUid, $user, $Role, $shareOptions).GetAwaiter().GetResult()
                $expireMsg = if ($shareOptions -and $shareOptions.Expiration) {
                    " (expires $($shareOptions.Expiration.LocalDateTime.ToString('g')))"
                } else { '' }
                Write-Host "Granted '$Role' access to '$user' on record '$RecordUid'$expireMsg." -ForegroundColor Green
            }
            else {
                [void]$vault.UnshareKeeperNSFRecord($RecordUid, $user).GetAwaiter().GetResult()
                Write-Host "Revoked access for '$user' from record '$RecordUid'." -ForegroundColor Green
            }
        }
        catch {
            Write-Host "Error ${Action}ing access for '$user': $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

New-Alias -Name nsf-share-record -Value Set-KeeperNSFRecordAccess

function Share-KeeperNSFRecords {
    <#
	.Synopsis
	Batch-share Keeper NSF records (grant access) in chunks of up to 1000 shares per API request.

	.Description
	Uses vault/records/v3/share batching. Independent of Set-KeeperNSFRecordAccess / nsf-share-record.
	Accepts JSON with a "shares" array. Each item: uid (or record_uid), email, optional role (default viewer),
	optional expire_in (e.g. 30d) or expire_at (ISO datetime).

	.Parameter FilePath
	Path to a UTF-8 JSON share file.

	.Parameter Json
	Inline JSON string (same schema as -FilePath).

	.Parameter DownloadSampleShares
	Writes a sample batch share JSON file and exits without sharing.

	.EXAMPLE
	PS> Share-KeeperNSFRecords -DownloadSampleShares

	.EXAMPLE
	PS> Share-KeeperNSFRecords -DownloadSampleShares -FilePath .\my-nsf-share-batch.json

	.EXAMPLE
	PS> Share-KeeperNSFRecords -FilePath .\nsf-records-share-batch.sample.json
#>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium', DefaultParameterSetName = 'File')]
    Param(
        [Parameter(Mandatory = $true, ParameterSetName = 'File')]
        [Parameter(Mandatory = $false, ParameterSetName = 'DownloadSample')]
        [ValidateNotNullOrEmpty()]
        [string] $FilePath,

        [Parameter(Mandatory = $true, ParameterSetName = 'Json')]
        [ValidateNotNullOrEmpty()]
        [string] $Json,

        [Parameter(Mandatory = $false, ParameterSetName = 'DownloadSample')]
        [switch] $DownloadSampleShares
    )

    try {
        [KeeperSecurity.Vault.VaultOnline]$vault = getVault
    }
    catch {
        Write-Error "Not connected to Keeper. Please login first."
        return
    }

    if ($DownloadSampleShares) {
        if (-not $FilePath) {
            $FilePath = 'nsf-records-share-batch.sample.json'
        }

        $fullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($FilePath)
        $parentDir = Split-Path -Parent $fullPath
        if ($parentDir -and -not (Test-Path -LiteralPath $parentDir)) {
            New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
        }

        $sampleJson = Get-KeeperNSFShareBatchSampleJson
        $utf8NoBom = New-Object System.Text.UTF8Encoding $false
        [System.IO.File]::WriteAllText($fullPath, $sampleJson, $utf8NoBom)

        Write-Host "Sample NSF share batch file written to: $fullPath" -ForegroundColor Green
        Write-Host "Edit the file with record UIDs and emails, then run:"
        Write-Host "    Share-KeeperNSFRecords -FilePath `"$FilePath`""
        return
    }

    if (-not $FilePath -and -not $Json) {
        Write-Error "FilePath or Json is required when -DownloadSampleShares is not specified."
        return
    }

    try {
        $jsonText = if ($PSCmdlet.ParameterSetName -eq 'File') {
            if (-not (Test-Path -LiteralPath $FilePath)) {
                throw "File not found: $FilePath"
            }
            Get-Content -LiteralPath $FilePath -Raw -Encoding UTF8
        }
        else {
            $Json
        }

        $shareRequests = ConvertTo-KeeperNSFShareRequests -JsonText $jsonText
        if (-not $shareRequests -or $shareRequests.Count -eq 0) {
            throw "Share file contains no shares."
        }

        # Ensure a typed IList so PowerShell does not pass Object[] into ShareKeeperNSFRecords.
        if ($shareRequests -isnot [System.Collections.Generic.List[KeeperSecurity.Vault.KeeperNSFRecordShareRequest]]) {
            $typed = New-Object 'System.Collections.Generic.List[KeeperSecurity.Vault.KeeperNSFRecordShareRequest]'
            foreach ($item in @($shareRequests)) {
                if ($item -is [KeeperSecurity.Vault.KeeperNSFRecordShareRequest]) {
                    $typed.Add($item) | Out-Null
                }
            }
            $shareRequests = $typed
        }
    }
    catch {
        Write-Host "Error parsing share payload: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    if (-not $PSCmdlet.ShouldProcess("$($shareRequests.Count) Keeper NSF record share(s)", "Share Keeper NSF records")) {
        return
    }

    try {
        Write-Host "Sharing $($shareRequests.Count) Keeper NSF record access(es) in batch..."
        $shareList = [System.Collections.Generic.List[KeeperSecurity.Vault.KeeperNSFRecordShareRequest]]$shareRequests
        $results = $vault.ShareKeeperNSFRecords($shareList).GetAwaiter().GetResult()

        $ok = @($results | Where-Object { $_.Success })
        $fail = @($results | Where-Object { -not $_.Success })
        Write-Host "Batch complete: $($ok.Count) succeeded, $($fail.Count) failed."
        Write-Host ""

        foreach ($result in $results) {
            if ($result.Success) {
                Write-Host "  [OK]   $($result.RecordUid) -> $($result.UserEmail) ($($result.Role))" -ForegroundColor Green
            }
            else {
                $msg = if ($result.Message) { $result.Message } else { '(no message)' }
                Write-Host "  [FAIL] $($result.RecordUid) -> $($result.UserEmail)  status=$($result.Status)  $msg" -ForegroundColor Red
            }
        }

        return ,@($results)
    }
    catch {
        Write-Host "Error sharing records in batch: $($_.Exception.Message)" -ForegroundColor Red
    }
}

New-Alias -Name nsf-share-records -Value Share-KeeperNSFRecords

function Script:ConvertTo-KeeperNSFShareRequests {
    Param(
        [Parameter(Mandatory = $true)]
        [string] $JsonText
    )

    $parsed = $JsonText | ConvertFrom-Json -ErrorAction Stop
    $items = @()
    if ($null -ne $parsed.shares) {
        $items = @($parsed.shares)
    }
    elseif ($parsed -is [System.Array]) {
        $items = @($parsed)
    }
    else {
        throw "JSON must contain a 'shares' array (or be a root array of share objects)."
    }

    $list = New-Object 'System.Collections.Generic.List[KeeperSecurity.Vault.KeeperNSFRecordShareRequest]'
    $validRoles = @('viewer', 'share-manager', 'content-manager', 'content-share-manager', 'full-manager')
    $index = 0
    foreach ($item in $items) {
        $uid = $null
        if ($item.uid) { $uid = [string]$item.uid }
        elseif ($item.record_uid) { $uid = [string]$item.record_uid }
        elseif ($item.RecordUid) { $uid = [string]$item.RecordUid }

        $email = $null
        if ($item.email) { $email = [string]$item.email }
        elseif ($item.user_email) { $email = [string]$item.user_email }
        elseif ($item.UserEmail) { $email = [string]$item.UserEmail }

        if ([string]::IsNullOrWhiteSpace($uid)) {
            throw "Share item at index $index is missing required 'uid' (or record_uid)."
        }
        if ([string]::IsNullOrWhiteSpace($email)) {
            throw "Share item at index $index is missing required 'email' (or user_email)."
        }

        $role = 'viewer'
        if ($item.role) { $role = [string]$item.role }
        $roleNormalized = $role.Trim().ToLowerInvariant()
        if ($validRoles -notcontains $roleNormalized) {
            throw "Invalid role '$role' at share index $index. Valid roles: $($validRoles -join ', ')."
        }

        $req = New-Object KeeperSecurity.Vault.KeeperNSFRecordShareRequest
        $req.RecordUid = $uid.Trim()
        $req.UserEmail = $email.Trim()
        $req.Role = $roleNormalized

        $expireIn = $null
        if ($item.expire_in) { $expireIn = $item.expire_in }
        elseif ($item.ExpireIn) { $expireIn = $item.ExpireIn }

        $expireAt = $null
        if ($item.expire_at) { $expireAt = [string]$item.expire_at }
        elseif ($item.ExpireAt) { $expireAt = [string]$item.ExpireAt }

        if ($expireIn -or $expireAt) {
            $expirationDto = Get-ExpirationDate -ExpireIn $expireIn -ExpireAt $expireAt
            $shareOptions = New-Object KeeperSecurity.Vault.SharedFolderRecordOptions
            $shareOptions.Expiration = $expirationDto
            $req.Options = $shareOptions
        }

        $list.Add($req) | Out-Null
        $index++
    }

    # Leading comma prevents PowerShell from unrolling the List into Object[].
    return ,$list
}

function Unshare-KeeperNSFRecords {
    <#
	.Synopsis
	Batch-unshare Keeper NSF records (revoke access) in chunks of up to 1000 per API request.

	.Description
	Uses vault/records/v3/share revokeSharingPermissions (and deny for inherited access).
	Independent of Set-KeeperNSFRecordAccess / nsf-share-record.
	Accepts JSON with an "unshares" array. Each item: uid (or record_uid), email.

	.Parameter FilePath
	Path to a UTF-8 JSON unshare file.

	.Parameter Json
	Inline JSON string (same schema as -FilePath).

	.Parameter DownloadSampleUnshares
	Writes a sample batch unshare JSON file and exits without unsharing.

	.EXAMPLE
	PS> Unshare-KeeperNSFRecords -DownloadSampleUnshares

	.EXAMPLE
	PS> Unshare-KeeperNSFRecords -DownloadSampleUnshares -FilePath .\my-nsf-unshare-batch.json

	.EXAMPLE
	PS> Unshare-KeeperNSFRecords -FilePath .\nsf-records-unshare-batch.sample.json
#>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium', DefaultParameterSetName = 'File')]
    Param(
        [Parameter(Mandatory = $true, ParameterSetName = 'File')]
        [Parameter(Mandatory = $false, ParameterSetName = 'DownloadSample')]
        [ValidateNotNullOrEmpty()]
        [string] $FilePath,

        [Parameter(Mandatory = $true, ParameterSetName = 'Json')]
        [ValidateNotNullOrEmpty()]
        [string] $Json,

        [Parameter(Mandatory = $false, ParameterSetName = 'DownloadSample')]
        [switch] $DownloadSampleUnshares
    )

    try {
        [KeeperSecurity.Vault.VaultOnline]$vault = getVault
    }
    catch {
        Write-Error "Not connected to Keeper. Please login first."
        return
    }

    if ($DownloadSampleUnshares) {
        if (-not $FilePath) {
            $FilePath = 'nsf-records-unshare-batch.sample.json'
        }

        $fullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($FilePath)
        $parentDir = Split-Path -Parent $fullPath
        if ($parentDir -and -not (Test-Path -LiteralPath $parentDir)) {
            New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
        }

        $sampleJson = Get-KeeperNSFUnshareBatchSampleJson
        $utf8NoBom = New-Object System.Text.UTF8Encoding $false
        [System.IO.File]::WriteAllText($fullPath, $sampleJson, $utf8NoBom)

        Write-Host "Sample NSF unshare batch file written to: $fullPath" -ForegroundColor Green
        Write-Host "Edit the file with record UIDs and emails, then run:"
        Write-Host "    Unshare-KeeperNSFRecords -FilePath `"$FilePath`""
        return
    }

    if (-not $FilePath -and -not $Json) {
        Write-Error "FilePath or Json is required when -DownloadSampleUnshares is not specified."
        return
    }

    try {
        $jsonText = if ($PSCmdlet.ParameterSetName -eq 'File') {
            if (-not (Test-Path -LiteralPath $FilePath)) {
                throw "File not found: $FilePath"
            }
            Get-Content -LiteralPath $FilePath -Raw -Encoding UTF8
        }
        else {
            $Json
        }

        $unshareRequests = ConvertTo-KeeperNSFUnshareRequests -JsonText $jsonText
        if (-not $unshareRequests -or $unshareRequests.Count -eq 0) {
            throw "Unshare file contains no unshares."
        }

        if ($unshareRequests -isnot [System.Collections.Generic.List[KeeperSecurity.Vault.KeeperNSFRecordUnshareRequest]]) {
            $typed = New-Object 'System.Collections.Generic.List[KeeperSecurity.Vault.KeeperNSFRecordUnshareRequest]'
            foreach ($item in @($unshareRequests)) {
                if ($item -is [KeeperSecurity.Vault.KeeperNSFRecordUnshareRequest]) {
                    $typed.Add($item) | Out-Null
                }
            }
            $unshareRequests = $typed
        }
    }
    catch {
        Write-Host "Error parsing unshare payload: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    if (-not $PSCmdlet.ShouldProcess("$($unshareRequests.Count) Keeper NSF record unshare(s)", "Unshare Keeper NSF records")) {
        return
    }

    try {
        Write-Host "Revoking $($unshareRequests.Count) Keeper NSF record access(es) in batch..."
        $unshareList = [System.Collections.Generic.List[KeeperSecurity.Vault.KeeperNSFRecordUnshareRequest]]$unshareRequests
        $results = $vault.UnshareKeeperNSFRecords($unshareList).GetAwaiter().GetResult()

        $ok = @($results | Where-Object { $_.Success })
        $fail = @($results | Where-Object { -not $_.Success })
        Write-Host "Batch complete: $($ok.Count) succeeded, $($fail.Count) failed."
        Write-Host ""

        foreach ($result in $results) {
            if ($result.Success) {
                Write-Host "  [OK]   $($result.RecordUid) -> $($result.UserEmail)" -ForegroundColor Green
            }
            else {
                $msg = if ($result.Message) { $result.Message } else { '(no message)' }
                Write-Host "  [FAIL] $($result.RecordUid) -> $($result.UserEmail)  status=$($result.Status)  $msg" -ForegroundColor Red
            }
        }

        return ,@($results)
    }
    catch {
        Write-Host "Error unsharing records in batch: $($_.Exception.Message)" -ForegroundColor Red
    }
}

New-Alias -Name nsf-unshare-records -Value Unshare-KeeperNSFRecords

function Script:ConvertTo-KeeperNSFUnshareRequests {
    Param(
        [Parameter(Mandatory = $true)]
        [string] $JsonText
    )

    $parsed = $JsonText | ConvertFrom-Json -ErrorAction Stop
    $items = @()
    if ($null -ne $parsed.unshares) {
        $items = @($parsed.unshares)
    }
    elseif ($null -ne $parsed.shares) {
        # Allow reuse of share-batch JSON (uid/email only; role ignored).
        $items = @($parsed.shares)
    }
    elseif ($parsed -is [System.Array]) {
        $items = @($parsed)
    }
    else {
        throw "JSON must contain an 'unshares' array (or be a root array of unshare objects)."
    }

    $list = New-Object 'System.Collections.Generic.List[KeeperSecurity.Vault.KeeperNSFRecordUnshareRequest]'
    $index = 0
    foreach ($item in $items) {
        $uid = $null
        if ($item.uid) { $uid = [string]$item.uid }
        elseif ($item.record_uid) { $uid = [string]$item.record_uid }
        elseif ($item.RecordUid) { $uid = [string]$item.RecordUid }

        $email = $null
        if ($item.email) { $email = [string]$item.email }
        elseif ($item.user_email) { $email = [string]$item.user_email }
        elseif ($item.UserEmail) { $email = [string]$item.UserEmail }

        if ([string]::IsNullOrWhiteSpace($uid)) {
            throw "Unshare item at index $index is missing required 'uid' (or record_uid)."
        }
        if ([string]::IsNullOrWhiteSpace($email)) {
            throw "Unshare item at index $index is missing required 'email' (or user_email)."
        }

        $req = New-Object KeeperSecurity.Vault.KeeperNSFRecordUnshareRequest
        $req.RecordUid = $uid.Trim()
        $req.UserEmail = $email.Trim()
        $list.Add($req) | Out-Null
        $index++
    }

    return ,$list
}

function Script:ConvertTo-KeeperNSFRemovalSpecs {
    Param(
        [Parameter(Mandatory = $true)]
        [string] $JsonText
    )

    $parsed = $JsonText | ConvertFrom-Json -ErrorAction Stop
    $items = @()
    if ($null -ne $parsed.removals) {
        $items = @($parsed.removals)
    }
    elseif ($null -ne $parsed.records) {
        $items = @($parsed.records)
    }
    elseif ($parsed -is [System.Array]) {
        $items = @($parsed)
    }
    else {
        throw "JSON must contain a 'removals' array (or be a root array of removal objects)."
    }

    $list = New-Object 'System.Collections.Generic.List[pscustomobject]'
    foreach ($item in $items) {
        $uid = $null
        if ($item.uid) { $uid = [string]$item.uid }
        elseif ($item.record_uid) { $uid = [string]$item.record_uid }
        elseif ($item.RecordUid) { $uid = [string]$item.RecordUid }

        if ([string]::IsNullOrWhiteSpace($uid)) {
            throw "Each removal item must include uid (or record_uid)."
        }

        $folder = $null
        if ($item.folder) { $folder = [string]$item.folder }
        elseif ($item.folder_uid) { $folder = [string]$item.folder_uid }
        elseif ($item.FolderUid) { $folder = [string]$item.FolderUid }

        $operation = 'owner-trash'
        if ($item.operation) { $operation = [string]$item.operation }
        elseif ($item.Operation) { $operation = [string]$item.Operation }

        $operation = $operation.Trim().ToLowerInvariant()
        if ($operation -notin @('owner-trash', 'folder-trash', 'unlink')) {
            throw "Invalid operation '$operation' for uid '$uid'. Use owner-trash, folder-trash, or unlink."
        }

        $list.Add([pscustomobject]@{
                RecordUid = $uid
                Folder    = $folder
                Operation = $operation
            }) | Out-Null
    }

    return ,$list
}

#    Before: function Link-KeeperNSFRecord
# -----------------------------------------------------------------------------


function Set-KeeperNSFRecordPermission {
    <#
	.Synopsis
	Bulk grant or revoke record-level sharing permissions for records in a Keeper NSF folder.

	.Description
	Modifies sharing permissions on all records within a Keeper NSF folder using the v3 API.
	Fetches current access permissions, computes required changes, displays a plan, and
	executes the changes after confirmation.

	.Parameter FolderUid
	Folder UID or name containing the records. If omitted, operates on root-level records.

	.Parameter Action
	Action to perform: 'grant' or 'revoke'.

	.Parameter Role
	Access role: viewer, share-manager, content-manager, content-share-manager, full-manager.
	Required for grant action. For revoke, if specified, only revokes users with that role.

	.Parameter Recursive
	If specified, includes records in subfolders.

	.Parameter Force
	Skip confirmation prompt.

	.Parameter DryRun
	Show what would change without making modifications.
#>
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseShouldProcessForStateChangingFunctions", "")]
    Param (
        [Parameter(Position = 0)]
        [string] $FolderUid,

        [Parameter(Mandatory = $true)]
        [ValidateSet('grant', 'revoke')]
        [string] $Action,

        [Parameter()]
        [ValidateSet('viewer', 'share-manager', 'content-manager', 'content-share-manager', 'full-manager')]
        [string] $Role,

        [Parameter()]
        [switch] $Recursive,

        [Parameter()]
        [switch] $Force,

        [Parameter()]
        [switch] $DryRun
    )

    if ($Action -eq 'grant' -and -not $Role) {
        Write-Host "Error: -Role is required for grant action." -ForegroundColor Red
        return
    }

    try {
        [KeeperSecurity.Vault.VaultOnline]$vault = getVault
    } catch {
        Write-Host "Error getting vault: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    if ($FolderUid) {
        [KeeperSecurity.Vault.FolderNode]$tmpFolder = $null
        if (-not $vault.TryGetKeeperNSFFolder($FolderUid, [ref]$tmpFolder)) {
            foreach ($f in $vault.KeeperNSFFolderNodes) {
                if ($f.Name -and $f.Name -ieq $FolderUid) { $FolderUid = $f.FolderUid; break }
            }
        }
    }

    $folderDisplay = if ($FolderUid) { $FolderUid } else { 'root' }
    $roleLabel = if ($Role) { "'$Role'" } else { 'all' }
    $scopeLabel = if ($Recursive.IsPresent) { 'recursively' } else { 'only' }
    Write-Host ""
    Write-Host "Request to $($Action.ToUpper()) $roleLabel permission(s) in '$folderDisplay' folder $scopeLabel" -ForegroundColor Cyan

    try {
        $permResult = $vault.UpdateKeeperNSFRecordPermissions($FolderUid, $Action, $Role, $Recursive.IsPresent, $true).GetAwaiter().GetResult()
    }
    catch {
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    $hasChanges = ($permResult.Grants.Count -gt 0) -or ($permResult.Revokes.Count -gt 0) -or ($permResult.Denies.Count -gt 0)

    if ($permResult.Skipped.Count -gt 0) {
        Write-Host ""
        Write-Host "  SKIPPED ($($permResult.Skipped.Count)):" -ForegroundColor Yellow
        foreach ($s in $permResult.Skipped) {
            $email = if ($s.Email) { $s.Email } else { '-' }
            $curRole = if ($s.CurrentRole) { $s.CurrentRole } else { '-' }
            Write-Host "    $($s.RecordUid)  $email  [$curRole]  $($s.Message)"
        }
    }

    if ($permResult.Grants.Count -gt 0) {
        Write-Host ""
        Write-Host "  PLANNED GRANTS ($($permResult.Grants.Count)):" -ForegroundColor Green
        foreach ($g in $permResult.Grants) {
            $inherited = if ($g.ChangeType -eq 'create') { ' (inherited override)' } else { '' }
            Write-Host "    $($g.RecordUid)  $($g.Email)  $($g.CurrentRole) -> $($g.NewRole)$inherited"
        }
    }

    if ($permResult.Revokes.Count -gt 0) {
        Write-Host ""
        Write-Host "  PLANNED REVOKES ($($permResult.Revokes.Count)):" -ForegroundColor Red
        foreach ($r in $permResult.Revokes) {
            Write-Host "    $($r.RecordUid)  $($r.Email)  [$($r.CurrentRole)]"
        }
    }

    if ($permResult.Denies.Count -gt 0) {
        Write-Host ""
        Write-Host "  PLANNED DENIES ($($permResult.Denies.Count)):" -ForegroundColor Magenta
        foreach ($d in $permResult.Denies) {
            $inherited = if ($d.ChangeType -eq 'deny') { ' (inherited override)' } else { '' }
            Write-Host "    $($d.RecordUid)  $($d.Email)  [$($d.CurrentRole)]$inherited"
        }
    }

    if (-not $hasChanges -and $permResult.Skipped.Count -eq 0) {
        Write-Host "No permission changes are needed." -ForegroundColor DarkYellow
        return
    }

    if ($DryRun.IsPresent) {
        Write-Host ""
        Write-Host "[Dry-run mode - no changes were made]" -ForegroundColor Yellow
        $planTotal = $permResult.Grants.Count + $permResult.Revokes.Count + $permResult.Denies.Count
        Write-Host "Summary: $planTotal planned, $($permResult.Skipped.Count) skipped" -ForegroundColor Cyan
        return
    }

    if (-not $hasChanges) {
        Write-Host ""
        Write-Host "Summary: 0 changes, $($permResult.Skipped.Count) skipped" -ForegroundColor Cyan
        return
    }

    if (-not $Force) {
        $confirmation = Read-Host "Are you sure you want to apply the above changes? (yes/No)"
        if ($confirmation -notmatch '^(y|yes)$') {
            Write-Host "Update operation cancelled"
            return
        }
    }

    try {
        $permResult = $vault.UpdateKeeperNSFRecordPermissions($FolderUid, $Action, $Role, $Recursive.IsPresent, $false).GetAwaiter().GetResult()
    }
    catch {
        Write-Host "Error executing changes: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    if ($permResult.Grants.Count -gt 0) {
        Write-Host ""
        Write-Host "  GRANT ($($permResult.Grants.Count)):" -ForegroundColor Green
        foreach ($g in $permResult.Grants) {
            $statusIcon = if ($g.Success) { '[OK]' } else { '[FAIL]' }
            $statusColor = if ($g.Success) { 'Green' } else { 'Red' }
            $inherited = if ($g.ChangeType -eq 'create') { ' (inherited override)' } else { '' }
            Write-Host "    $statusIcon $($g.RecordUid)  $($g.Email)  $($g.CurrentRole) -> $($g.NewRole)$inherited" -ForegroundColor $statusColor
            if (-not $g.Success -and $g.Message) {
                Write-Host "         Error: $($g.Message)" -ForegroundColor Red
            }
        }
    }

    if ($permResult.Revokes.Count -gt 0) {
        Write-Host ""
        Write-Host "  REVOKE ($($permResult.Revokes.Count)):" -ForegroundColor Red
        foreach ($r in $permResult.Revokes) {
            $statusIcon = if ($r.Success) { '[OK]' } else { '[FAIL]' }
            $statusColor = if ($r.Success) { 'Green' } else { 'Red' }
            Write-Host "    $statusIcon $($r.RecordUid)  $($r.Email)  [$($r.CurrentRole)]" -ForegroundColor $statusColor
            if (-not $r.Success -and $r.Message) {
                Write-Host "         Error: $($r.Message)" -ForegroundColor Red
            }
        }
    }

    if ($permResult.Denies.Count -gt 0) {
        Write-Host ""
        Write-Host "  DENY ($($permResult.Denies.Count)):" -ForegroundColor Magenta
        foreach ($d in $permResult.Denies) {
            $statusIcon = if ($d.Success) { '[OK]' } else { '[FAIL]' }
            $statusColor = if ($d.Success) { 'Green' } else { 'Red' }
            $inherited = if ($d.ChangeType -eq 'deny') { ' (inherited override)' } else { '' }
            Write-Host "    $statusIcon $($d.RecordUid)  $($d.Email)  [$($d.CurrentRole)]$inherited" -ForegroundColor $statusColor
            if (-not $d.Success -and $d.Message) {
                Write-Host "         Error: $($d.Message)" -ForegroundColor Red
            }
        }
    }

    $successCount = ($permResult.Grants | Where-Object { $_.Success }).Count + ($permResult.Revokes | Where-Object { $_.Success }).Count + ($permResult.Denies | Where-Object { $_.Success }).Count
    $failCount = ($permResult.Grants | Where-Object { -not $_.Success }).Count + ($permResult.Revokes | Where-Object { -not $_.Success }).Count + ($permResult.Denies | Where-Object { -not $_.Success }).Count
    Write-Host ""
    Write-Host "Summary: $successCount succeeded, $failCount failed, $($permResult.Skipped.Count) skipped" -ForegroundColor Cyan
}

New-Alias -Name nsf-record-permission -Value Set-KeeperNSFRecordPermission

function Get-KeeperNSFShortcut {
    <#
	.Synopsis
	Lists Keeper NSF records that appear in more than one folder (shortcuts).

	.Description
	Scans all Keeper NSF folder-record links and reports records that exist
	in two or more folders. Optionally filters by a specific record UID/title
	or folder UID/name.

	.Parameter Target
	Optional record UID, record title, folder UID, or folder name to filter results.

	.Parameter Format
	Output format: table (default), csv, or json.

	.Parameter Output
	Path to output file. Ignored for table format.
#>
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0)]
        [string] $Target,

        [Parameter()]
        [ValidateSet('table', 'csv', 'json')]
        [string] $Format = 'table',

        [Parameter()]
        [string] $Output
    )

    try {
        [KeeperSecurity.Vault.VaultOnline]$vault = getVault
    } catch {
        Write-Host "Error getting vault: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    $recordUid = $null
    $folderUid = $null

    if ($Target) {
        [KeeperSecurity.Vault.KeeperNSFRecord]$tmpRecord = $null
        if ($vault.TryGetKeeperNSFRecord($Target, [ref]$tmpRecord)) {
            $recordUid = $Target
        } else {
            [KeeperSecurity.Vault.FolderNode]$tmpFolder = $null
            if ($vault.TryGetKeeperNSFFolder($Target, [ref]$tmpFolder)) {
                $folderUid = $Target
            } else {
                $foundByTitle = $false
                foreach ($r in $vault.KeeperNSFRecordEntries) {
                    if ($r.Title -and $r.Title -ieq $Target) {
                        $recordUid = $r.RecordUid
                        $foundByTitle = $true
                        break
                    }
                }
                if (-not $foundByTitle) {
                    foreach ($f in $vault.KeeperNSFFolderNodes) {
                        if ($f.Name -and $f.Name -ieq $Target) {
                            $folderUid = $f.FolderUid
                            $foundByTitle = $true
                            break
                        }
                    }
                }
                if (-not $foundByTitle) {
                    Write-Host "Error: Target '$Target' not found as record UID, title, folder UID, or folder name." -ForegroundColor Red
                    return
                }
            }
        }
    }

    try {
        $entries = $vault.GetKeeperNSFShortcuts($recordUid, $folderUid)
    } catch {
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    if ($entries.Count -eq 0) {
        Write-Host "No shortcut records found." -ForegroundColor DarkYellow
        return
    }

    if ($Format -eq 'json') {
        $jsonItems = @()
        foreach ($e in $entries) {
            $folders = @()
            foreach ($f in $e.Folders) {
                $folders += [ordered]@{ folder_uid = $f.FolderUid; name = $f.Name }
            }
            $jsonItems += [ordered]@{
                record_uid   = $e.RecordUid
                record_title = $e.Title
                folders      = $folders
            }
        }
        $jsonText = $jsonItems | ConvertTo-Json -Depth 4
        if ($Output) {
            $jsonText | Out-File -FilePath $Output -Encoding utf8
            Write-Host "JSON output written to '$Output' ($($entries.Count) shortcuts)." -ForegroundColor Green
        } else {
            $jsonText
        }
        return
    }

    if ($Format -eq 'csv') {
        $csvData = @()
        foreach ($e in $entries) {
            $folderNames = ($e.Folders | ForEach-Object { $_.Name }) -join '; '
            $folderUids  = ($e.Folders | ForEach-Object { $_.FolderUid }) -join '; '
            $csvData += [PSCustomObject]@{
                RecordUid   = $e.RecordUid
                Title       = $e.Title
                FolderCount = $e.Folders.Count
                FolderUids  = $folderUids
                FolderNames = $folderNames
            }
        }
        if ($Output) {
            $csvData | Export-Csv -Path $Output -NoTypeInformation -Encoding utf8
            Write-Host "CSV output written to '$Output' ($($entries.Count) shortcuts)." -ForegroundColor Green
        } else {
            $csvData | ConvertTo-Csv -NoTypeInformation
        }
        return
    }

    Write-Host ""
    Write-Host "  Shortcut Records ($($entries.Count)):" -ForegroundColor Cyan
    Write-Host ""
    foreach ($e in $entries) {
        Write-Host "  $($e.RecordUid)  $($e.Title)  [$($e.Folders.Count) folders]" -ForegroundColor White
        foreach ($f in $e.Folders) {
            Write-Host "    - $($f.Name) ($($f.FolderUid))"
        }
    }
    Write-Host ""
}

New-Alias -Name nsf-shortcut-list -Value Get-KeeperNSFShortcut

function Set-KeeperNSFShortcutKeep {
    <#
	.Synopsis
	Keep a Keeper NSF record in one folder and remove it from all others.

	.Description
	For a record that appears in multiple Keeper NSF folders (a shortcut),
	keeps it in the specified folder and unlinks it from all other folders.

	.Parameter RecordUid
	Record UID or title of the record.

	.Parameter FolderUid
	Folder UID or folder name to keep the record in.

	.Parameter Force
	Skip confirmation prompt.
#>
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseShouldProcessForStateChangingFunctions", "")]
    Param (
        [Parameter(Position = 0, Mandatory = $true)]
        [string] $RecordUid,

        [Parameter(Position = 1, Mandatory = $true)]
        [string] $FolderUid,

        [Parameter()]
        [switch] $Force
    )

    try {
        [KeeperSecurity.Vault.VaultOnline]$vault = getVault
    } catch {
        Write-Host "Error getting vault: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    [KeeperSecurity.Vault.KeeperNSFRecord]$tmpRecord = $null
    if (-not $vault.TryGetKeeperNSFRecord($RecordUid, [ref]$tmpRecord)) {
        $found = $false
        foreach ($r in $vault.KeeperNSFRecordEntries) {
            if ($r.Title -and $r.Title -ieq $RecordUid) {
                $RecordUid = $r.RecordUid
                $found = $true
                break
            }
        }
        if (-not $found) {
            Write-Host "Error: Record '$RecordUid' not found." -ForegroundColor Red
            return
        }
    }

    [KeeperSecurity.Vault.FolderNode]$tmpFolder = $null
    if (-not $vault.TryGetKeeperNSFFolder($FolderUid, [ref]$tmpFolder)) {
        $found = $false
        foreach ($f in $vault.KeeperNSFFolderNodes) {
            if ($f.Name -and $f.Name -ieq $FolderUid) {
                $FolderUid = $f.FolderUid
                $found = $true
                break
            }
        }
        if (-not $found) {
            Write-Host "Error: Folder '$FolderUid' not found." -ForegroundColor Red
            return
        }
    }

    $shortcuts = $vault.GetKeeperNSFShortcuts($RecordUid, $null)
    if ($shortcuts.Count -eq 0) {
        Write-Host "Record '$RecordUid' does not appear in multiple folders." -ForegroundColor DarkYellow
        return
    }

    $entry = $shortcuts[0]
    $keepFolder = $entry.Folders | Where-Object { $_.FolderUid -eq $FolderUid }
    if (-not $keepFolder) {
        Write-Host "Error: Record '$RecordUid' is not in folder '$FolderUid'." -ForegroundColor Red
        return
    }

    $removeFolders = $entry.Folders | Where-Object { $_.FolderUid -ne $FolderUid }

    if (-not $Force) {
        Write-Host ""
        Write-Host "  Will remove record '$($entry.Title)' ($RecordUid) from:" -ForegroundColor Yellow
        foreach ($rf in $removeFolders) {
            Write-Host "    - $($rf.Name) ($($rf.FolderUid))"
        }
        Write-Host "  Keeping in: $($keepFolder.Name) ($($keepFolder.FolderUid))" -ForegroundColor Green
        Write-Host ""
        $confirmation = Read-Host "Are you sure you want to keep the record only in '$($keepFolder.Name)' and remove it from the other folder(s) above? (yes/No)"
        if ($confirmation -notmatch '^(y|yes)$') {
            Write-Host "Shortcut-keep operation cancelled"
            return
        }
    }

    try {
        $result = $vault.KeepKeeperNSFRecordInFolder($RecordUid, $FolderUid).GetAwaiter().GetResult()
    } catch {
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    $successCount = ($result.Removals | Where-Object { $_.Success }).Count
    $failCount = ($result.Removals | Where-Object { -not $_.Success }).Count

    foreach ($removal in $result.Removals) {
        if ($removal.Success) {
            Write-Host "  [OK] Removed from '$($removal.FolderName)' ($($removal.FolderUid))" -ForegroundColor Green
        } else {
            Write-Host "  [FAIL] '$($removal.FolderName)' ($($removal.FolderUid)): $($removal.Message)" -ForegroundColor Red
        }
    }

    Write-Host ""
    Write-Host "Record kept in '$($result.KeptFolderName)'. $successCount removed, $failCount failed." -ForegroundColor Cyan
}

New-Alias -Name nsf-shortcut-keep -Value Set-KeeperNSFShortcutKeep

function Remove-KeeperNSFRecord {
    <#
	.Synopsis
	Removes one or more Keeper NSF records (Keeper NSF v3 API).

	.Parameter Record
	One or more record UIDs or titles.

	.Parameter Folder
	Folder UID or name that provides context (required for unlink).

	.Parameter Operation
	Removal operation: owner-trash, folder-trash, or unlink.

	.Parameter Force
	Skip confirmation after preview.

	.Parameter DryRun
	Preview only; do not remove records.

	.EXAMPLE
	PS> Remove-KeeperNSFRecord <recordUid>
	Moves one record to owner trash (default). Alias: nsf-rm <recordUid>

	.EXAMPLE
	PS> Remove-KeeperNSFRecord <recordUid> -DryRun
	Previews removal impact without deleting.

	.EXAMPLE
	PS> Remove-KeeperNSFRecord <recordUid1>,<recordUid2>,<recordUid3> -Force
	Removes multiple records in one batch (owner trash), skipping the confirmation prompt.

	.EXAMPLE
	PS> '<recordUid1>','<recordUid2>' | Remove-KeeperNSFRecord -Operation folder-trash -Folder <folderUid>
	Batch-removes records from a folder via the pipeline (folder trash).

	.EXAMPLE
	PS> nsf-rm <recordUid> -Operation unlink -Folder <folderUid> -Force
	Unlinks a single record from a folder without moving it to trash.

	.EXAMPLE
	PS> Remove-KeeperNSFRecords -DownloadSampleRemovals
	Writes nsf-records-remove-batch.sample.json for JSON batch remove (alias: nsf-records-rm).
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseShouldProcessForStateChangingFunctions", "")]
    [CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Default')]
    Param(
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true)]
        [string[]] $Record,

        [string] $Folder,

        [Alias('o')]
        [ValidateSet('owner-trash', 'folder-trash', 'unlink')]
        [string] $Operation = 'owner-trash',

        [Alias('f')]
        [switch] $Force,

        [switch] $DryRun
    )

    begin {
        [KeeperSecurity.Vault.VaultOnline]$vault = getVault
        $removals = New-Object 'System.Collections.Generic.List[KeeperSecurity.Vault.KeeperNSFRecordRemoval]'
        $folderHint = $null

        if ($Folder) {
            [KeeperSecurity.Vault.FolderNode]$folderNode = $null
            if (-not $vault.TryResolveKeeperNSFFolder($Folder, [ref]$folderNode)) {
                Write-Error -Message "Keeper NSF folder `"$Folder`" was not found. Run Sync-Keeper or nsf-list first."
                return
            }
            $folderHint = $Folder
        }
        elseif ($Operation -ne 'owner-trash' -and $Script:Context.CurrentFolder) {
            $folderHint = $Script:Context.CurrentFolder
        }

        $op = switch ($Operation) {
            'owner-trash' { [KeeperSecurity.Vault.KeeperNSFRecordRemoveOperation]::OwnerTrash }
            'folder-trash' { [KeeperSecurity.Vault.KeeperNSFRecordRemoveOperation]::FolderTrash }
            'unlink' { [KeeperSecurity.Vault.KeeperNSFRecordRemoveOperation]::Unlink }
        }

        if ($op -eq [KeeperSecurity.Vault.KeeperNSFRecordRemoveOperation]::Unlink -and [string]::IsNullOrWhiteSpace($folderHint)) {
            Write-Error -Message "Folder context is required for unlink. Use -Folder or cd into a Keeper NSF folder."
            return
        }
    }

    process {
        foreach ($name in $Record) {
            [KeeperSecurity.Vault.KeeperNSFRecord]$kdRecord = $null
            if (-not $vault.TryResolveKeeperNSFRecord($name, [ref]$kdRecord)) {
                Write-Error -Message "Keeper NSF record `"$name`" was not found. Run Sync-Keeper or nsf-list first."
                continue
            }

            [string]$folderUid = $null
            if (-not $vault.TryResolveKeeperNSFRecordRemovalFolder($kdRecord.RecordUid, $folderHint, $op, [ref]$folderUid)) {
                if ($Folder) {
                    Write-Error -Message "Keeper NSF folder `"$Folder`" was not found. Run Sync-Keeper or nsf-list first."
                }
                else {
                    Write-Error -Message "No folder context for record `"$name`". Use -Folder or -Operation owner-trash."
                }
                continue
            }

            $removal = New-Object KeeperSecurity.Vault.KeeperNSFRecordRemoval
            $removal.RecordUid = $kdRecord.RecordUid
            $removal.FolderUid = $folderUid
            $removal.Operation = $op
            $removals.Add($removal)
        }
    }

    end {
        if ($removals.Count -eq 0) {
            return
        }

        Write-Host ""
        Write-Host "=== Keeper NSF Remove Preview ===" -ForegroundColor Cyan
        $previewResult = $vault.RemoveKeeperNSFRecords($removals, $true).GetAwaiter().GetResult()
        Write-KeeperNSFRemoveImpact -Response $previewResult.PreviewResponse

        $previewErrors = @($previewResult.PreviewResponse.Results | Where-Object {
                $_.Error -and -not [string]::IsNullOrWhiteSpace($_.Error.Message)
            })
        if ($previewErrors.Count -gt 0) {
            Write-Host ""
            Write-Host "One or more records could not be previewed. Aborting." -ForegroundColor Yellow
            return
        }

        try {
            [KeeperSecurity.Vault.VaultOnline]::ValidateRemoveResponse($previewResult.PreviewResponse, $false)
        }
        catch {
            Write-Error -Message $_.Exception.Message
            return
        }

        if ($DryRun) {
            Write-Host ""
            Write-Host "Dry run: no records were removed." -ForegroundColor DarkYellow
            return
        }

        if (-not $Force) {
            $prompt = if ($Operation -eq 'owner-trash') {
                "Are you sure you want to move the record(s) above to your trash? (yes/No)"
            } elseif ($Operation -eq 'folder-trash') {
                "Are you sure you want to move the record(s) above to folder trash? (yes/No)"
            } else {
                "Are you sure you want to unlink the record(s) above from the folder? (yes/No)"
            }
            $confirmation = Read-Host $prompt
            if ($confirmation -notmatch '^(y|yes)$') {
                Write-Host "Remove operation cancelled"
                return
            }
        }

        if ($previewResult.PreviewResponse.ConfirmationToken.IsEmpty) {
            Write-Error -Message "Preview did not return a confirmation token."
            return
        }

        Write-Host ""
        Write-Host "Removing records..." -ForegroundColor Cyan
        $confirmResult = $vault.RemoveKeeperNSFRecords($removals, $false).GetAwaiter().GetResult()
        if (-not $confirmResult.Confirmed) {
            Write-Error -Message "Record removal was not confirmed by the server."
            return
        }

        $vault.SyncDown($false).GetAwaiter().GetResult() | Out-Null
        Write-Host ""
        Write-Host "Keeper NSF record removal completed." -ForegroundColor Green
    }
}
New-Alias -Name nsf-rm -Value Remove-KeeperNSFRecord

function Remove-KeeperNSFRecords {
    <#
	.Synopsis
	Batch-remove Keeper NSF records from a JSON file (Keeper NSF v3 API).

	.Description
	Accepts JSON with a "removals" array. Each item: uid (or record_uid), optional folder
	(folder_uid; required for unlink / recommended for folder-trash), optional operation
	(owner-trash default, folder-trash, or unlink).
	Independent of Remove-KeeperNSFRecord / nsf-rm (UID args or pipeline).

	.Parameter FilePath
	Path to a UTF-8 JSON remove file.

	.Parameter Json
	Inline JSON string (same schema as -FilePath).

	.Parameter DownloadSampleRemovals
	Writes a sample batch remove JSON file and exits without removing.

	.Parameter Force
	Skip confirmation after preview.

	.Parameter DryRun
	Preview only; do not remove records.

	.EXAMPLE
	PS> Remove-KeeperNSFRecords -DownloadSampleRemovals

	.EXAMPLE
	PS> Remove-KeeperNSFRecords -DownloadSampleRemovals -FilePath .\my-nsf-remove-batch.json

	.EXAMPLE
	PS> Remove-KeeperNSFRecords -FilePath .\nsf-records-remove-batch.sample.json

	.EXAMPLE
	PS> Remove-KeeperNSFRecords -FilePath .\nsf-records-remove-batch.sample.json -Force
#>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High', DefaultParameterSetName = 'File')]
    Param(
        [Parameter(Mandatory = $true, ParameterSetName = 'File')]
        [Parameter(Mandatory = $false, ParameterSetName = 'DownloadSample')]
        [ValidateNotNullOrEmpty()]
        [string] $FilePath,

        [Parameter(Mandatory = $true, ParameterSetName = 'Json')]
        [ValidateNotNullOrEmpty()]
        [string] $Json,

        [Parameter(Mandatory = $false, ParameterSetName = 'DownloadSample')]
        [switch] $DownloadSampleRemovals,

        [Alias('f')]
        [switch] $Force,

        [switch] $DryRun
    )

    try {
        [KeeperSecurity.Vault.VaultOnline]$vault = getVault
    }
    catch {
        Write-Error "Not connected to Keeper. Please login first."
        return
    }

    if ($DownloadSampleRemovals) {
        if (-not $FilePath) {
            $FilePath = 'nsf-records-remove-batch.sample.json'
        }

        $fullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($FilePath)
        $parentDir = Split-Path -Parent $fullPath
        if ($parentDir -and -not (Test-Path -LiteralPath $parentDir)) {
            New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
        }

        $sampleJson = Get-KeeperNSFRemoveBatchSampleJson
        $utf8NoBom = New-Object System.Text.UTF8Encoding $false
        [System.IO.File]::WriteAllText($fullPath, $sampleJson, $utf8NoBom)

        Write-Host "Sample NSF remove batch file written to: $fullPath" -ForegroundColor Green
        Write-Host "Edit the file with record UIDs (and folder UIDs where needed), then run:"
        Write-Host "    Remove-KeeperNSFRecords -FilePath `"$FilePath`""
        return
    }

    if (-not $FilePath -and -not $Json) {
        Write-Error "FilePath or Json is required when -DownloadSampleRemovals is not specified."
        return
    }

    try {
        $jsonText = if ($PSCmdlet.ParameterSetName -eq 'File') {
            if (-not (Test-Path -LiteralPath $FilePath)) {
                throw "File not found: $FilePath"
            }
            Get-Content -LiteralPath $FilePath -Raw -Encoding UTF8
        }
        else {
            $Json
        }

        $specs = ConvertTo-KeeperNSFRemovalSpecs -JsonText $jsonText
        if (-not $specs -or $specs.Count -eq 0) {
            throw "Remove file contains no removals."
        }
    }
    catch {
        Write-Host "Error parsing remove payload: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    $removals = New-Object 'System.Collections.Generic.List[KeeperSecurity.Vault.KeeperNSFRecordRemoval]'
    foreach ($spec in $specs) {
        [KeeperSecurity.Vault.KeeperNSFRecord]$kdRecord = $null
        if (-not $vault.TryResolveKeeperNSFRecord($spec.RecordUid, [ref]$kdRecord)) {
            Write-Error -Message "Keeper NSF record `"$($spec.RecordUid)`" was not found. Run Sync-Keeper or nsf-list first."
            continue
        }

        $op = switch ($spec.Operation) {
            'owner-trash' { [KeeperSecurity.Vault.KeeperNSFRecordRemoveOperation]::OwnerTrash }
            'folder-trash' { [KeeperSecurity.Vault.KeeperNSFRecordRemoveOperation]::FolderTrash }
            'unlink' { [KeeperSecurity.Vault.KeeperNSFRecordRemoveOperation]::Unlink }
        }

        $folderHint = $spec.Folder
        if ([string]::IsNullOrWhiteSpace($folderHint) -and $op -ne [KeeperSecurity.Vault.KeeperNSFRecordRemoveOperation]::OwnerTrash -and $Script:Context.CurrentFolder) {
            $folderHint = $Script:Context.CurrentFolder
        }

        if ($op -eq [KeeperSecurity.Vault.KeeperNSFRecordRemoveOperation]::Unlink -and [string]::IsNullOrWhiteSpace($folderHint)) {
            Write-Error -Message "Folder is required for unlink of record `"$($spec.RecordUid)`"."
            continue
        }

        [string]$folderUid = $null
        if (-not $vault.TryResolveKeeperNSFRecordRemovalFolder($kdRecord.RecordUid, $folderHint, $op, [ref]$folderUid)) {
            if ($spec.Folder) {
                Write-Error -Message "Keeper NSF folder `"$($spec.Folder)`" was not found for record `"$($spec.RecordUid)`"."
            }
            else {
                Write-Error -Message "No folder context for record `"$($spec.RecordUid)`". Set folder in JSON or use operation owner-trash."
            }
            continue
        }

        $removal = New-Object KeeperSecurity.Vault.KeeperNSFRecordRemoval
        $removal.RecordUid = $kdRecord.RecordUid
        $removal.FolderUid = $folderUid
        $removal.Operation = $op
        $removals.Add($removal)
    }

    if ($removals.Count -eq 0) {
        return
    }

    Write-Host ""
    Write-Host "=== Keeper NSF Remove Preview ===" -ForegroundColor Cyan
    $previewResult = $vault.RemoveKeeperNSFRecords($removals, $true).GetAwaiter().GetResult()
    Write-KeeperNSFRemoveImpact -Response $previewResult.PreviewResponse

    $previewErrors = @($previewResult.PreviewResponse.Results | Where-Object {
            $_.Error -and -not [string]::IsNullOrWhiteSpace($_.Error.Message)
        })
    if ($previewErrors.Count -gt 0) {
        Write-Host ""
        Write-Host "One or more records could not be previewed. Aborting." -ForegroundColor Yellow
        return
    }

    try {
        [KeeperSecurity.Vault.VaultOnline]::ValidateRemoveResponse($previewResult.PreviewResponse, $false)
    }
    catch {
        Write-Error -Message $_.Exception.Message
        return
    }

    if ($DryRun) {
        Write-Host ""
        Write-Host "Dry run: no records were removed." -ForegroundColor DarkYellow
        return
    }

    if (-not $Force) {
        $confirmation = Read-Host "Are you sure you want to remove the record(s) above? (yes/No)"
        if ($confirmation -notmatch '^(y|yes)$') {
            Write-Host "Remove operation cancelled"
            return
        }
    }

    if ($previewResult.PreviewResponse.ConfirmationToken.IsEmpty) {
        Write-Error -Message "Preview did not return a confirmation token."
        return
    }

    Write-Host ""
    Write-Host "Removing $($removals.Count) Keeper NSF record(s) in batch..." -ForegroundColor Cyan
    $confirmResult = $vault.RemoveKeeperNSFRecords($removals, $false).GetAwaiter().GetResult()
    if ($confirmResult.PartialSuccess) {
        Write-Warning "Partial record removal: $($confirmResult.ConfirmedChunkCount) chunk(s) succeeded, $($confirmResult.FailedChunkCount) failed."
        foreach ($err in @($confirmResult.ChunkErrors)) {
            Write-Warning "  $err"
        }
        $vault.SyncDown($false).GetAwaiter().GetResult() | Out-Null
        return
    }
    if (-not $confirmResult.Confirmed) {
        $detail = if ($confirmResult.ChunkErrors -and $confirmResult.ChunkErrors.Count -gt 0) {
            ($confirmResult.ChunkErrors -join '; ')
        } else {
            'Record removal was not confirmed by the server.'
        }
        Write-Error -Message $detail
        return
    }

    $vault.SyncDown($false).GetAwaiter().GetResult() | Out-Null
    Write-Host ""
    Write-Host "Keeper NSF record removal completed." -ForegroundColor Green
}
New-Alias -Name nsf-records-rm -Value Remove-KeeperNSFRecords

function Link-KeeperNSFRecord {
    <#
	.Synopsis
	Links a Keeper NSF record into a Keeper NSF folder (Keeper NSF v3 API).

	.Description
	Uses vault/folders/v3/record_update (AddRecords) for a single link.
	For bulk linking from JSON, use Link-KeeperNSFRecords (nsf-lns).

	.Parameter Record
	Record UID or title.

	.Parameter Folder
	Destination folder UID, name, or "/" for Keeper NSF root.
#>
    [CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Default')]
    Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [string] $Record,

        [Parameter(Position = 1, Mandatory = $true)]
        [string] $Folder
    )

    [KeeperSecurity.Vault.VaultOnline]$vault = getVault

    [KeeperSecurity.Vault.KeeperNSFRecord]$kdRecord = $null
    if (-not $vault.TryResolveKeeperNSFRecord($Record, [ref]$kdRecord)) {
        Write-Error -Message "Keeper NSF record `"$Record`" was not found. Run Sync-Keeper or nsf-list first."
        return
    }

    [KeeperSecurity.Vault.FolderNode]$folderNode = $null
    if (-not $vault.TryResolveKeeperNSFFolder($Folder, [ref]$folderNode)) {
        Write-Error -Message "Keeper NSF folder `"$Folder`" was not found. Run Sync-Keeper or nsf-list first."
        return
    }

    $folderLabel = if ([string]::IsNullOrEmpty($folderNode.FolderUid)) { 'root' } else { "$($folderNode.Name) ($($folderNode.FolderUid))" }
    $target = "$($kdRecord.RecordUid) -> $folderLabel"
    if (-not $PSCmdlet.ShouldProcess($target, "Link Keeper NSF record into folder")) {
        return
    }

    try {
        $result = $vault.LinkKeeperNSFRecordToFolder($Record, $Folder).GetAwaiter().GetResult()
        [KeeperSecurity.Vault.VaultOnline]::ValidateFolderRecordUpdateResult($result)
    }
    catch {
        Write-Error -Message $_.Exception.Message
        return
    }

    $vault.SyncDown($false).GetAwaiter().GetResult() | Out-Null
    Write-Host "Keeper NSF record linked into folder." -ForegroundColor Green
}
New-Alias -Name nsf-ln -Value Link-KeeperNSFRecord

function Link-KeeperNSFRecords {
    <#
	.Synopsis
	Batch-link Keeper NSF records into folders (up to 500 records per folder API request).

	.Description
	Uses vault/folders/v3/record_update (AddRecords). Independent of Link-KeeperNSFRecord / nsf-ln.
	JSON schema: a "links" array. Each item: folder_uid, record_uid (or uid / record_uid aliases).

	.Parameter FilePath
	Path to a UTF-8 JSON link batch file.

	.Parameter Json
	Inline JSON string (same schema as -FilePath).

	.Parameter DownloadSampleLinks
	Writes a sample link batch JSON file and exits without linking.

	.EXAMPLE
	PS> Link-KeeperNSFRecords -DownloadSampleLinks

	.EXAMPLE
	PS> Link-KeeperNSFRecords -FilePath .\nsf-folder-records-link-batch.sample.json
#>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium', DefaultParameterSetName = 'File')]
    Param(
        [Parameter(Mandatory = $true, ParameterSetName = 'File')]
        [Parameter(Mandatory = $false, ParameterSetName = 'DownloadSample')]
        [ValidateNotNullOrEmpty()]
        [string] $FilePath,

        [Parameter(Mandatory = $true, ParameterSetName = 'Json')]
        [ValidateNotNullOrEmpty()]
        [string] $Json,

        [Parameter(Mandatory = $false, ParameterSetName = 'DownloadSample')]
        [switch] $DownloadSampleLinks
    )

    try {
        [KeeperSecurity.Vault.VaultOnline]$vault = getVault
    }
    catch {
        Write-Error "Not connected to Keeper. Please login first."
        return
    }

    if ($DownloadSampleLinks) {
        if (-not $FilePath) {
            $FilePath = 'nsf-folder-records-link-batch.sample.json'
        }

        $fullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($FilePath)
        $parentDir = Split-Path -Parent $fullPath
        if ($parentDir -and -not (Test-Path -LiteralPath $parentDir)) {
            New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
        }

        $sampleJson = Get-KeeperNSFFolderRecordLinkBatchSampleJson
        $utf8NoBom = New-Object System.Text.UTF8Encoding $false
        [System.IO.File]::WriteAllText($fullPath, $sampleJson, $utf8NoBom)

        Write-Host "Sample NSF folder-record link batch file written to: $fullPath" -ForegroundColor Green
        Write-Host "Replace placeholders, then run:"
        Write-Host "    Link-KeeperNSFRecords -FilePath `"$FilePath`""
        return
    }

    if (-not $FilePath -and -not $Json) {
        Write-Error "FilePath or Json is required when -DownloadSampleLinks is not specified."
        return
    }

    try {
        $jsonText = if ($PSCmdlet.ParameterSetName -eq 'File') {
            if (-not (Test-Path -LiteralPath $FilePath)) {
                throw "File not found: $FilePath"
            }
            Get-Content -LiteralPath $FilePath -Raw -Encoding UTF8
        }
        else {
            $Json
        }

        $requests = ConvertTo-KeeperNSFFolderRecordLinkRequests -JsonText $jsonText
        if (-not $requests -or $requests.Count -eq 0) {
            throw "Link file contains no entries."
        }

        if ($requests -isnot [System.Collections.Generic.List[KeeperSecurity.Vault.KeeperNSFFolderRecordLinkRequest]]) {
            $typed = New-Object 'System.Collections.Generic.List[KeeperSecurity.Vault.KeeperNSFFolderRecordLinkRequest]'
            foreach ($item in @($requests)) {
                if ($item -is [KeeperSecurity.Vault.KeeperNSFFolderRecordLinkRequest]) {
                    $typed.Add($item) | Out-Null
                }
            }
            $requests = $typed
        }
    }
    catch {
        Write-Host "Error parsing folder-record link payload: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    if (-not $PSCmdlet.ShouldProcess("$($requests.Count) Keeper NSF folder-record link(s)", "Link Keeper NSF records into folders")) {
        return
    }

    try {
        Write-Host "Linking $($requests.Count) Keeper NSF record(s) into folders in batch..."
        $list = [System.Collections.Generic.List[KeeperSecurity.Vault.KeeperNSFFolderRecordLinkRequest]]$requests
        $results = $vault.LinkKeeperNSFRecordsToFolders($list).GetAwaiter().GetResult()
        Write-KeeperNSFFolderRecordBatchResults -Results $results -ActionLabel 'link'
        return ,@($results)
    }
    catch {
        Write-Host "Error linking records in batch: $($_.Exception.Message)" -ForegroundColor Red
    }
}

New-Alias -Name nsf-lns -Value Link-KeeperNSFRecords


function Unlink-KeeperNSFRecords {
    <#
	.Synopsis
	Batch-unlink Keeper NSF records from folders (up to 500 records per folder API request).

	.Description
	Uses vault/folders/v3/record_update (RemoveRecords). Record remains in other folders.
	JSON schema: an "unlinks" array. Each item: folder_uid (empty/"/" for NSF root), record_uid.

	.Parameter FilePath
	Path to a UTF-8 JSON unlink batch file.

	.Parameter Json
	Inline JSON string (same schema as -FilePath).

	.Parameter DownloadSampleUnlinks
	Writes a sample unlink batch JSON file and exits without unlinking.

	.EXAMPLE
	PS> Unlink-KeeperNSFRecords -DownloadSampleUnlinks

	.EXAMPLE
	PS> Unlink-KeeperNSFRecords -FilePath .\nsf-folder-records-unlink-batch.sample.json
#>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium', DefaultParameterSetName = 'File')]
    Param(
        [Parameter(Mandatory = $true, ParameterSetName = 'File')]
        [Parameter(Mandatory = $false, ParameterSetName = 'DownloadSample')]
        [ValidateNotNullOrEmpty()]
        [string] $FilePath,

        [Parameter(Mandatory = $true, ParameterSetName = 'Json')]
        [ValidateNotNullOrEmpty()]
        [string] $Json,

        [Parameter(Mandatory = $false, ParameterSetName = 'DownloadSample')]
        [switch] $DownloadSampleUnlinks
    )

    try {
        [KeeperSecurity.Vault.VaultOnline]$vault = getVault
    }
    catch {
        Write-Error "Not connected to Keeper. Please login first."
        return
    }

    if ($DownloadSampleUnlinks) {
        if (-not $FilePath) {
            $FilePath = 'nsf-folder-records-unlink-batch.sample.json'
        }

        $fullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($FilePath)
        $parentDir = Split-Path -Parent $fullPath
        if ($parentDir -and -not (Test-Path -LiteralPath $parentDir)) {
            New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
        }

        $sampleJson = Get-KeeperNSFFolderRecordUnlinkBatchSampleJson
        $utf8NoBom = New-Object System.Text.UTF8Encoding $false
        [System.IO.File]::WriteAllText($fullPath, $sampleJson, $utf8NoBom)

        Write-Host "Sample NSF folder-record unlink batch file written to: $fullPath" -ForegroundColor Green
        Write-Host "Replace placeholders, then run:"
        Write-Host "    Unlink-KeeperNSFRecords -FilePath `"$FilePath`""
        return
    }

    if (-not $FilePath -and -not $Json) {
        Write-Error "FilePath or Json is required when -DownloadSampleUnlinks is not specified."
        return
    }

    try {
        $jsonText = if ($PSCmdlet.ParameterSetName -eq 'File') {
            if (-not (Test-Path -LiteralPath $FilePath)) {
                throw "File not found: $FilePath"
            }
            Get-Content -LiteralPath $FilePath -Raw -Encoding UTF8
        }
        else {
            $Json
        }

        $requests = ConvertTo-KeeperNSFFolderRecordUnlinkRequests -JsonText $jsonText
        if (-not $requests -or $requests.Count -eq 0) {
            throw "Unlink file contains no entries."
        }

        if ($requests -isnot [System.Collections.Generic.List[KeeperSecurity.Vault.KeeperNSFFolderRecordUnlinkRequest]]) {
            $typed = New-Object 'System.Collections.Generic.List[KeeperSecurity.Vault.KeeperNSFFolderRecordUnlinkRequest]'
            foreach ($item in @($requests)) {
                if ($item -is [KeeperSecurity.Vault.KeeperNSFFolderRecordUnlinkRequest]) {
                    $typed.Add($item) | Out-Null
                }
            }
            $requests = $typed
        }
    }
    catch {
        Write-Host "Error parsing folder-record unlink payload: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    if (-not $PSCmdlet.ShouldProcess("$($requests.Count) Keeper NSF folder-record unlink(s)", "Unlink Keeper NSF records from folders")) {
        return
    }

    try {
        Write-Host "Unlinking $($requests.Count) Keeper NSF record(s) from folders in batch..."
        $list = [System.Collections.Generic.List[KeeperSecurity.Vault.KeeperNSFFolderRecordUnlinkRequest]]$requests
        $results = $vault.UnlinkKeeperNSFRecordsFromFolders($list).GetAwaiter().GetResult()
        Write-KeeperNSFFolderRecordBatchResults -Results $results -ActionLabel 'unlink'
        return ,@($results)
    }
    catch {
        Write-Host "Error unlinking records in batch: $($_.Exception.Message)" -ForegroundColor Red
    }
}

New-Alias -Name nsf-unln -Value Unlink-KeeperNSFRecords

function Script:Write-KeeperNSFFolderRecordBatchResults {
    Param(
        [Parameter(Mandatory = $true)]
        $Results,
        [string] $ActionLabel = 'folder-record'
    )

    $ok = @($Results | Where-Object { $_.Success })
    $fail = @($Results | Where-Object { -not $_.Success })
    Write-Host "Batch complete: $($ok.Count) succeeded, $($fail.Count) failed."
    Write-Host ""

    foreach ($result in $Results) {
        $folderLabel = if ([string]::IsNullOrEmpty($result.FolderUid)) { 'root' } else { $result.FolderUid }
        if ($result.Success) {
            Write-Host "  [OK]   $($result.RecordUid) @ $folderLabel" -ForegroundColor Green
        }
        else {
            $msg = if ($result.Message) { $result.Message } else { '(no message)' }
            Write-Host "  [FAIL] $($result.RecordUid) @ $folderLabel  status=$($result.Status)  $msg" -ForegroundColor Red
        }
    }
}

function Script:Get-KeeperNSFFolderRecordJsonItems {
    Param(
        [Parameter(Mandatory = $true)]
        [string] $JsonText,
        [Parameter(Mandatory = $true)]
        [string] $ArrayName
    )

    $parsed = $JsonText | ConvertFrom-Json -ErrorAction Stop
    if ($null -ne $parsed.$ArrayName) {
        return @($parsed.$ArrayName)
    }
    if ($parsed -is [System.Array]) {
        return @($parsed)
    }
    throw "JSON must contain a '$ArrayName' array (or be a root array of objects)."
}

function Script:Get-KeeperNSFFolderRecordItemFields {
    Param($Item, [int] $Index)

    $folderUid = $null
    if ($Item.folder_uid) { $folderUid = [string]$Item.folder_uid }
    elseif ($Item.FolderUid) { $folderUid = [string]$Item.FolderUid }
    elseif ($Item.folder) { $folderUid = [string]$Item.folder }

    $recordUid = $null
    if ($Item.record_uid) { $recordUid = [string]$Item.record_uid }
    elseif ($Item.uid) { $recordUid = [string]$Item.uid }
    elseif ($Item.RecordUid) { $recordUid = [string]$Item.RecordUid }
    elseif ($Item.record) { $recordUid = [string]$Item.record }

    if ([string]::IsNullOrWhiteSpace($recordUid)) {
        throw "Item at index $Index is missing required 'record_uid' (or uid)."
    }

    return @{
        FolderUid = if ($null -eq $folderUid) { '' } else { $folderUid.Trim() }
        RecordUid = $recordUid.Trim()
    }
}

function Script:ConvertTo-KeeperNSFFolderRecordLinkRequests {
    Param(
        [Parameter(Mandatory = $true)]
        [string] $JsonText
    )

    $items = Get-KeeperNSFFolderRecordJsonItems -JsonText $JsonText -ArrayName 'links'
    $list = New-Object 'System.Collections.Generic.List[KeeperSecurity.Vault.KeeperNSFFolderRecordLinkRequest]'
    $index = 0
    foreach ($item in $items) {
        $fields = Get-KeeperNSFFolderRecordItemFields -Item $item -Index $index
        $req = New-Object KeeperSecurity.Vault.KeeperNSFFolderRecordLinkRequest
        $req.FolderUid = $fields.FolderUid
        $req.RecordUid = $fields.RecordUid
        $list.Add($req) | Out-Null
        $index++
    }
    return ,$list
}

function Script:ConvertTo-KeeperNSFFolderRecordUnlinkRequests {
    Param(
        [Parameter(Mandatory = $true)]
        [string] $JsonText
    )

    $items = Get-KeeperNSFFolderRecordJsonItems -JsonText $JsonText -ArrayName 'unlinks'
    $list = New-Object 'System.Collections.Generic.List[KeeperSecurity.Vault.KeeperNSFFolderRecordUnlinkRequest]'
    $index = 0
    foreach ($item in $items) {
        $fields = Get-KeeperNSFFolderRecordItemFields -Item $item -Index $index
        # Empty folder_uid maps to NSF root (same as Link-KeeperNSFRecords / SDK).
        $req = New-Object KeeperSecurity.Vault.KeeperNSFFolderRecordUnlinkRequest
        $req.FolderUid = $fields.FolderUid
        $req.RecordUid = $fields.RecordUid
        $list.Add($req) | Out-Null
        $index++
    }
    return ,$list
}

function Transfer-KeeperNSFRecordOwnership {
    <#
	.Synopsis
	Transfers ownership of one or more Keeper NSF records to another user (Keeper NSF v3 API).

	.Description
	Positional arguments: one or more record UIDs or titles, then the new owner's email address.
	After a successful transfer you will no longer have access to the record(s).

	.Example
	nsf-transfer-record rvwIBG_ban2VTH64OsnzLn alice@example.com

	.Example
	nsf-transfer-record rec1 rec2 rec3 alice@example.com
#>
    [CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Default')]
    Param(
        [Parameter(ValueFromRemainingArguments = $true, Mandatory = $true)]
        [string[]] $ArgumentList,

        [Alias('f')]
        [switch] $Force
    )

    if ($ArgumentList.Count -lt 2) {
        Write-Error -Message "Usage: nsf-transfer-record RECORD [RECORD...] NEW_OWNER_EMAIL"
        return
    }

    $newOwnerEmail = $ArgumentList[-1]
    $recordArgs = @($ArgumentList[0..($ArgumentList.Count - 2)])

    if ($recordArgs.Count -eq 0 -or [string]::IsNullOrWhiteSpace($newOwnerEmail)) {
        Write-Error -Message "Record UID(s) and new owner email are required."
        return
    }

    if ($newOwnerEmail -notmatch '@') {
        Write-Error -Message "New owner must be an email address: `"$newOwnerEmail`""
        return
    }

    [KeeperSecurity.Vault.VaultOnline]$vault = getVault
    $resolvedRecords = New-Object 'System.Collections.Generic.List[string]'

    foreach ($name in $recordArgs) {
        [KeeperSecurity.Vault.KeeperNSFRecord]$kdRecord = $null
        if (-not $vault.TryResolveKeeperNSFRecord($name, [ref]$kdRecord)) {
            Write-Error -Message "Keeper NSF record `"$name`" was not found. Run Sync-Keeper or nsf-list first."
            return
        }
        $resolvedRecords.Add($kdRecord.RecordUid)
    }

    if (-not $Force) {
        Write-Host ""
        Write-Host "*** WARNING ***" -ForegroundColor Yellow
        Write-Host "After ownership is transferred you will lose owner rights on the record(s)."
        Write-Host "You may still see the record(s) if you retain access via a shared folder or admin role; otherwise they will disappear after sync."
        Write-Host "Make sure the new owner is correct before continuing."
        Write-Host ""
        $confirmation = Read-Host "Are you sure you want to transfer ownership to '$newOwnerEmail'? This action cannot be undone. (yes/No)"
        if ($confirmation -notmatch '^(y|yes)$') {
            Write-Host "Transfer operation cancelled"
            return
        }
    }

    try {
        $results = $vault.TransferKeeperNSFRecordOwnership($resolvedRecords, $newOwnerEmail).GetAwaiter().GetResult()
        [KeeperSecurity.Vault.VaultOnline]::ValidateKeeperNSFTransferResults($results)

        foreach ($result in $results) {
            Write-Host "Record '$($result.RecordUid)' ownership transferred to $($result.Username)." -ForegroundColor Green
            Write-Host "You no longer own this record. Run Sync-Keeper to refresh; it will remain visible only if you retain access via a shared folder or admin role." -ForegroundColor Yellow
        }
    }
    catch {
        Write-Error -Message $_.Exception.Message
        return
    }

    $vault.SyncDown($false).GetAwaiter().GetResult() | Out-Null
}
New-Alias -Name nsf-transfer-record -Value Transfer-KeeperNSFRecordOwnership
