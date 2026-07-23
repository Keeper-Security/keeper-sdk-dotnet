#requires -Version 5.1

function script:encodePamByteString {
    Param (
        [Google.Protobuf.ByteString] $ByteString
    )

    if ($null -eq $ByteString -or $ByteString.IsEmpty) {
        return ''
    }

    return [KeeperSecurity.Utils.CryptoUtils]::Base64UrlEncode($ByteString.ToByteArray())
}

function script:resolvePamRotationRecord {
    Param (
        [Parameter(Mandatory = $true)]
        [KeeperSecurity.Vault.VaultOnline] $Vault,
        [Parameter(Mandatory = $true)]
        [string] $Identifier,
        [Parameter(Mandatory = $true)]
        [System.Collections.Generic.HashSet[string]] $AllowedTypes
    )

    try {
        return [KeeperSecurity.Plugins.PAM.PamVaultHelpers]::ResolveRecord($Vault, $Identifier.Trim(), $AllowedTypes)
    }
    catch [System.InvalidOperationException] {
        # Ambiguous title / validation caller must not also print "not found".
        Write-Output $_.Exception.Message
        throw
    }
}

function script:testPamRotationScriptOwnerException {
    Param (
        [Parameter(Mandatory = $true)]
        [System.Exception] $Exception
    )

    $ex = $Exception
    while ($null -ne $ex) {
        if ($ex -is [KeeperSecurity.Authentication.KeeperApiException]) {
            $code = [string]$ex.Code
            if ($code -eq 'only_owner_can_modify_scripts' -or $code -eq 'RS_ONLY_OWNER_CAN_MODIFY_SCRIPTS') {
                return $true
            }
        }
        $ex = $ex.InnerException
    }
    return $false
}

function script:updatePamRotationScriptRecord {
    Param (
        [Parameter(Mandatory = $true)]
        [KeeperSecurity.Vault.VaultOnline] $Vault,
        [Parameter(Mandatory = $true)]
        [KeeperSecurity.Vault.TypedRecord] $Record,
        [Parameter(Mandatory = $true)]
        [ValidateSet('add', 'edit', 'remove')]
        [string] $Action
    )

    try {
        $Vault.UpdateRecord($Record).GetAwaiter().GetResult() | Out-Null
        return $true
    }
    catch {
        if (testPamRotationScriptOwnerException -Exception $_.Exception) {
            switch ($Action) {
                'add' { Write-Output 'Only the record owner can attach post-rotation scripts.' }
                'edit' { Write-Output 'Only the record owner can edit post-rotation scripts.' }
                'remove' { Write-Output 'Only the record owner can remove post-rotation scripts.' }
            }
            return $false
        }
        throw
    }
}

function script:buildPamRotationOptions {
    Param (
        [hashtable] $Values = @{}
    )

    $options = New-Object KeeperSecurity.Plugins.PAM.PamRotationOptions
    foreach ($entry in $Values.GetEnumerator()) {
        $property = $options.GetType().GetProperty($entry.Key)
        if ($null -eq $property) {
            continue
        }

        $property.SetValue($options, $entry.Value, $null)
    }

    return $options
}

function script:getPamRotationVault {
  $vault = getVault
  if (-not $vault) {
    Write-Error -Message 'Vault is not available.' -ErrorAction Stop
  }

  return $vault
}
