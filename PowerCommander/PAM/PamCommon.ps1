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
    catch {
        return $null
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

function script:confirmPamRotationPrompt {
    Param (
        [Parameter(Mandatory = $true)]
        [string] $Prompt,
        [bool] $DefaultYes = $true
    )

    $trimmedPrompt = $Prompt.Trim()
    if ($trimmedPrompt.EndsWith(':')) {
        $trimmedPrompt = $trimmedPrompt.Substring(0, $trimmedPrompt.Length - 1)
    }

    $answer = Read-Host $trimmedPrompt
    if ([string]::IsNullOrWhiteSpace($answer)) {
        return $DefaultYes
    }

    $normalized = $answer.Trim()
    if ($normalized -match '^(y|yes)$') {
        return $true
    }

    if ($normalized -match '^(n|no)$') {
        return $false
    }

    return $DefaultYes
}

function script:newPamRotationConfirmHandler {
    return [Func[string, bool, System.Threading.Tasks.Task[bool]]]{
        param(
            [string] $Prompt,
            [bool] $DefaultYes
        )

        $result = confirmPamRotationPrompt -Prompt $Prompt -DefaultYes $DefaultYes
        return [System.Threading.Tasks.Task[bool]]::FromResult($result)
    }
}

function script:getPamRotationVault {
  $vault = getVault
  if (-not $vault) {
    Write-Error -Message 'Vault is not available.' -ErrorAction Stop
  }

  return $vault
}
