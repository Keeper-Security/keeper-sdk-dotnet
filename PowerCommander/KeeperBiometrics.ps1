# PowerShell Windows Hello Integration
# Lightweight, standalone Windows Hello implementation for PowerCommander
# 
# This module provides enhanced Windows Hello functionality using native WebAuthn APIs
# with no external dependencies beyond the Windows webauthn.dll

try {
    $null = [KeeperBiometric.WindowsHelloApi]
    $KeeperBiometricAvailable = $true
}
catch {
    Write-Warning "KeeperBiometric assembly not available: $($_.Exception.Message)"
    $KeeperBiometricAvailable = $false
}

$script:DefaultRpId = "keepersecurity.com"

function Test-AssemblyAvailable {
    <#
    .SYNOPSIS
    Tests if the KeeperBiometric assembly is available
    
    .DESCRIPTION
    Common function to check assembly availability and provide consistent error handling
    across all functions that depend on the KeeperBiometric assembly.
    
    .PARAMETER Quiet
    Suppress warning messages if assembly is not available
    
    .OUTPUTS
    [bool] True if assembly is available, false otherwise
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$Quiet
    )
    
    if (-not $KeeperBiometricAvailable) {
        if (-not $Quiet) {
            Write-Warning "KeeperBiometric assembly not available. Please build the project first."
        }
        return $false
    }
    return $true
}

function Write-ErrorWithContext {
    <#
    .SYNOPSIS
    Writes error messages with consistent formatting and context
    
    .DESCRIPTION
    Common function for error handling that provides consistent error message formatting
    across all functions in the module.
    
    .PARAMETER Message
    The error message to display
    
    .PARAMETER FunctionName
    The name of the function where the error occurred
    
    .PARAMETER Exception
    The exception object (optional)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$true)]
        [string]$FunctionName,
        
        [Parameter()]
        [Exception]$Exception
    )
    
    $errorMessage = "$FunctionName`: $Message"
    if ($Exception) {
        $errorMessage += " - $($Exception.Message)"
    }
    Write-Error $errorMessage
}

function Test-ExistingCredentialMatch {
    <#
    .SYNOPSIS
    Tests if an existing credential matches the exclude credentials list
    
    .DESCRIPTION
    Checks if a stored credential ID matches any of the exclude credentials
    to prevent duplicate credential creation.
    
    .PARAMETER Username
    The username to check for existing credentials
    
    .PARAMETER ExcludeCredentials
    Array of exclude credentials from registration options
    
    .PARAMETER Force
    Skip the check if Force is specified
    
    .OUTPUTS
    [hashtable] Object containing match information or null if no match
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Username,
        
        [Parameter(Mandatory=$true)]
        [AllowEmptyCollection()]
        [array]$ExcludeCredentials,
        
        [Parameter()]
        [switch]$Force
    )
    
    if ($Force -or $null -eq $ExcludeCredentials -or $ExcludeCredentials.Count -eq 0) {
        return $null
    }
    
    $existingCredentialId = Get-WindowsHelloCredentialId -Username $Username
    if (-not $existingCredentialId) {
        return $null
    }
    
    foreach ($excludeCred in $ExcludeCredentials) {
        $excludeCredId = $excludeCred.id
        if ($existingCredentialId -eq $excludeCredId) {
            return @{
                Username = $Username
                CredentialId = $existingCredentialId
            }
        }
    }
    
    return $null
}

function New-ExcludeCredentialObjects {
    <#
    .SYNOPSIS
    Converts exclude credentials array to KeeperBiometric.ExcludeCredential objects
    
    .DESCRIPTION
    Converts the exclude credentials from registration options into the proper
    object format expected by the Windows Hello API.
    
    .PARAMETER ExcludeCredentials
    Array of exclude credentials from registration options
    
    .OUTPUTS
    [array] Array of KeeperBiometric.ExcludeCredential objects
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [AllowEmptyCollection()]
        [array]$ExcludeCredentials
    )
    
    if ($null -eq $ExcludeCredentials -or $ExcludeCredentials.Count -eq 0) {
        return @()
    }
    
    # Ensure it's an array
    if ($ExcludeCredentials -isnot [array]) {
        $ExcludeCredentials = @($ExcludeCredentials)
    }
    
    $excludeCredentialObjects = @()
    for ($i = 0; $i -lt $ExcludeCredentials.Count; $i++) {
        $excludeCred = $ExcludeCredentials[$i]
        
        try {
            $credObj = New-Object KeeperBiometric.ExcludeCredential
            $credObj.Type = $excludeCred.type
            $credObj.Id = $excludeCred.id
            $credObj.Transports = $excludeCred.transports
            $excludeCredentialObjects += $credObj
        }
        catch {
            Write-Warning "Failed to create ExcludeCredential object: $($_.Exception.Message)"
            # Continue with next credential
        }
    }
    
    return $excludeCredentialObjects
}

function Invoke-CredentialCreationFlow {
    <#
    .SYNOPSIS
    Performs the Windows Hello credential creation and registration flow
    
    .DESCRIPTION
    Handles the actual credential creation using Windows Hello and registration
    with Keeper's servers.
    
    .PARAMETER RegOptions
    Registration options from Keeper API
    
    .PARAMETER DisplayName
    Display name for the credential
    
    .PARAMETER ExcludeCredentialObjects
    Array of exclude credential objects
    
    .PARAMETER Vault
    Keeper vault instance
    
    .OUTPUTS
    [hashtable] Result object with Success, CredentialId, and other properties
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$RegOptions,
        
        [Parameter(Mandatory=$true)]
        [string]$DisplayName,
        
        [Parameter()]
        [AllowEmptyCollection()]
        [array]$ExcludeCredentialObjects = @(),
        
        [Parameter()]
        [object]$Vault
    )
    
    $credResult = Invoke-WindowsHelloCredentialCreation `
        -Challenge $RegOptions.challenge `
        -RpId $RegOptions.rp_id `
        -RpName $RegOptions.rp_name `
        -UserId $RegOptions.user_id `
        -UserName $RegOptions.user_name `
        -UserDisplayName $DisplayName `
        -ExcludeCredentials $ExcludeCredentialObjects

    if (-not $credResult.Success) {
        return @{
            Success = $false
            Error = $credResult.ErrorMessage
            ErrorType = $credResult.ErrorType
            Timestamp = $credResult.Timestamp
        }
    }

    $registerResult = Register-KeeperCredential `
        -ChallengeToken $RegOptions.challenge_token `
        -CredentialId $credResult.CredentialId `
        -AttestationObject $credResult.AttestationObject `
        -ClientDataJSON $credResult.ClientDataJSON `
        -Vault $Vault

    if (-not $registerResult.Success) {
        return @{
            Success = $false
            Error = "Windows Hello credential creation failed: $($credResult.ErrorMessage)"
            ErrorType = "RegistrationFailed"
            Timestamp = [DateTime]::UtcNow
        }
    }

    $credentialId = $credResult.CredentialId
    $username = $RegOptions.user_name
    
    $storeResult = Set-WindowsHelloCredentialId -Username $username -CredentialId $credentialId
    if ($storeResult) {
        Write-Host "Credential ID stored for user: $username" -ForegroundColor Green
    } else {
        Write-Warning "Failed to store credential ID for user: $username"
    }

    return @{
        Success = $true
        CredentialId = $credentialId
        Username = $username
        DisplayName = $DisplayName
        Timestamp = [DateTime]::UtcNow
    }
}


function Test-WindowsHelloCapabilities {
    <#
    .SYNOPSIS
    Tests Windows Hello capabilities with comprehensive information
    
    .DESCRIPTION
    This function provides detailed information about Windows Hello capabilities
    using native WebAuthn APIs. It shows availability, API version, supported methods,
    and integration recommendations.
    
    .EXAMPLE
    Test-WindowsHelloCapabilities
    
    .EXAMPLE
    $caps = Test-WindowsHelloCapabilities -PassThru
    if ($caps.WindowsHello.Available) {
        Write-Host "Windows Hello is ready for use"
    }
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$PassThru,
        
        [Parameter()]
        [switch]$Quiet
    )
    
    if (-not (Test-AssemblyAvailable -Quiet:$Quiet)) {
        return $false
    }
    
    try {
        $capabilities = [KeeperBiometric.WindowsHelloApi]::GetFormattedInfo()
        if ($PassThru) {
            return $capabilities
        }
        else {
            return $capabilities.WindowsHello.Available
        }
    }
    catch {
        if (-not $Quiet) {
            Write-Debug "Failed to check Windows Hello capabilities: $($_.Exception.Message)"
        }
        return $false
    }
}

function Invoke-WindowsHelloAuthentication {
    <#
    .SYNOPSIS
    Performs Windows Hello authentication using native WebAuthn APIs
    
    .DESCRIPTION
    This function performs Windows Hello authentication for a given challenge,
    returning the WebAuthn assertion data needed for Keeper authentication.
    
    .PARAMETER Challenge
    The authentication challenge (as byte array)
    
    .PARAMETER RpId
    The relying party identifier (default: uses module constant)
    
    .PARAMETER AllowedCredentials
    Array of allowed credential IDs (base64 encoded)
    
    .PARAMETER TimeoutMs
    Authentication timeout in milliseconds (default: 60000)
    
    .PARAMETER UserVerification
    User verification requirement: "required", "preferred", or "discouraged" (default: "required")
    
    .EXAMPLE
    $challenge = [System.Text.Encoding]::UTF8.GetBytes("example-challenge")
    $result = Invoke-WindowsHelloAuthentication -Challenge $challenge
    if ($result.Success) {
        Write-Host "Authentication successful!"
    }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [byte[]]$Challenge,
        
        [Parameter()]
        [string]$RpId = $script:DefaultRpId,
        
        [Parameter()]
        [AllowEmptyCollection()]
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 'AllowedCredentials', Justification='Credential IDs are public identifiers, not sensitive data')]
        [string[]]$AllowedCredentials,
        
        [Parameter()]
        [int]$TimeoutMs = 60000,
        
        [Parameter()]
        [ValidateSet("required", "preferred", "discouraged")]
        [string]$UserVerification = "required"
    )
    
    if (-not (Test-AssemblyAvailable)) {
        throw "PowerShellWindowsHello assembly not available. Please build the project first."
    }
    
    try {
        $authOptions = New-Object KeeperBiometric.AuthenticationOptions
        $authOptions.Challenge = $Challenge
        $authOptions.RpId = $RpId
        $authOptions.AllowedCredentialIds = $AllowedCredentials
        $authOptions.TimeoutMs = $TimeoutMs
        $authOptions.UserVerification = $UserVerification
        
        Write-Debug "Please complete Windows Hello verification when prompted..."
        
        $task = [KeeperBiometric.WindowsHelloApi]::AuthenticateAsync($authOptions)
        $result = $task.GetAwaiter().GetResult()
        
        return $result
    }
    catch {
        Write-Error "Authentication failed: $($_.Exception.Message)"
        return @{
            Success = $false
            ErrorMessage = $_.Exception.Message
            ErrorType = $_.Exception.GetType().Name
            Timestamp = [DateTime]::UtcNow
        }
    }
}

function Invoke-WindowsHelloCredentialCreation {
    <#
    .SYNOPSIS
    Creates a new Windows Hello credential using native WebAuthn APIs
    
    .DESCRIPTION
    This function creates a new Windows Hello credential for a given relying party,
    returning the WebAuthn attestation data needed for credential registration.
    
    .PARAMETER Challenge
    The registration challenge (as byte array)
    
    .PARAMETER RpId
    The relying party identifier (default: uses module constant)
    
    .PARAMETER RpName
    The relying party display name (default: same as RpId)
    
    .PARAMETER UserId
    The user identifier (as byte array)
    
    .PARAMETER UserName
    The username
    
    .PARAMETER UserDisplayName
    The user display name (default: same as UserName)
    
    .PARAMETER TimeoutMs
    Authentication timeout in milliseconds (default: 60000)
    
    .PARAMETER UserVerification
    User verification requirement: "required", "preferred", or "discouraged" (default: "required")
    
    .PARAMETER AttestationConveyancePreference
    Attestation preference: "none", "indirect", or "direct" (default: "direct")
    
    .PARAMETER ResidentKeyRequirement
    Resident key requirement: "discouraged", "preferred", or "required" (default: "discouraged")
    
    .PARAMETER AuthenticatorAttachment
    Authenticator attachment: "platform" or "cross-platform" (default: "platform")
    
    .EXAMPLE
    $challenge = [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes(32)
    $userId = [System.Text.Encoding]::UTF8.GetBytes("user123")
    $result = Invoke-WindowsHelloCredentialCreation -Challenge $challenge -UserId $userId -UserName "user@example.com"
    if ($result.Success) {
        Write-Host "Credential created successfully!"
    }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [byte[]]$Challenge,
        
        [Parameter()]
        [string]$RpId = $script:DefaultRpId,
        
        [Parameter()]
        [string]$RpName,
        
        [Parameter(Mandatory=$true)]
        [byte[]]$UserId,
        
        [Parameter(Mandatory=$true)]
        [string]$UserName,
        
        [Parameter()]
        [string]$UserDisplayName,
        
        [Parameter()]
        [int]$TimeoutMs = 60000,
        
        [Parameter()]
        [ValidateSet("required", "preferred", "discouraged")]
        [string]$UserVerification = "required",
        
        [Parameter()]
        [ValidateSet("none", "indirect", "direct")]
        [string]$AttestationConveyancePreference = "direct",
        
        [Parameter()]
        [ValidateSet("discouraged", "preferred", "required")]
        [string]$ResidentKeyRequirement = "discouraged",
        
        [Parameter()]
        [ValidateSet("platform", "cross-platform")]
        [string]$AuthenticatorAttachment = "platform",

        [Parameter()]
        [AllowEmptyCollection()]
        [KeeperBiometric.ExcludeCredential[]]$ExcludeCredentials
    )
    
    if (-not (Test-AssemblyAvailable)) {
        throw "PowerShellWindowsHello assembly not available. Please build the project first."
    }
    
    try {

        $regOptions = New-Object KeeperBiometric.RegistrationOptions
        $regOptions.Challenge = $Challenge
        $regOptions.RpId = $RpId
        $regOptions.RpName = if ($RpName) { $RpName } else { $RpId }
        $regOptions.UserId = $UserId
        $regOptions.UserName = $UserName
        $regOptions.UserDisplayName = if ($UserDisplayName) { $UserDisplayName } else { $UserName }
        $regOptions.TimeoutMs = $TimeoutMs
        $regOptions.UserVerification = $UserVerification
        $regOptions.AttestationConveyancePreference = $AttestationConveyancePreference
        $regOptions.ResidentKeyRequirement = $ResidentKeyRequirement
        $regOptions.AuthenticatorAttachment = $AuthenticatorAttachment
        
        Write-Host "Please complete Windows Hello verification to create the credential..." -ForegroundColor Yellow
        
        $task = [KeeperBiometric.WindowsHelloApi]::CreateCredentialAsync($regOptions,$excludeCredentials)
        $result = $task.GetAwaiter().GetResult()
        
        return $result
    }
    catch {
        Write-Error "Credential creation failed: $($_.Exception.Message)"
        return @{
            Success = $false
            ErrorMessage = $_.Exception.Message
            ErrorType = $_.Exception.GetType().Name
            Timestamp = [DateTime]::UtcNow
        }
    }
}

function Get-KeeperRegistrationOptions {
    <#
    .SYNOPSIS
    Gets Windows Hello registration options from Keeper API
    
    .DESCRIPTION
    This function retrieves registration options from the Keeper API,
    including challenge and creation options needed for Windows Hello credential creation.
    
    .PARAMETER Vault
    Keeper vault instance (optional - will use global vault if not provided)
    
    .EXAMPLE
    $regOptions = Get-KeeperRegistrationOptions
    if ($regOptions) {
        # Use with Register-KeeperBiometricCredential
    }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [object]$Vault
    )
    
    try {
        if (-not $Vault) {
            if (Get-Command getVault -ErrorAction SilentlyContinue) {
                $vault = getVault
            } elseif ($Script:Context.Vault) {
                $vault = $Script:Context.Vault
            } else {
                throw "No vault instance available. Please connect to Keeper first or provide a vault parameter."
            }
        } else {
            $vault = $Vault
        }
        
        $auth = $vault.Auth
        
        $request = [Authentication.PasskeyRegistrationRequest]::new()
        $request.AuthenticatorAttachment = [Authentication.AuthenticatorAttachment]::Platform
        
        $response = $auth.ExecuteAuthRest("authentication/passkey/generate_registration", $request, [Authentication.PasskeyRegistrationResponse]).GetAwaiter().GetResult()
        
        $creationOptions = $response.PkCreationOptions | ConvertFrom-Json
        
        $challengeTokenBytes = $null
        if ($response.ChallengeToken -is [Google.Protobuf.ByteString]) {
            $challengeTokenBytes = $response.ChallengeToken.ToByteArray()
        } else {
            $challengeTokenBytes = $response.ChallengeToken
        }

        $result = @{
            challenge_token = $challengeTokenBytes
            creation_options = $creationOptions
            rp_id = $creationOptions.rp.id
            rp_name = $creationOptions.rp.name
            user_id = ConvertFrom-Base64Url -Base64UrlString $creationOptions.user.id
            user_name = $creationOptions.user.name
            user_display_name = $creationOptions.user.displayName
            challenge = ConvertFrom-Base64Url -Base64UrlString $creationOptions.challenge
        }
        return $result
    }
    catch {
        Write-Error "Failed to get registration options: $($_.Exception.Message)"
        throw "Error getting passkey registration options: $($_.Exception.Message)"
    }
}

function ConvertFrom-Base64Url {
    <#
    .SYNOPSIS
    Converts a Base64Url string to a byte array
    
    .DESCRIPTION
    Converts a Base64Url encoded string to a byte array, handling the URL-safe
    Base64 encoding format used by WebAuthn.
    
    .PARAMETER Base64UrlString
    The Base64Url encoded string to convert
    
    .OUTPUTS
    [byte[]] The decoded byte array, or null if input is invalid
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Base64UrlString
    )
    
    if ([string]::IsNullOrEmpty($Base64UrlString)) {
        return $null
    }
    
    try {
        $base64 = $Base64UrlString.Replace('-', '+').Replace('_', '/')
        
        switch ($base64.Length % 4) {
            2 { $base64 += '==' }
            3 { $base64 += '=' }
        }
        
        return [Convert]::FromBase64String($base64)
    }
    catch {
        Write-Verbose "Base64Url decode failed for: $Base64UrlString, error: $($_.Exception.Message)"
        try {
            return [Convert]::FromBase64String($Base64UrlString)
        }
        catch {
            Write-Warning "Both base64url and base64 decode failed for: $Base64UrlString"
            return $null
        }
    }
}

function ConvertTo-ByteString {
    <#
    .SYNOPSIS
    Converts various input types to a byte array
    
    .DESCRIPTION
    Converts string, byte array, or other input types to a byte array
    for use with WebAuthn operations.
    
    .PARAMETER InputData
    The input data to convert (string, byte array, etc.)
    
    .OUTPUTS
    [byte[]] The converted byte array, or null if input is invalid
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        $InputData
    )
    
    if ($null -eq $InputData) {
        return $null
    }
    
    if ($InputData -is [Google.Protobuf.ByteString]) {
        return $InputData
    }
    elseif ($InputData -is [byte[]]) {
        return [Google.Protobuf.ByteString]::CopyFrom($InputData)
    }
    elseif ($InputData -is [string]) {
        try {
            $bytes = $InputData -split '\s+' | ForEach-Object { [byte]$_ }
            return [Google.Protobuf.ByteString]::CopyFrom([byte[]]$bytes)
        }
        catch {
            throw
        }
    }
    else {
        try {
            return [Google.Protobuf.ByteString]::CopyFrom($InputData)
        }
        catch {
            throw
        }
    }
}

function Utf8BytesToString {
    <#
    .SYNOPSIS
    Converts byte array or ByteString to UTF-8 string
    
    .DESCRIPTION
    Converts a byte array or Google.Protobuf.ByteString to a UTF-8 encoded string.
    
    .PARAMETER InputData
    The input data to convert (byte array or ByteString)
    
    .OUTPUTS
    [string] The UTF-8 decoded string, or null if input is invalid
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        $InputData
    )
    
    if ($null -eq $InputData) {
        return $null
    }
    
    try {
        # Handle different input types
        if ($InputData -is [Google.Protobuf.ByteString]) {
            $bytes = $InputData.ToByteArray()
            $result = [System.Text.Encoding]::UTF8.GetString($bytes)
            return $result
        }
        elseif ($InputData -is [byte[]]) {
            $result = [System.Text.Encoding]::UTF8.GetString($InputData)
            return $result
        }
        elseif ($InputData -is [string]) {
            try {
                $bytes = $InputData -split '\s+' | ForEach-Object { [byte]$_ }
                $result = [System.Text.Encoding]::UTF8.GetString([byte[]]$bytes)
                return $result
            }
            catch {
                return $InputData
            }
        }
        else {
            return $InputData.ToString()
        }
    }
    catch {
        throw
    }
}

function Get-KeeperAuthenticationOptions {
    <#
    .SYNOPSIS
    Gets Windows Hello authentication options from Keeper API
    
    .DESCRIPTION
    This function retrieves authentication options from the Keeper API,
    including challenge and assertion options needed for Windows Hello authentication.
    It works with both Vault and AuthSync objects, automatically detecting which one is provided.
    
    .PARAMETER Username
    The username to authenticate (optional - will use current auth username if not provided)
    
    .PARAMETER Purpose
    The purpose of authentication: 'login' (default) or 'vault' (re-authentication)
    
    .PARAMETER AuthSyncObject
    Keeper AuthSync instance (optional - will use global auth if not provided)
    
    .PARAMETER Vault
    Keeper Vault instance (optional - will use global vault if not provided)
    
    .EXAMPLE
    $authOptions = Get-KeeperAuthenticationOptions
    if ($authOptions) {
        # Use with Windows Hello authentication
    }
    
    .EXAMPLE
    $authOptions = Get-KeeperAuthenticationOptions -Username "user@company.com" -Purpose "vault"
    
    .EXAMPLE
    $authOptions = Get-KeeperAuthenticationOptions -Vault $vault -Purpose "vault"
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Username,
        
        [Parameter()]
        [ValidateSet('login', 'vault')]
        [string]$Purpose = 'login',
        
        [Parameter()]
        [object]$AuthSyncObject,
        
        [Parameter()]
        [object]$Vault
    )
    
    try {
        $auth = $null
        $isVault = $false
        
        # Determine which object to use - prioritize Vault if both are provided
        if ($Vault) {
            $auth = $Vault.Auth
            $isVault = $true
        } elseif ($AuthSyncObject) {
            $auth = $AuthSyncObject
            $isVault = $false
        } else {
            # Try to get from global context - prioritize Vault
            if (Get-Command getVault -ErrorAction SilentlyContinue) {
                $vault = getVault
                $auth = $vault.Auth
                $isVault = $true
            } elseif ($Script:Context.Vault) {
                $vault = $Script:Context.Vault
                $auth = $vault.Auth
                $isVault = $true
            } elseif (Get-Command getAuthSync -ErrorAction SilentlyContinue) {
                $auth = getAuthSync
                $isVault = $false
            } elseif ($Script:Context.AuthSync) {
                $auth = $Script:Context.AuthSync
                $isVault = $false
            } else {
                throw "No Vault or AuthSync instance available. Please connect to Keeper first or provide a Vault or AuthSyncObject parameter."
            }
        }
                
        # Create the PasskeyAuthenticationRequest
        $request = [Authentication.PasskeyAuthenticationRequest]::new()
        $request.AuthenticatorAttachment = [Authentication.AuthenticatorAttachment]::Platform
        $request.ClientVersion = $auth.Endpoint.ClientVersion
        
        # Set username (use provided username or current auth username)
        if ($Username) {
            $request.Username = $Username
        } else {
            $request.Username = $auth.Username
        }
        
        # Set passkey purpose
        if ($Purpose -eq 'vault') {
            $request.PasskeyPurpose = [Authentication.PasskeyPurpose]::PkReauth
        } else {
            $request.PasskeyPurpose = [Authentication.PasskeyPurpose]::PkLogin
        }
        
        # Add device token if available
        if ($auth.DeviceToken) {
            $request.EncryptedDeviceToken = [Google.Protobuf.ByteString]::CopyFrom([byte[]]$auth.DeviceToken)
        }
        
        # Execute API call based on object type
        if ($isVault) {
            # Use ExecuteAuthRest for Vault
            $response = $auth.ExecuteAuthRest("authentication/passkey/generate_authentication", $request, [Authentication.PasskeyAuthenticationResponse]).GetAwaiter().GetResult()
        } else {
            # Use ExecuteRest for AuthSync
            $requestBytes = [Google.Protobuf.MessageExtensions]::ToByteArray($request)
            $apiRequest = [Authentication.ApiRequestPayload]::new()
            $apiRequest.Payload = [Google.Protobuf.ByteString]::CopyFrom($requestBytes)
            $responseBytes = $auth.Endpoint.ExecuteRest("authentication/passkey/generate_authentication", $apiRequest).GetAwaiter().GetResult()
            $response = [Authentication.PasskeyAuthenticationResponse]::Parser.ParseFrom($responseBytes)
        }
        
        $requestOptions = $response.PkRequestOptions | ConvertFrom-Json
        
        $result = @{
            challenge_token = $response.ChallengeToken
            request_options = $requestOptions
            login_token = $response.EncryptedLoginToken
            purpose = $Purpose
            username = $request.Username
            success = $true
            challenge = $requestOptions.challenge
            allowCredentials = $requestOptions.allowCredentials
            timeout = $requestOptions.timeout
            userVerification = $requestOptions.userVerification
            rpId = $requestOptions.rpId
            }
        return $result
    }
    catch {
        Write-Error "Failed to generate authentication options: $($_.Exception.Message)"
        return @{
            success = $false
            error_message = $_.Exception.Message
            error_type = $_.Exception.GetType().Name
        }
    }
}

function Invoke-WindowsHelloAssertion {
    <#
    .SYNOPSIS
    Performs Windows Hello authentication (GetAssertion) using existing credentials
    
    .DESCRIPTION
    This function performs WebAuthn GetAssertion operation using Windows Hello,
    Uses existing Windows Hello credentials to authenticate with a challenge.
    
    .PARAMETER Challenge
    The authentication challenge (byte array, Base64Url string, or ByteString)
    
    .PARAMETER RpId
    The relying party identifier
    
    .PARAMETER AllowedCredentials
    Array of allowed credential descriptors with id and type
    
    .PARAMETER UserVerification
    User verification requirement ("required", "preferred", "discouraged")
    
    .PARAMETER TimeoutMs
    Timeout in milliseconds (default: 60000)
    
    .EXAMPLE
    $authOptions = Get-KeeperAuthenticationOptions
    $rpid = $authOptions.request_options.publicKeyCredentialRequestOptions.rpId
    $assertion = Invoke-WindowsHelloAssertion -Challenge $authOptions.challenge -RpId $rpid -AllowedCredentials $authOptions.allowCredentials
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        $Challenge,
        
        [Parameter(Mandatory=$true)]
        [string]$RpId,
        
        [Parameter()]
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 'AllowedCredentials', Justification='Credential IDs are public identifiers, not sensitive data')]
        [array]$AllowedCredentials = @(),
        
        [Parameter()]
        [string]$UserVerification = "required",
        
        [Parameter()]
        [int]$TimeoutMs = 60000
    )
    
    if (-not (Test-AssemblyAvailable)) {
        return @{
            Success = $false
            ErrorMessage = "PowerShellWindowsHello assembly not available"
            ErrorType = "AssemblyNotFound"
        }
    }
    
    try {
        $challengeBytes = $null
        
        if ($Challenge -is [byte[]]) {
            $challengeBytes = $Challenge
        }
        elseif ($Challenge -is [string]) {
            $challengeBytes = [System.Convert]::FromBase64String($Challenge.Replace('-', '+').Replace('_', '/').PadRight(($Challenge.Length + 3) -band -4, '='))
        }
        elseif ($Challenge.GetType().Name -eq "ByteString" -or $Challenge.GetType().FullName -like "*ByteString*") {
            $challengeBytes = $Challenge.ToByteArray()
        }
        elseif ($Challenge -and $Challenge.GetType().GetMethod("ToByteArray")) {
            $challengeBytes = $Challenge.ToByteArray()
        }
        else {
            throw "Challenge must be either a byte array, Base64Url encoded string, or ByteString. Received type: $($Challenge.GetType().FullName)"
        }
        
        $options = [KeeperBiometric.AuthenticationOptions]@{
            RpId = $RpId
            Challenge = $challengeBytes
            TimeoutMs = $TimeoutMs
            UserVerification = $UserVerification
        }
        
        if ($AllowedCredentials -and $AllowedCredentials.Count -gt 0) {
            $credentialIds = @()
            foreach ($cred in $AllowedCredentials) {
                if ($cred.id) {
                    $credentialIds += $cred.id
                }
            }
            if ($credentialIds.Count -gt 0) {
                $options.AllowedCredentialIds = $credentialIds
            }
        }
        
        $result = [KeeperBiometric.WindowsHelloApi]::AuthenticateAsync($options).GetAwaiter().GetResult()
        
        if (-not $result.Success) {
            Write-Warning "Windows Hello Assertion failed: $($result.ErrorMessage)"
            return @{
                Success = $false
                ErrorMessage = $result.ErrorMessage
                ErrorType = $result.ErrorType
                HResult = $result.HResult
            }
        }
                
        return @{
            Success = $true
            CredentialId = $result.CredentialId
            AuthenticatorData = $result.AuthenticatorData
            ClientDataJSON = $result.ClientDataJSON
            Signature = $result.Signature
            UserHandle = $result.UserHandle
            RpId = $RpId
            Challenge = $Challenge
        }
    }
    catch {
        Write-Error "Windows Hello assertion failed: $($_.Exception.Message)"
        return @{
            Success = $false
            ErrorMessage = $_.Exception.Message
            ErrorType = $_.Exception.GetType().Name
        }
    }
}

function Complete-KeeperAuthentication {
    <#
    .SYNOPSIS
    Completes Keeper authentication using Windows Hello assertion result
    
    .DESCRIPTION
    This function sends the Windows Hello assertion result to Keeper to complete
    the authentication process.
    
    .PARAMETER ChallengeToken
    The challenge token received from Get-KeeperAuthenticationOptions
    
    .PARAMETER LoginToken
    The encrypted login token from Get-KeeperAuthenticationOptions
    
    .PARAMETER CredentialId
    The credential ID from Windows Hello assertion (Base64Url encoded)
    
    .PARAMETER AuthenticatorData
    The authenticator data from Windows Hello assertion (Base64Url encoded)
    
    .PARAMETER ClientDataJSON
    The client data JSON from Windows Hello assertion (Base64Url encoded)
    
    .PARAMETER Signature
    The assertion signature from Windows Hello (Base64Url encoded)
    
    .PARAMETER UserHandle
    The user handle from Windows Hello assertion (optional)
    
    .PARAMETER RpId
    The relying party identifier (optional - for logging/validation)
    
    .PARAMETER Purpose
    The purpose of authentication: 'login' (default) or 'vault' (re-authentication)
    
    .PARAMETER AuthSyncObject
    Keeper AuthSync instance (optional - will use global auth if not provided)
    
    .PARAMETER Vault
    Keeper Vault instance (optional - will use global vault if not provided)
    
    .EXAMPLE
    $authOptions = Get-KeeperAuthenticationOptions -Purpose "vault"
    $rpid = $authOptions.request_options.publicKeyCredentialRequestOptions.rpId
    $assertion = Invoke-WindowsHelloAssertion -Challenge $authOptions.challenge -RpId $rpid -AllowedCredentials $authOptions.allowCredentials
    if ($assertion.Success) {
        $authResult = Complete-KeeperAuthentication -ChallengeToken $authOptions.challenge_token -LoginToken $authOptions.login_token -CredentialId $assertion.CredentialId -AuthenticatorData $assertion.AuthenticatorData -ClientDataJSON $assertion.ClientDataJSON -Signature $assertion.Signature -RpId $rpid -Purpose "vault"
    }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [byte[]]$ChallengeToken,
        
        [Parameter(Mandatory=$false)]
        [byte[]]$LoginToken,
        
        [Parameter(Mandatory=$true)]
        [string]$CredentialId,
        
        [Parameter(Mandatory=$true)]
        [string]$AuthenticatorData,
        
        [Parameter(Mandatory=$true)]
        [string]$ClientDataJSON,
        
        [Parameter(Mandatory=$true)]
        [string]$Signature,
        
        [Parameter()]
        [string]$UserHandle,
        
        [Parameter()]
        [string]$RpId,
        
        [Parameter()]
        [ValidateSet('login', 'vault')]
        [string]$Purpose = 'login',
        
        [Parameter()]
        [object]$AuthSyncObject,
        
        [Parameter()]
        [object]$Vault
    )
    
    try {
        $auth = $null
        $isVault = $false
        
        if ($Vault) {
            $auth = $Vault.Auth
            $isVault = $true
        } elseif ($AuthSyncObject) {
            $auth = $AuthSyncObject
            $isVault = $false
        } else {
            if (Get-Command getVault -ErrorAction SilentlyContinue) {
                $vault = getVault
                $auth = $vault.Auth
                $isVault = $true
            } elseif ($Script:Context.Vault) {
                $vault = $Script:Context.Vault
                $auth = $vault.Auth
                $isVault = $true
            } elseif (Get-Command getAuthSync -ErrorAction SilentlyContinue) {
                $auth = getAuthSync
                $isVault = $false
            } elseif ($Script:Context.AuthSync) {
                $auth = $Script:Context.AuthSync
                $isVault = $false
            } else {
                throw "No Vault or AuthSync instance available. Please connect to Keeper first or provide a Vault or AuthSyncObject parameter."
            }
        }
        
        $request = [Authentication.PasskeyValidationRequest]::new()
        
        $request.ChallengeToken = [Google.Protobuf.ByteString]::CopyFrom([byte[]]$ChallengeToken)
    
        if ($LoginToken -is [string]) {
            $loginTokenBase64 = $LoginToken.Replace('-', '+').Replace('_', '/').PadRight(($LoginToken.Length + 3) -band -4, '=')
            $loginTokenBytes = [System.Convert]::FromBase64String($loginTokenBase64)
            $request.EncryptedLoginToken = [Google.Protobuf.ByteString]::CopyFrom($loginTokenBytes)
        } else {
            $loginTokenBytes = [Google.Protobuf.ByteString]::CopyFrom([byte[]]$LoginToken)
            if ($loginTokenBytes.Length -gt 0) {
                $request.EncryptedLoginToken = $loginTokenBytes
            }
        }
        $signatureBase64Url = ""

        function ConvertTo-Base64Url {
            param([byte[]]$Bytes)
            if ($Bytes -is [byte[]]) {
                $base64 = [System.Convert]::ToBase64String($Bytes)
                return $base64.Replace('+', '-').Replace('/', '_').TrimEnd('=')
            }
            return $Bytes
        }

        $request.passkeyPurpose = if ($Purpose -eq 'vault') { [Authentication.PasskeyPurpose]::PkReauth } else { [Authentication.PasskeyPurpose]::PkLogin }
        
        # Convert ClientDataJSON
        if ($ClientDataJSON -is [byte[]]) {
            $clientDataBase64Url = ConvertTo-Base64Url $ClientDataJSON
        } else {
            $clientDataBase64Url = $ClientDataJSON
        }
        
        # Convert AuthenticatorData
        if ($AuthenticatorData -is [byte[]]) {
            $authenticatorDataBase64Url = ConvertTo-Base64Url $AuthenticatorData
        } else {
            $authenticatorDataBase64Url = $AuthenticatorData
        }
        
        # Convert Signature
        if ($Signature -is [byte[]]) {
            $signatureBase64Url = ConvertTo-Base64Url $Signature
        } else {
            $signatureBase64Url = $Signature
        }
        
        $assertionResponse = @{
            id = $CredentialId
            rawId = $CredentialId
            response = @{
                authenticatorData = $authenticatorDataBase64Url
                clientDataJSON = $clientDataBase64Url
                signature = $signatureBase64Url
            }
            type = "public-key"
            clientExtensionResults = @{}
        }
        
        # Add user handle if provided
        if ($UserHandle) {
            $assertionResponse.response.userHandle = $UserHandle
        }
        
        $assertionResponseJson = $assertionResponse | ConvertTo-Json -Depth 10 -Compress
        
        $assertionResponseBytes = [System.Text.Encoding]::UTF8.GetBytes($assertionResponseJson)
        $request.AssertionResponse = [Google.Protobuf.ByteString]::CopyFrom($assertionResponseBytes)
 
        # Execute API call based on object type
        if ($isVault) {
            # Use ExecuteAuthRest for Vault
            $response = $auth.ExecuteAuthRest("authentication/passkey/verify_authentication", $request, [Authentication.PasskeyValidationResponse]).GetAwaiter().GetResult()
        } else {
            # Use ExecuteRest for AuthSync
            $requestBytes = [Google.Protobuf.MessageExtensions]::ToByteArray($request)
            $apiRequest = [Authentication.ApiRequestPayload]::new()
            $apiRequest.Payload = [Google.Protobuf.ByteString]::CopyFrom($requestBytes)
            $responseBytes = $auth.Endpoint.ExecuteRest("authentication/passkey/verify_authentication", $apiRequest).GetAwaiter().GetResult()
            $response = [Authentication.PasskeyValidationResponse]::Parser.ParseFrom($responseBytes)
        }
                
        return @{
            Success = $true
            Message = "Authentication completed successfully"
            IsValid = $response.IsValid
            EncryptedLoginToken = $response.EncryptedLoginToken
            Descriptor = $response.Descriptor
        }
    }
    catch {
        Write-Error "Failed to complete Keeper authentication: $($_.Exception.Message)"
        return @{
            Success = $false
            ErrorMessage = $_.Exception.Message
            ErrorType = $_.Exception.GetType().Name
        }
    }
}

function Assert-KeeperBiometricCredential {
    <#
    .SYNOPSIS
    Complete Windows Hello authentication flow with Keeper
    
    .DESCRIPTION
    This function performs the complete Windows Hello authentication flow:
    1. Gets authentication options from Keeper API
    2. Performs Windows Hello assertion
    3. Completes authentication with Keeper
        
    .PARAMETER Username
    The username to authenticate (optional - will use current auth username if not provided)
    
    .PARAMETER Purpose
    The purpose of authentication: 'login' (default) or 'vault' (re-authentication)
    
    .PARAMETER AuthSyncObject
    Keeper AuthSync instance (optional - will use global auth if not provided)
    
    .PARAMETER Vault
    Keeper Vault instance (optional - will use global vault if not provided)
    
    .PARAMETER PassThru
    Return the authentication result object. If not specified, function returns nothing.
    
    .EXAMPLE
    Assert-KeeperBiometricCredential
    # Performs authentication without returning a result object
    
    .EXAMPLE
    $result = Assert-KeeperBiometricCredential -PassThru
    if ($result.Success) {
        Write-Host "Authentication successful!"
    }
    
    .EXAMPLE
    $result = Assert-KeeperBiometricCredential -Purpose "vault" -PassThru
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Username,
        
        [Parameter()]
        [ValidateSet('login', 'vault')]
        [string]$Purpose = 'login',
        
        [Parameter()]
        [object]$AuthSyncObject,
        
        [Parameter()]
        [object]$Vault,
        
        [Parameter()]
        [switch]$PassThru
    )
    
    try {
        Write-Debug "`nStep 1: Getting authentication options from Keeper..."
        $authOptions = Get-KeeperAuthenticationOptions -Username $Username -Purpose $Purpose -AuthSyncObject $AuthSyncObject -Vault $Vault
        
        if (-not $authOptions.success) {
            if ($PassThru) {
                return @{
                    Success = $false
                    ErrorMessage = "Failed to get authentication options: $($authOptions.error_message)"
                    ErrorType = "AuthenticationOptionsError"
                }
            }
            return
        }
        $rpid = $authOptions.request_options.publicKeyCredentialRequestOptions.rpId
        Write-Debug "Authentication options retrieved successfully"
        
        $allowCredentials = $authOptions.request_options.publicKeyCredentialRequestOptions.allowCredentials
        if ($allowCredentials) {
            Write-Debug "Allowed credentials: $($allowCredentials.Count)"
        } else {
            Write-Debug "Allowed credentials: 0 (any registered credential)"
        }
        
        # Step 2: Perform Windows Hello assertion
        Write-Debug "`nStep 2: Performing Windows Hello authentication..."
        
        # Ensure we have the required properties
        if (-not $authOptions.challenge_token) {
            if ($PassThru) {
                return @{
                    Success = $false
                    ErrorMessage = "No challenge token received from authentication options"
                    ErrorType = "AuthenticationOptionsError"
                }
            }
            return
        }
        
        if (-not $rpid) {
            if ($PassThru) {
                return @{
                    Success = $false
                    ErrorMessage = "No RP ID received from authentication options"
                    ErrorType = "AuthenticationOptionsError"
                }
            }
            return
        }
        
        $assertion = Invoke-WindowsHelloAssertion -Challenge $authOptions.request_options.publicKeyCredentialRequestOptions.challenge -RpId $rpid -AllowedCredentials $allowCredentials -UserVerification $authOptions.userVerification
        
        if (-not $assertion.Success) {
            if ($PassThru) {
                return @{
                    Success = $false
                    ErrorMessage = "Windows Hello assertion failed: $($assertion.ErrorMessage)"
                    ErrorType = "WindowsHelloAssertionError"
                }
            }
            return
        }
        
        Write-Debug "Windows Hello assertion completed successfully"
        
        # Step 3: Complete authentication with Keeper
        Write-Debug "`nStep 3: Completing authentication with Keeper..."
        $completion = Complete-KeeperAuthentication -ChallengeToken $authOptions.challenge_token -LoginToken $authOptions.login_token -CredentialId $assertion.CredentialId -AuthenticatorData $assertion.AuthenticatorData -ClientDataJSON $assertion.ClientDataJSON -Signature $assertion.Signature -UserHandle $assertion.UserHandle -AuthSyncObject $AuthSyncObject -Vault $Vault -RpId $rpid -Purpose $Purpose
        
        if (-not $completion.Success) {
            if ($PassThru) {
                return @{
                    Success = $false
                    ErrorMessage = $_.Exception.Message
                    ErrorType = $_.Exception.GetType().Name
                }
            }
            return
        }
        
        Write-Host "Verification completed successfully!"
        
        if ($PassThru) {
            return @{
                Success = $true
                Purpose = $Purpose
                Username = $authOptions.username
                CredentialId = $assertion.CredentialId
                IsValid = $completion.IsValid
                EncryptedLoginToken = $completion.EncryptedLoginToken
                Message = "Windows Hello authentication with Keeper completed successfully"
            }
        }
    }
    catch {
        Write-Error "Windows Hello authentication flow failed: $($_.Exception.Message)"
        if ($PassThru) {
            return @{
                Success = $false
                ErrorMessage = $_.Exception.Message
                ErrorType = $_.Exception.GetType().Name
            }
        }
    }
}

function Register-KeeperCredential {
    <#
    .SYNOPSIS
    Registers a WebAuthn credential with Keeper's servers
    
    .DESCRIPTION
    This function registers a created Windows Hello credential with Keeper's API,
    completing the credential registration flow.
    
    .PARAMETER ChallengeToken
    The challenge token received from Get-KeeperRegistrationOptions
    
    .PARAMETER CredentialId
    The credential ID from the created credential (Base64Url encoded)
    
    .PARAMETER AttestationObject
    The attestation object from the created credential (Base64Url encoded)
    
    .PARAMETER ClientDataJSON
    The client data JSON from the created credential (Base64Url encoded)
    
    .PARAMETER Vault
    Keeper vault instance (optional - will use global vault if not provided)
    
    .EXAMPLE
    $credResult = Invoke-WindowsHelloCredentialCreation -Challenge $challenge -UserId $userId -UserName $userName
    if ($credResult.Success) {
        $regResult = Register-KeeperCredential -ChallengeToken $challengeToken -CredentialId $credResult.CredentialId -AttestationObject $credResult.AttestationObject -ClientDataJSON $credResult.ClientDataJSON
    }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [byte[]]$ChallengeToken,
        
        [Parameter(Mandatory=$true)]
        [string]$CredentialId,
        
        [Parameter(Mandatory=$true)]
        [object]$AttestationObject,
        
        [Parameter(Mandatory=$true)]
        [string]$ClientDataJSON,
        
        [Parameter(Mandatory=$false)]
        [object]$Vault
    )
    
    try {
        # Get vault instance
        if (-not $Vault) {
            if (Get-Command getVault -ErrorAction SilentlyContinue) {
                $vault = getVault
            } elseif ($Script:Context.Vault) {
                $vault = $Script:Context.Vault
            } else {
                throw "No vault instance available. Please connect to Keeper first or provide a vault parameter."
            }
        } else {
            $vault = $Vault
        }
        
        $auth = $vault.Auth
        
        # Create the registration completion request
        $request = [Authentication.PasskeyRegistrationFinalization]::new()
        
        $request.ChallengeToken = [Google.Protobuf.ByteString]::CopyFrom([byte[]]$ChallengeToken)
        
        # This ensures rawId represents the actual raw credential ID bytes
        $base64 = $CredentialId.Replace('-', '+').Replace('_', '/')
        while ($base64.Length % 4 -ne 0) { $base64 += '=' }
        $rawCredBytes = [Convert]::FromBase64String($base64)
        $rawIdBase64Url = [Convert]::ToBase64String($rawCredBytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
        
        $authenticatorResponseJson = @"
{
  "id": "$CredentialId",
  "rawId": "$rawIdBase64Url",
  "response": {
    "attestationObject": "$AttestationObject",
    "clientDataJSON": "$ClientDataJSON"
  },
  "type": "public-key",
  "clientExtensionResults": {}
}
"@
        
        $request.authenticatorResponse = $authenticatorResponseJson
        $request.FriendlyName = $friendly_name
        
        $response = $auth.ExecuteAuthRest("authentication/passkey/verify_registration", $request).GetAwaiter().GetResult()
        
        return @{
            Success = $true
            CredentialId = $CredentialId
            Status = "Registered"
            Message = "WebAuthn credential successfully registered with Keeper"
            Response = $response
            Timestamp = [DateTime]::UtcNow
        }
    }
    catch {
        Write-Error "Failed to register credential with Keeper: $($_.Exception.Message)"
        return @{
            Success = $false
            Error = $_.Exception.Message
            ErrorType = $_.Exception.GetType().Name
            Timestamp = [DateTime]::UtcNow
        }
    }
}
function Get-KeeperAvailableBiometricCredentials {
    <#
    .SYNOPSIS
    Get list of available biometric credentials from Keeper
    
    .DESCRIPTION
    This function retrieves a list of all registered biometric credentials (passkeys) 
    associated with the current Keeper account. It returns information about each credential
    including user ID, friendly name, creation date, last used date, and credential ID.
    
    .PARAMETER Vault
    Keeper vault instance (optional - will use global vault if not provided)
    
    .PARAMETER IncludeDisabled
    Include disabled credentials in the results (default: false)
    
    .EXAMPLE
    $credentials = Get-KeeperAvailableBiometricCredentials
    $credentials | Format-Table
    
    .EXAMPLE
    $allCredentials = Get-KeeperAvailableBiometricCredentials -IncludeDisabled
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [object]$Vault,
        
        [Parameter(Mandatory=$false)]
        [switch]$IncludeDisabled
    )
    
    try {
        # Get vault instance
        if (-not $Vault) {
            if (Get-Command getVault -ErrorAction SilentlyContinue) {
                $vault = getVault
            } elseif ($Script:Context.Vault) {
                $vault = $Script:Context.Vault
            } else {
                throw "No vault instance available. Please connect to Keeper first or provide a vault parameter."
            }
        } else {
            $vault = $Vault
        }
        
        $auth = $vault.Auth
        
        # Create the passkey list request
        $request = [Authentication.PasskeyListRequest]::new()
        $request.IncludeDisabled = $IncludeDisabled.IsPresent
        
        # Execute the API call
        $response = $auth.ExecuteAuthRest("authentication/passkey/get_available_keys", $request, [Authentication.PasskeyListResponse]).GetAwaiter().GetResult()
        
        # Convert the response to PowerShell objects
        $credentials = @()
        foreach ($passkey in $response.PasskeyInfo) {
            $credential = [PSCustomObject]@{
                Id = $passkey.UserId
                Name = $passkey.FriendlyName
                Created = if ($passkey.CreatedAtMillis -gt 0) { [DateTimeOffset]::FromUnixTimeMilliseconds($passkey.CreatedAtMillis).DateTime } else { $null }
                LastUsed = if ($passkey.LastUsedMillis -gt 0) { [DateTimeOffset]::FromUnixTimeMilliseconds($passkey.LastUsedMillis).DateTime } else { $null }
                CredentialId = $passkey.CredentialId
                AAGUID = if ($passkey.AAGUID) { $passkey.AAGUID.Replace('-', '') } else { $null }
                Disabled = if ($passkey.DisabledAtMillis -gt 0) { [DateTimeOffset]::FromUnixTimeMilliseconds($passkey.DisabledAtMillis).DateTime } else { $null }
            }
            $credentials += $credential
        }
        
        return $credentials
    }
    catch {
        Write-Error "Failed to get available biometric credentials: $($_.Exception.Message)"
        throw "Error getting available biometric credentials: $($_.Exception.Message)"
    }
}

# AAGUID to Provider Name mapping based on community-sourced data
# Source: https://github.com/passkeydeveloper/passkey-authenticator-aaguids
$script:AAGUID_PROVIDER_MAPPING = @{
    'ea9b8d664d011d213ce4b6b48cb575d4' = 'Google Password Manager'
    'adce000235bcc60a648b0b25f1f05503' = 'Chrome on Mac'
    'fbfc3007154e4ecc8c0b6e020557d7bd' = 'iCloud Keychain'
    'dd4ec289e01d41c9bb8970fa845d4bf2' = 'iCloud Keychain (Managed)'
    '08987058cadc4b81b6e130de50dcbe96' = 'Windows Hello'
    '9ddd1817af5a4672a2b93e3dd95000a9' = 'Windows Hello'
    '6028b017b1d44c02b4b3afcdafc96bb2' = 'Windows Hello'
    '00000000000000000000000000000000' = 'Platform Authenticator'
}

function Get-ProviderNameFromAAGUID {
    <#
    .SYNOPSIS
    Get friendly provider name from AAGUID
    
    .DESCRIPTION
    Maps an AAGUID to a friendly provider name using the community-sourced mapping.
    
    .PARAMETER AAGUID
    The AAGUID to look up
    
    .EXAMPLE
    Get-ProviderNameFromAAGUID -AAGUID "9ddd1817-af5a-4672-a2b9-3e3dd95000a9"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$AAGUID
    )
    
    if ($script:AAGUID_PROVIDER_MAPPING.ContainsKey($AAGUID)) {
        return $script:AAGUID_PROVIDER_MAPPING[$AAGUID]
    } else {
        return "Unknown Provider ($AAGUID)"
    }
}


function Disable-KeeperPasskey {
    <#
    .SYNOPSIS
    Disable a passkey on the Keeper server
    
    .DESCRIPTION
    This function disables a specific passkey on the Keeper server using the UpdatePasskeyRequest API.
    
    .PARAMETER Vault
    Keeper vault instance
    
    .PARAMETER UserId
    User ID for the passkey
    
    .PARAMETER CredentialId
    Credential ID to disable (Base64Url encoded)
    
    .EXAMPLE
    $result = Disable-KeeperPasskey -Vault $vault -UserId "user123" -CredentialId "abc123def456"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [object]$Vault,
        
        [Parameter(Mandatory=$true)]
        [string]$UserId,
        
        [Parameter(Mandatory=$true)]
        [string]$CredentialId
    )
    
    try {
        $auth = $vault.Auth
        $request = [Authentication.UpdatePasskeyRequest]::new()
        $request.UserId = $UserId
        $credentialIdBytes = $null
        if ($CredentialId -match '^[A-Za-z0-9+/=_-]+$') {
            $base64 = $CredentialId
            
            if ($CredentialId.Contains('-') -or $CredentialId.Contains('_')) {
                $base64 = $CredentialId.Replace('-', '+').Replace('_', '/')
            }
            
            while ($base64.Length % 4 -ne 0) { $base64 += '=' }
            
            $credentialIdBytes = [Convert]::FromBase64String($base64)
        } else {
            $credentialIdBytes = [System.Text.Encoding]::UTF8.GetBytes($CredentialId)
        }
        
        $request.CredentialId = [Google.Protobuf.ByteString]::CopyFrom($credentialIdBytes)
        $response = $auth.ExecuteAuthRest("authentication/passkey/disable", $request).GetAwaiter().GetResult()
        return @{
            Success = $true
            Message = "Passkey unregistered successfully"
            UserId = $UserId
            CredentialId = $CredentialId
        }
    }
    catch {
        $errorMsg = $_.Exception.Message.ToLower()
        if ($errorMsg -like "*bad_request*" -or $errorMsg -like "*credential id*" -or $errorMsg -like "*userid*") {
            return @{
                Success = $false
                ErrorMessage = "Invalid credential ID or user ID"
                ErrorType = "BadRequest"
            }
        } elseif ($errorMsg -like "*server_error*" -or $errorMsg -like "*unexpected*") {
            return @{
                Success = $false
                ErrorMessage = "Server error occurred"
                ErrorType = "ServerError"
            }
        } else {
            return @{
                Success = $false
                ErrorMessage = $_.Exception.Message
                ErrorType = $_.Exception.GetType().Name
            }
        }
    }
}

function Unregister-KeeperBiometricCredential {
    <#
    .SYNOPSIS
    Remove/unregister biometric credentials from Keeper
    
    .DESCRIPTION
    This function removes or unregisters biometric credentials (passkeys) from the Keeper account.
    It can remove specific credentials by ID or unregister all biometric authentication for the user.
    
    .PARAMETER CredentialId
    Specific credential ID to remove (optional - if not provided, unregisters all biometric auth)
    
    .PARAMETER Username
    Username to unregister biometric auth for (optional - uses current user if not provided)
    
    .PARAMETER Confirm
    Skip confirmation prompt (default: false)
    
    .PARAMETER Vault
    Keeper vault instance (optional - will use global vault if not provided)
    
    .PARAMETER PassThru
    Return the result object. If not specified, function returns nothing.
    
    .EXAMPLE
    # Unregister all biometric authentication for current user
    Unregister-KeeperBiometricCredential
    
    .EXAMPLE
    # Unregister specific credential
    Unregister-KeeperBiometricCredential -CredentialId "abc123def456"
    
    .EXAMPLE
    # Unregister for specific user without confirmation
    Unregister-KeeperBiometricCredential -Username "user@company.com" -Confirm
    
    .EXAMPLE
    # Get result object
    $result = Unregister-KeeperBiometricCredential -PassThru
    if ($result.Success) {
        Write-Host "Unregistration successful!"
    }
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory=$false)]
        [string]$CredentialId,
        
        [Parameter(Mandatory=$false)]
        [string]$Username,
        
        [Parameter(Mandatory=$false)]
        [object]$Vault,
        
        [Parameter(Mandatory=$false)]
        [switch]$PassThru
    )
    
    try {
        if (-not $Vault) {
            if (Get-Command getVault -ErrorAction SilentlyContinue) {
                $vault = getVault
            } elseif ($Script:Context.Vault) {
                $vault = $Script:Context.Vault
            } else {
                throw "No vault instance available. Please connect to Keeper first or provide a vault parameter."
            }
        } else {
            $vault = $Vault
        }
        $auth = $vault.Auth
        
        if (-not $Username) {
            $Username = $auth.Username
        }
        
        $hasBiometric = Test-WindowsHelloBiometricPreviouslyUsed -Username $Username
        if (-not $hasBiometric) {
            $result = @{
                Success = $true
                Message = "Biometric authentication is not yet registered"
            }
            if ($PassThru) {
                return $result
            }
            return
        }
        
        $confirmationMessage = if ($CredentialId) {
            "Are you sure you want to permanently remove the biometric credential '$CredentialId' for user '$Username'? (y/N): "
        } else {
            "Are you sure you want to permanently remove ALL biometric authentication for user '$Username'? (y/N): "
        }
        
        $response = Read-Host $confirmationMessage
        if ($response -ne 'y' -and $response -ne 'Y') {
            $result = @{
                Success = $false
                Message = "Operation cancelled by user"
            }
            if ($PassThru) {
                return $result
            }
            return
        }
        
        $rpId = $script:DefaultRpId
        
        Write-Debug "Unregistering server passkeys..."
        $disableResult = $false
        
        $storedCredentialId = Get-WindowsHelloCredentialId -Username $Username
        
        if ($storedCredentialId) {
            try {
                $availableCredentials = Get-KeeperAvailableBiometricCredentials -Vault $vault                
                $targetPasskey = $null
                $targetPasskeyBase64 = $null
                foreach ($credential in $availableCredentials) {
                    $credentialId = $credential.CredentialId
                    $credentialBytes = $credentialId -split ' ' | ForEach-Object { [byte]$_ }

                    $credentialIdBase64 = [Convert]::ToBase64String($credentialBytes)
                    $credentialIdBase64Url = $credentialIdBase64.Replace('+', '-').Replace('/', '_').TrimEnd('=')
                                                            
                    if ($credentialIdBase64Url -eq $storedCredentialId) {
                        $targetPasskey = $credential
                        $targetPasskeyBase64 = $credentialIdBase64
                        break
                    }
                }
                
                if ($targetPasskey) {
                    try {
                        $disableResult = Disable-KeeperPasskey -Vault $vault -UserId $targetPasskey.Id -CredentialId $targetPasskeyBase64
                        if ($disableResult.Success) {
                            Write-Host "Successfully unregistered passkey on server" -ForegroundColor Green
                        } else {
                            Write-Warning "Failed to unregister passkey on server: $($disableResult.ErrorMessage)"
                            $disableResult = $false
                        }
                    } catch {
                        Write-Warning "Error calling server API to unregister passkey: $($_.Exception.Message)"
                        $disableResult = $false
                    }
                } else {
                    Write-Host "Stored credential ID not found in available credentials - may already be unregistered" -ForegroundColor Yellow
                }
            } catch {
                Write-Warning "Failed to get available credentials: $($_.Exception.Message)"
                $disableResult = $false
            }
        } else {
            Write-Host "No stored credential ID found for user"
        }

        $cleanupSuccess = $false
        if ($storedCredentialId -and $disableResult) {
            $cleanupSuccess = Unregister-WindowsHelloCredential -Username $Username -RpId $rpId -CredentialId $storedCredentialId
        }
        
        $verificationSuccess = -not (Test-WindowsHelloBiometricPreviouslyUsed -Username $Username)
        
        $result = if ($cleanupSuccess -and $verificationSuccess) {
            @{
                Success = $true
                Message = "Biometric credentials unregistered successfully"
                Username = $Username
                CredentialId = $storedCredentialId
            }
        } else {
            @{
                Success = $false
                Message = "Biometric credential unregistration may have failed"
                Username = $Username
                CredentialId = $storedCredentialId
            }
        }
        
        if ($PassThru) {
            return $result
        }
    }
    catch {
        Write-Error "Failed to unregister biometric credentials: $($_.Exception.Message)"
        $errorResult = @{
            Success = $false
            ErrorMessage = $_.Exception.Message
            ErrorType = $_.Exception.GetType().Name
        }
        
        if ($PassThru) {
            return $errorResult
        }
    }
}

function Show-KeeperBiometricCredentials {
    <#
    .SYNOPSIS
    Display biometric credentials in a formatted table
    
    .DESCRIPTION
    This function retrieves and displays all registered biometric credentials (passkeys) 
    It shows credential name, creation date, and last used date.
    
    .PARAMETER Vault
    Keeper vault instance (optional - will use global vault if not provided)
    
    .PARAMETER IncludeDisabled
    Include disabled credentials in the results (default: false)
    
    .EXAMPLE
    Show-KeeperBiometricCredentials
    
    .EXAMPLE
    Show-KeeperBiometricCredentials -IncludeDisabled
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [object]$Vault,
        
        [Parameter(Mandatory=$false)]
        [switch]$IncludeDisabled
    )
    
    try {
        $credentials = Get-KeeperAvailableBiometricCredentials -Vault $Vault -IncludeDisabled:$IncludeDisabled
        
        if (-not $credentials -or $credentials.Count -eq 0) {
            Write-Host "No biometric authentication methods found." -ForegroundColor Yellow
            return
        }
        
        Write-Host "`nRegistered Biometric Authentication Methods:" -ForegroundColor Green
        Write-Host ("-" * 70) -ForegroundColor Gray
        
        foreach ($credential in $credentials) {
            $createdDate = if ($credential.Created) { 
                $credential.Created.ToString("yyyy-MM-dd HH:mm:ss") 
            } else { 
                "Never" 
            }
            
            $lastUsedDate = if ($credential.LastUsed) { 
                $credential.LastUsed.ToString("yyyy-MM-dd HH:mm:ss") 
            } else { 
                "Never" 
            }
            
            $displayName = $credential.Name
            if ([string]::IsNullOrWhiteSpace($displayName)) {
                $aaguid = $credential.AAGUID
                if ($aaguid) {
                    $displayName = Get-ProviderNameFromAAGUID -AAGUID $aaguid
                } else {
                    $displayName = "Unknown Provider"
                }
            }
            
            if ($credential.Disabled) {
                $displayName += " (DISABLED)"
            }
            $credentialIdDisplay = [System.Convert]::ToBase64String($credential.CredentialId)
            Write-Host "Id: $credentialIdDisplay" -ForegroundColor Cyan
            Write-Host "Name: $displayName" -ForegroundColor White
            Write-Host "Created: $createdDate" -ForegroundColor Cyan
            Write-Host "Last Used: $lastUsedDate" -ForegroundColor Cyan
            Write-Host ("-" * 70) -ForegroundColor Gray
        }
    }
    catch {
        Write-Error "Failed to display biometric credentials: $($_.Exception.Message)"
        throw "Error displaying biometric credentials: $($_.Exception.Message)"
    }
}

function Register-KeeperBiometricCredential {
    <#
    .SYNOPSIS
    Complete Windows Hello credential creation flow for Keeper
    
    .DESCRIPTION
    This function performs the complete Windows Hello credential creation flow:
    1. Gets registration options from Keeper API
    2. Checks for existing credentials for the same RP ID and username
    3. Either reuses existing credential or creates new one based on user choice
    4. Registers credential with Keeper (if new) or confirms existing registration
    
    The function prevents duplicate credential creation by checking for existing
    Windows Hello credentials for the same relying party and username combination.
    
    .PARAMETER Vault
    Keeper vault instance (optional)
    
    .PARAMETER Force
    Force creation of new credential even if existing credentials are found
    
    .PARAMETER FriendlyName
    Friendly name for the credential (optional)
    
    .PARAMETER PassThru
    Return the registration result object. If not specified, function returns nothing on success or false on failure.
    
    .EXAMPLE
    $result = Register-KeeperBiometricCredential
    if ($result.Success) {
        # Credential ready for Keeper registration
        Write-Host "Credential ID: $($result.CredentialId)"
    }
    
    .EXAMPLE
    # Force creation of new credential even if duplicates exist
    $result = Register-KeeperBiometricCredential -Force
    
    .EXAMPLE
    # Create credential with custom friendly name
    $result = Register-KeeperBiometricCredential -FriendlyName "My Work Laptop"
    
    .EXAMPLE
    # Get detailed result information
    $result = Register-KeeperBiometricCredential -PassThru
    if ($result.Success) {
        Write-Host "Registration successful for user: $($result.Username)"
        Write-Host "Credential ID: $($result.CredentialId)"
    } else {
        Write-Host "Registration failed: $($result.Error)"
    }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [object]$Vault,
        
        [Parameter(Mandatory=$false)]
        [switch]$Force,
        
        [Parameter(Mandatory=$false)]
        [string]$FriendlyName,
        
        [Parameter(Mandatory=$false)]
        [switch]$PassThru
    )
    
    try {
        Write-Host "Biometric Credential Creation for Keeper" -ForegroundColor Yellow
        
        # Get registration options from Keeper API
        $regOptions = Get-KeeperRegistrationOptions -Vault $Vault
        
        # Determine display name
        $displayName = if ($FriendlyName) { 
            $FriendlyName 
        } elseif ($friendly_name) { 
            $friendly_name 
        } else { 
            $regOptions.user_display_name 
        }

        # Get exclude credentials and convert to objects
        $excludeCredentials = $regOptions.creation_options.excludeCredentials
        if ($null -eq $excludeCredentials) {
            $excludeCredentials = @()
        }
        $excludeCredentialObjects = New-ExcludeCredentialObjects -ExcludeCredentials $excludeCredentials
        
        # Ensure we always have a valid array
        if ($null -eq $excludeCredentialObjects) {
            Write-Verbose "ExcludeCredentialObjects was null, setting to empty array"
            $excludeCredentialObjects = @()
        }
        Write-Verbose "ExcludeCredentialObjects count: $($excludeCredentialObjects.Count)"
        
        # Check for existing credential matches
        $matchedCredential = Test-ExistingCredentialMatch `
            -Username $regOptions.user_name `
            -ExcludeCredentials $excludeCredentials `
            -Force:$Force
        
        if ($matchedCredential) {
            Write-Host "Found matching credential which is also in registry!" -ForegroundColor Yellow
            Write-Host "Registration cancelled as a matching credential was found in registry use biometric verify instead to just use the existing credential and login with the existing credential." -ForegroundColor Red
            if ($PassThru) {
                return @{
                    Success = $false
                    Error = "Matching credential found in registry"
                    ErrorType = "DuplicateCredential"
                    Timestamp = [DateTime]::UtcNow
                }
            }
            return $false
        }
        
        # Perform credential creation and registration
        $result = Invoke-CredentialCreationFlow `
            -RegOptions $regOptions `
            -DisplayName $displayName `
            -ExcludeCredentialObjects $excludeCredentialObjects `
            -Vault $Vault
        
        Write-Host "Credential created successfully" -ForegroundColor Green
        Write-Host "Success! Biometric authentication `"$displayName`" has been registered." -ForegroundColor Green
        Write-Host "Please register your device using the `"Set-KeeperDeviceSettings -Register`" command to set biometric authentication as your default login method." -ForegroundColor Yellow
        if ($PassThru) {
            return $result
        } 
    }
    catch {
        Write-ErrorWithContext -Message "Keeper credential creation failed" -FunctionName "Register-KeeperBiometricCredential" -Exception $_.Exception
        $errorResult = @{
            Success = $false
            Error = $_.Exception.Message
            ErrorType = $_.Exception.GetType().Name
            Timestamp = [DateTime]::UtcNow
        }
        return $errorResult
    }
}

if ($IsWindows -or $PSVersionTable.PSVersion.Major -lt 6) {
    $script:WindowsHelloRegistryPath = "HKCU:\Software\Keeper Security\Commander\Biometric"
} else {
    $script:WindowsHelloRegistryPath = $null
}

function Unregister-WindowsHelloCredential {
    <#
    .SYNOPSIS
    Unregisters a Windows Hello credential from the local registry
    
    .DESCRIPTION
    Removes a Windows Hello credential ID from the local registry for a specific user.
    This function is only functional on Windows platforms.
    
    .PARAMETER Username
    The username to unregister
    
    .PARAMETER RpId
    The relying party identifier
    
    .PARAMETER CredentialId
    The credential ID to unregister
    
    .OUTPUTS
    [bool] True if successful, false otherwise
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Username,
        
        [Parameter(Mandatory=$true)]
        [string]$RpId,
        
        [Parameter(Mandatory=$true)]
        [string]$CredentialId
    )
    
    if (-not $script:WindowsHelloRegistryPath) {
        Write-Warning "Windows Hello registry functions are only available on Windows platforms"
        return $false
    }
    
    try {
        $keyName = $Username
        
        if (Test-Path $script:WindowsHelloRegistryPath) {
            Remove-ItemProperty -Path $script:WindowsHelloRegistryPath -Name $keyName -Force -ErrorAction SilentlyContinue
            Write-Host "Successfully unregistered credential for $Username@$RpId" -ForegroundColor Green
        }
        return $true
    }
    catch {
        Write-Error "Failed to unregister credential: $($_.Exception.Message)"
        return $false
    }
}


function Get-WindowsHelloCredentialId {
    <#
    .SYNOPSIS
    Gets a Windows Hello credential ID from the local registry
    
    .DESCRIPTION
    Retrieves a stored Windows Hello credential ID for a specific user from the local registry.
    This function is only functional on Windows platforms.
    
    .PARAMETER Username
    The username to get the credential ID for
    
    .OUTPUTS
    [string] The credential ID if found, null otherwise
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Username
    )
    
    if (-not $script:WindowsHelloRegistryPath) {
        return $null
    }
    
    try {
        if (Test-Path $script:WindowsHelloRegistryPath) {
            $credentialId = Get-ItemProperty -Path $script:WindowsHelloRegistryPath -Name $Username -ErrorAction SilentlyContinue
            
            if ($credentialId -and $credentialId.$Username) {
                $id = $credentialId.$Username
                return $id
            } else {
                return $null
            }
        } else {
            return $null
        }
    }
    catch [System.Management.Automation.ItemNotFoundException] {
        return $null
    }
    catch {
        return $null
    }
}

function Set-WindowsHelloCredentialId {
    <#
    .SYNOPSIS
    Sets a Windows Hello credential ID in the local registry
    
    .DESCRIPTION
    Stores a Windows Hello credential ID for a specific user in the local registry.
    This function is only functional on Windows platforms.
    
    .PARAMETER Username
    The username to set the credential ID for
    
    .PARAMETER CredentialId
    The credential ID to store (optional - if not provided, removes the credential)
    
    .OUTPUTS
    [bool] True if successful, false otherwise
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Username,
        
        [Parameter(Mandatory = $false)]
        [string]$CredentialId
    )
    
    if (-not $script:WindowsHelloRegistryPath) {
        Write-Warning "Windows Hello registry functions are only available on Windows platforms"
        return $false
    }
    
    try {
        if (!(Test-Path $script:WindowsHelloRegistryPath)) {
            New-Item -Path $script:WindowsHelloRegistryPath -Force | Out-Null
        }
        
        if ($CredentialId) {
            # Store the credential ID for the username
            Set-ItemProperty -Path $script:WindowsHelloRegistryPath -Name $Username -Value $CredentialId -Type String
        } else {
            # Remove the credential ID for the username
            Remove-ItemProperty -Path $script:WindowsHelloRegistryPath -Name $Username -ErrorAction SilentlyContinue
        }
        return $true
    }
    catch {
        Write-Warning "Failed to set credential ID for $Username`: $($_.Exception.Message)"
        return $false
    }
}

function Test-WindowsHelloBiometricPreviouslyUsed {
    <#
    .SYNOPSIS
    Tests if a Windows Hello biometric credential was previously used for a user
    
    .DESCRIPTION
    Checks if a Windows Hello credential ID exists in the local registry for a specific user.
    This function is only functional on Windows platforms.
    
    .PARAMETER Username
    The username to check
    
    .OUTPUTS
    [bool] True if credential was previously used, false otherwise
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Username
    )
    
    if (-not $script:WindowsHelloRegistryPath) {
        return $false
    }
    
    try {
        if (Test-Path $script:WindowsHelloRegistryPath) {
            $credentialExists = Get-ItemProperty -Path $script:WindowsHelloRegistryPath -Name $Username -ErrorAction SilentlyContinue
            
            if ($credentialExists) {
                return $true
            } else {
                return $false
            }
        } else {
            return $false
        }
    }
    catch [System.Management.Automation.ItemNotFoundException] {
        return $false
    }
    catch {
        return $false
    }
}

$exportFunctions = @(
    "Test-WindowsHelloCapabilities","Assert-KeeperBiometricCredential","Register-KeeperBiometricCredential","Show-KeeperBiometricCredentials","Unregister-KeeperBiometricCredential"
)

Export-ModuleMember -Function $exportFunctions
