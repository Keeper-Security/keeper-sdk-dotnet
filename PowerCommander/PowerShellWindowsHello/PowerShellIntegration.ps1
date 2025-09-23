# PowerShell Windows Hello Integration
# Lightweight, standalone Windows Hello implementation for PowerCommander
# 
# This module provides enhanced Windows Hello functionality using native WebAuthn APIs
# with no external dependencies beyond the Windows webauthn.dll

#region Module Setup and Loading

# Get the directory where this script is located
$ModuleRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

function Import-PowerShellWindowsHello {
    <#
    .SYNOPSIS
    Loads the PowerShell Windows Hello assembly
    
    .DESCRIPTION
    This function loads the PowerShellWindowsHello.dll assembly, trying different
    framework versions and build configurations automatically.
    #>
    [CmdletBinding()]
    param()
    
    $assemblyLoaded = $false
    $assemblyPaths = @(
        
        # Try .NET Framework first for Windows PowerShell compatibility
        "$ModuleRoot\bin\Release\net472\win-x64\PowerShellWindowsHello.dll",
        "$ModuleRoot\bin\Release\net472\PowerShellWindowsHello.dll",
        # Try .NET 8.0 as fallback (for PowerShell Core)
        "$ModuleRoot\bin\Release\net8.0\PowerShellWindowsHello.dll",
        # Then try Debug builds as fallback
        "$ModuleRoot\bin\Debug\net472\win-x64\PowerShellWindowsHello.dll",
        "$ModuleRoot\bin\Debug\net472\PowerShellWindowsHello.dll",
        "$ModuleRoot\bin\Debug\net8.0\PowerShellWindowsHello.dll"
    )
    
    foreach ($path in $assemblyPaths) {
        if (Test-Path $path) {
            try {
                Add-Type -Path $path -ErrorAction Stop
                Write-Verbose "Loaded PowerShellWindowsHello assembly from: $path"
                $assemblyLoaded = $true
                break
            }
            catch {
                Write-Verbose "Failed to load assembly from $path : $($_.Exception.Message)"
                continue
            }
        }
    }
    
    if (-not $assemblyLoaded) {
        throw @"
PowerShellWindowsHello assembly not found or could not be loaded.

Please build the project first:
  cd $ModuleRoot
  dotnet build

Tried the following locations:
$($assemblyPaths | ForEach-Object { "  - $_" } | Out-String)
"@
    }
    
    return $assemblyLoaded
}

# Try to load the assembly when this module is imported
try {
    Import-PowerShellWindowsHello -Verbose:$VerbosePreference
    $PowerShellWindowsHelloAvailable = $true
}
catch {
    Write-Warning "PowerShellWindowsHello not available: $($_.Exception.Message)"
    $PowerShellWindowsHelloAvailable = $false
}

#endregion

#region Enhanced Windows Hello Functions

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
    
    if (-not $PowerShellWindowsHelloAvailable) {
        if (-not $Quiet) {
            Write-Warning "PowerShellWindowsHello assembly not available. Please build the project first."
        }
        return $false
    }
    
    try {
        # Get comprehensive capabilities
        $capabilities = [PowerShellWindowsHello.WindowsHelloApi]::GetFormattedInfo()
        
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
    The relying party identifier (default: "keepersecurity.com")
    
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
        [string]$RpId = "keepersecurity.com",
        
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
    
    if (-not $PowerShellWindowsHelloAvailable) {
        throw "PowerShellWindowsHello assembly not available. Please build the project first."
    }
    
    try {
        # Create authentication options
        $authOptions = New-Object PowerShellWindowsHello.AuthenticationOptions
        $authOptions.Challenge = $Challenge
        $authOptions.RpId = $RpId
        $authOptions.AllowedCredentialIds = $AllowedCredentials
        $authOptions.TimeoutMs = $TimeoutMs
        $authOptions.UserVerification = $UserVerification
        
        Write-Debug "Please complete Windows Hello verification when prompted..."
        
        # Perform authentication
        $task = [PowerShellWindowsHello.WindowsHelloApi]::AuthenticateAsync($authOptions)
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

function Get-WindowsHelloInfo {
    <#
    .SYNOPSIS
    Gets Windows Hello information in a simple format
    
    .DESCRIPTION
    This function returns basic Windows Hello availability and capability information
    in a format that's easy to consume programmatically.
    
    .EXAMPLE
    $info = Get-WindowsHelloInfo
    if ($info.IsAvailable) {
        Write-Host "Windows Hello is ready"
    }
    #>
    [CmdletBinding()]
    param()
    
    if (-not $PowerShellWindowsHelloAvailable) {
        return @{
            IsAvailable = $false
            ErrorMessage = "PowerShellWindowsHello assembly not available"
            WebAuthnDllAvailable = $false
        }
    }
    
    try {
        $capabilities = [PowerShellWindowsHello.WindowsHelloApi]::GetCapabilities()
        return @{
            IsAvailable = $capabilities.IsAvailable
            ApiVersion = $capabilities.ApiVersion
            Platform = $capabilities.Platform
            SupportedMethods = $capabilities.SupportedMethods
            CanCreateCredentials = $capabilities.CanCreateCredentials
            CanPerformAuthentication = $capabilities.CanPerformAuthentication
            WebAuthnDllAvailable = $capabilities.WebAuthnDllAvailable
            RecommendedIntegration = $capabilities.RecommendedIntegration
            ErrorMessage = $capabilities.ErrorMessage
            LastChecked = $capabilities.LastChecked
        }
    }
    catch {
        return @{
            IsAvailable = $false
            ErrorMessage = $_.Exception.Message
            WebAuthnDllAvailable = $false
            LastChecked = [DateTime]::UtcNow
        }
    }
}

#endregion

#region Windows Hello Registration Functions

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
    The relying party identifier (default: "keepersecurity.com")
    
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
        [string]$RpId = "keepersecurity.com",
        
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
        [PowerShellWindowsHello.ExcludeCredential[]]$ExcludeCredentials
    )
    
    if (-not $PowerShellWindowsHelloAvailable) {
        throw "PowerShellWindowsHello assembly not available. Please build the project first."
    }
    
    try {
        # Create registration options
        $regOptions = New-Object PowerShellWindowsHello.RegistrationOptions
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
        
        # Create credential
        $task = [PowerShellWindowsHello.WindowsHelloApi]::CreateCredentialAsync($regOptions,$excludeCredentials)
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
    This is equivalent to the WindowsHelloAuth.ps1 Get-KeeperPasskeyRegistrationOptions function
    but designed to work with the PowerShellWindowsHello project.
    
    .PARAMETER Vault
    Keeper vault instance (optional - will use global vault if not provided)
    
    .EXAMPLE
    $regOptions = Get-KeeperRegistrationOptions
    if ($regOptions) {
        # Use with Invoke-KeeperCredentialCreation
    }
    #>
    [CmdletBinding()]
    param(
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
        
        $request = [Authentication.PasskeyRegistrationRequest]::new()
        $request.AuthenticatorAttachment = [Authentication.AuthenticatorAttachment]::Platform
        
        $response = $auth.ExecuteAuthRest("authentication/passkey/generate_registration", $request, [Authentication.PasskeyRegistrationResponse]).GetAwaiter().GetResult()
        
        $creationOptions = $response.PkCreationOptions | ConvertFrom-Json
        
        # Try to get the actual byte array from the ByteString
        $challengeTokenBytes = $null
        if ($response.ChallengeToken -is [Google.Protobuf.ByteString]) {
            $challengeTokenBytes = $response.ChallengeToken.ToByteArray()
        } elseif ($response.ChallengeToken -is [byte[]]) {
            $challengeTokenBytes = $response.ChallengeToken
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
    param([string]$Base64UrlString)
    
    if ([string]::IsNullOrEmpty($Base64UrlString)) {
        return $null
    }
    
    try {
        # Convert base64url to standard base64
        $base64 = $Base64UrlString.Replace('-', '+').Replace('_', '/')
        
        # Add padding if needed
        switch ($base64.Length % 4) {
            2 { $base64 += '==' }
            3 { $base64 += '=' }
        }
        
        return [Convert]::FromBase64String($base64)
    }
    catch {
        Write-Verbose "Base64Url decode failed for: $Base64UrlString, error: $($_.Exception.Message)"
        # Fallback: try direct base64 decode
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
    param($InputData)
    
    if ($null -eq $InputData) {
        return $null
    }
    
    # Handle different input types
    if ($InputData -is [Google.Protobuf.ByteString]) {
        return $InputData
    }
    elseif ($InputData -is [byte[]]) {
        return [Google.Protobuf.ByteString]::CopyFrom($InputData)
    }
    elseif ($InputData -is [string]) {
        try {
            # Try to parse string like "1 2 3 4" into byte array
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
    param($InputData)
    
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
                # Try to parse string like "1 2 3 4" into byte array, then to UTF-8 string
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
    Based on the Python generate_authentication_options function.
    
    .PARAMETER Username
    The username to authenticate (optional - will use current auth username if not provided)
    
    .PARAMETER Purpose
    The purpose of authentication: 'login' (default) or 'vault' (re-authentication)
    
    .PARAMETER AuthSyncObject
    Keeper AuthSync instance (optional - will use global auth if not provided)
    
    .EXAMPLE
    $authOptions = Get-KeeperAuthenticationOptions
    if ($authOptions) {
        # Use with Windows Hello authentication
    }
    
    .EXAMPLE
    $authOptions = Get-KeeperAuthenticationOptions -Username "user@company.com" -Purpose "vault"
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Username,
        
        [Parameter()]
        [ValidateSet('login', 'vault')]
        [string]$Purpose = 'login',
        
        [Parameter()]
        [object]$AuthSyncObject
    )
    
    try {
        # Get AuthSync instance
        if (-not $AuthSyncObject) {
            if (Get-Command getAuthSync -ErrorAction SilentlyContinue) {
                $authSync = getAuthSync
            } elseif ($Script:Context.AuthSync) {
                $authSync = $Script:Context.AuthSync
            } else {
                throw "No AuthSync instance available. Please connect to Keeper first or provide an AuthSyncObject parameter."
            }
        } else {
            $authSync = $AuthSyncObject
        }
        
        Write-Verbose "Generating passkey authentication options from Keeper API"
        
        # Create the PasskeyAuthenticationRequest
        $request = [Authentication.PasskeyAuthenticationRequest]::new()
        $request.AuthenticatorAttachment = [Authentication.AuthenticatorAttachment]::Platform
        $request.ClientVersion = $authSync.Endpoint.ClientVersion
        
        # Set username (use provided username or current auth username)
        if ($Username) {
            $request.Username = $Username
        } else {
            $request.Username = $authSync.Username
        }
        
        # Set passkey purpose
        if ($Purpose -eq 'vault') {
            $request.PasskeyPurpose = [Authentication.PasskeyPurpose]::PkReauth
        } else {
            $request.PasskeyPurpose = [Authentication.PasskeyPurpose]::PkLogin
        }
        
        # Add device token if available
        if ($authSync.DeviceToken) {
            $request.EncryptedDeviceToken = [Google.Protobuf.ByteString]::CopyFrom([byte[]]$authSync.DeviceToken)
        }
        
        $requestBytes = [Google.Protobuf.MessageExtensions]::ToByteArray($request)
        $apiRequest = [Authentication.ApiRequestPayload]::new()
        $apiRequest.Payload = [Google.Protobuf.ByteString]::CopyFrom($requestBytes)
        $responseBytes = $authSync.Endpoint.ExecuteRest("authentication/passkey/generate_authentication", $apiRequest).GetAwaiter().GetResult()
        
        $response = [Authentication.PasskeyAuthenticationResponse]::Parser.ParseFrom($responseBytes)
        
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
    similar to the Python biometric client implementation.
    Uses existing Windows Hello credentials to authenticate with a challenge.
    
    .PARAMETER Challenge
    The authentication challenge (byte array, Base64Url string, or ByteString)
    
    .PARAMETER RpId
    The relying party identifier (e.g., "keepersecurity.com")
    
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
        [array]$AllowedCredentials = @(),
        
        [Parameter()]
        [string]$UserVerification = "required",
        
        [Parameter()]
        [int]$TimeoutMs = 60000
    )
    
    if (-not $PowerShellWindowsHelloAvailable) {
        Write-Warning "PowerShellWindowsHello assembly not available. Please build the project first."
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
        
        # Create authentication options object
        $options = [PowerShellWindowsHello.AuthenticationOptions]@{
            RpId = $RpId
            Challenge = $challengeBytes
            TimeoutMs = $TimeoutMs
            UserVerification = $UserVerification
        }
        
        # Convert allowed credentials if provided
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
        
        # Call the Windows Hello authentication
        $result = [PowerShellWindowsHello.WindowsHelloApi]::AuthenticateAsync($options).GetAwaiter().GetResult()
        
        if (-not $result.Success) {
            Write-Warning "Windows Hello authentication failed: $($result.ErrorMessage)"
            return @{
                Success = $false
                ErrorMessage = $result.ErrorMessage
                ErrorType = $result.ErrorType
                HResult = $result.HResult
            }
        }
        
        Write-Host "Windows Hello authentication successful!" -ForegroundColor Green
        
        # Return the assertion result
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
    the authentication process, similar to the Python biometric client implementation.
    
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
        
        [Parameter(Mandatory=$true)]
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
        [object]$AuthSyncObject
    )
    
    try {
        # Get AuthSync instance
        if (-not $AuthSyncObject) {
            if (Get-Command getAuthSync -ErrorAction SilentlyContinue) {
                $authSync = getAuthSync
            } elseif ($Script:Context.AuthSync) {
                $authSync = $Script:Context.AuthSync
            } else {
                throw "No AuthSync instance available. Please connect to Keeper first or provide an AuthSyncObject parameter."
            }
        } else {
            $authSync = $AuthSyncObject
        }
        
        # Create the authentication completion request
        $request = [Authentication.PasskeyValidationRequest]::new()
        
        $request.ChallengeToken = [Google.Protobuf.ByteString]::CopyFrom([byte[]]$ChallengeToken)
    
        # Handle login token - decode using URL-safe Base64 decoding
        if ($LoginToken -is [string]) {
            $loginTokenBase64 = $LoginToken.Replace('-', '+').Replace('_', '/').PadRight(($LoginToken.Length + 3) -band -4, '=')
            $loginTokenBytes = [System.Convert]::FromBase64String($loginTokenBase64)
            $request.EncryptedLoginToken = [Google.Protobuf.ByteString]::CopyFrom($loginTokenBytes)
        } else {
            $request.EncryptedLoginToken = [Google.Protobuf.ByteString]::CopyFrom([byte[]]$LoginToken)
        }
                
        # Convert all assertion data from bytes to Base64Url (matching Python implementation)
        $clientDataBase64Url = ""
        $authenticatorDataBase64Url = ""
        $signatureBase64Url = ""
        
        # Helper function to convert byte array to Base64Url
        function ConvertTo-Base64Url {
            param([byte[]]$Bytes)
            if ($Bytes -is [byte[]]) {
                $base64 = [System.Convert]::ToBase64String($Bytes)
                return $base64.Replace('+', '-').Replace('/', '_').TrimEnd('=')
            }
            return $Bytes
        }
        
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
        
        # Create the assertion response (matching Python format exactly)
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
        
        # Convert to JSON (matching Python json.dumps() behavior)
        $assertionResponseJson = $assertionResponse | ConvertTo-Json -Depth 10 -Compress
        
        # Convert JSON string to UTF-8 bytes for the protobuf property (matching Python: json.dumps().encode('utf-8'))
        $assertionResponseBytes = [System.Text.Encoding]::UTF8.GetBytes($assertionResponseJson)
        $request.AssertionResponse = [Google.Protobuf.ByteString]::CopyFrom($assertionResponseBytes)
 
        # Serialize the request object to bytes using protobuf extension method
        $requestBytes = [Google.Protobuf.MessageExtensions]::ToByteArray($request)
        $apiRequest = [Authentication.ApiRequestPayload]::new()
        $apiRequest.Payload = [Google.Protobuf.ByteString]::CopyFrom($requestBytes)
        $responseBytes = $authSync.Endpoint.ExecuteRest("authentication/passkey/verify_authentication", $apiRequest).GetAwaiter().GetResult()
        
        # Parse the response using protobuf parser
        $response = [Authentication.PasskeyValidationResponse]::Parser.ParseFrom($responseBytes)
                
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

function Invoke-KeeperWindowsHelloAuthentication {
    <#
    .SYNOPSIS
    Complete Windows Hello authentication flow with Keeper
    
    .DESCRIPTION
    This function performs the complete Windows Hello authentication flow:
    1. Gets authentication options from Keeper API
    2. Performs Windows Hello assertion
    3. Completes authentication with Keeper
    
    Based on the Keeper Commander Python biometric client implementation.
    
    .PARAMETER Username
    The username to authenticate (optional - will use current auth username if not provided)
    
    .PARAMETER Purpose
    The purpose of authentication: 'login' (default) or 'vault' (re-authentication)
    
    .PARAMETER AuthSyncObject
    Keeper AuthSync instance (optional - will use global auth if not provided)
    
    .EXAMPLE
    $result = Invoke-KeeperWindowsHelloAuthentication
    if ($result.Success) {
        Write-Host "Authentication successful!"
    }
    
    .EXAMPLE
    $result = Invoke-KeeperWindowsHelloAuthentication -Purpose "vault"
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Username,
        
        [Parameter()]
        [ValidateSet('login', 'vault')]
        [string]$Purpose = 'login',
        
        [Parameter()]
        [object]$AuthSyncObject
    )
    
    try {
        Write-Debug "`nStep 1: Getting authentication options from Keeper..."
        $authOptions = Get-KeeperAuthenticationOptions -Username $Username -Purpose $Purpose -AuthSyncObject $AuthSyncObject
        
        if (-not $authOptions.success) {
            return @{
                Success = $false
                ErrorMessage = "Failed to get authentication options: $($authOptions.error_message)"
                ErrorType = "AuthenticationOptionsError"
            }
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
            return @{
                Success = $false
                ErrorMessage = "No challenge token received from authentication options"
                ErrorType = "AuthenticationOptionsError"
            }
        }
        
        if (-not $rpid) {
            return @{
                Success = $false
                ErrorMessage = "No RP ID received from authentication options"
                ErrorType = "AuthenticationOptionsError"
            }
        }
        
        $assertion = Invoke-WindowsHelloAssertion -Challenge $authOptions.request_options.publicKeyCredentialRequestOptions.challenge -RpId $rpid -AllowedCredentials $allowCredentials -UserVerification $authOptions.userVerification
        
        if (-not $assertion.Success) {
            return @{
                Success = $false
                ErrorMessage = "Windows Hello assertion failed: $($assertion.ErrorMessage)"
                ErrorType = "WindowsHelloAssertionError"
            }
        }
        
        Write-Debug "Windows Hello assertion completed successfully"
        
        # Step 3: Complete authentication with Keeper
        Write-Debug "`nStep 3: Completing authentication with Keeper..."
        $completion = Complete-KeeperAuthentication -ChallengeToken $authOptions.challenge_token -LoginToken $authOptions.login_token -CredentialId $assertion.CredentialId -AuthenticatorData $assertion.AuthenticatorData -ClientDataJSON $assertion.ClientDataJSON -Signature $assertion.Signature -UserHandle $assertion.UserHandle -AuthSyncObject $AuthSyncObject -RpId $rpid -Purpose $Purpose
        
        if (-not $completion.Success) {
            return @{
                Success = $false
                ErrorMessage = "Failed to complete Keeper authentication: $($completion.ErrorMessage)"
                ErrorType = "KeeperAuthenticationError"
            }
        }
        
        Write-Debug "`nAuthentication flow completed successfully!"
        
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
    catch {
        Write-Error "Windows Hello authentication flow failed: $($_.Exception.Message)"
        return @{
            Success = $false
            ErrorMessage = $_.Exception.Message
            ErrorType = $_.Exception.GetType().Name
        }
    }
}

function Register-KeeperCredential {
    <#
    .SYNOPSIS
    Registers a WebAuthn credential with Keeper's servers
    
    .DESCRIPTION
    This function registers a created Windows Hello credential with Keeper's API,
    completing the credential registration flow. This is equivalent to the 
    register_credential function in Keeper's Python implementation.
    
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
        
        # Create the proper WebAuthn authenticator response as stringified JSON (like Python implementation)
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

function Invoke-KeeperCredentialCreation {
    <#
    .SYNOPSIS
    Complete Windows Hello credential creation flow for Keeper with deduplication
    
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
    
    .EXAMPLE
    $result = Invoke-KeeperCredentialCreation
    if ($result.Success) {
        # Credential ready for Keeper registration
        Write-Host "Credential ID: $($result.CredentialId)"
    }
    
    .EXAMPLE
    # Force creation of new credential even if duplicates exist
    $result = Invoke-KeeperCredentialCreation -Force
    
    .EXAMPLE
    # Create credential with custom friendly name
    $result = Invoke-KeeperCredentialCreation -FriendlyName "My Work Laptop"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [object]$Vault,
        
        [Parameter(Mandatory=$false)]
        [switch]$Force,
        
        [Parameter(Mandatory=$false)]
        [string]$FriendlyName
    )
    
    try {
        Write-Host "Windows Hello Credential Creation for Keeper" -ForegroundColor Yellow
        
        $regOptions = Get-KeeperRegistrationOptions -Vault $Vault
        $displayName = $null
        if ($FriendlyName) {
            $displayName = $FriendlyName
        } elseif ($friendly_name) {
            $displayName = $friendly_name
        } else {
            $displayName = $regOptions.user_display_name
        }

        $rpId = $regOptions.rp_id
        $username = $regOptions.user_name
        $excludeCredentials = $regOptions.creation_options.excludeCredentials
        if ($excludeCredentials -isnot [array]) {
            $excludeCredentials = @($excludeCredentials)
        } 
        $excludeCredentialsJson = $excludeCredentials | ConvertTo-Json -Depth 10
        
        # Convert exclude credentials to the format expected by C# method
        $excludeCredentialObjects = @()
        if ($excludeCredentials -and $excludeCredentials.Count -gt 0) {
            for ($i = 0; $i -lt $excludeCredentials.Count; $i++) {
                $excludeCred = $excludeCredentials[$i]
                
                $credObj = New-Object PowerShellWindowsHello.ExcludeCredential
                $credObj.Type = $excludeCred.type
                $credObj.Id = $excludeCred.id
                $credObj.Transports = $excludeCred.transports
                $excludeCredentialObjects += $credObj
            }
        }
        
        # Check if user already has a credential ID stored
        $existingCredentialId = Get-WindowsHelloCredentialId -Username $username
        
        # Check for matches between stored credential ID and excludeCredentials
        $matchedCredential = $null
        if ($existingCredentialId -and $excludeCredentials.Count -gt 0 -and -not $Force) {
            foreach ($excludeCred in $excludeCredentials) {
                $excludeCredId = $excludeCred.id
                
                # Compare the full credential IDs
                if ($existingCredentialId -eq $excludeCredId) {
                    $matchedCredential = @{
                        Username = $username
                        CredentialId = $existingCredentialId
                    }
                    break
                }
            }
        }
        
        # Handle matched credential from registry vs excludeCredentials
        if ($matchedCredential) {
            Write-Host "Found matching credential in registry that's also in excludeCredentials!" -ForegroundColor Yellow
            Write-Host "Registration cancelled as a matching credential was found in registry use biometric verify instead to just use the existing credential and login with the existing credential." -ForegroundColor Red
            return $false
        } 
        $credResult = Invoke-WindowsHelloCredentialCreation `
            -Challenge $regOptions.challenge `
            -RpId $regOptions.rp_id `
            -RpName $regOptions.rp_name `
            -UserId $regOptions.user_id `
            -UserName $regOptions.user_name `
            -UserDisplayName $displayName `
            -ExcludeCredentials $excludeCredentialObjects

        if ($credResult.Success) {
            Write-Host " Windows Hello credential creation completed!" -ForegroundColor Green
            $registerResult = Register-KeeperCredential -ChallengeToken $regOptions.challenge_token -CredentialId $credResult.CredentialId -AttestationObject $credResult.AttestationObject -ClientDataJSON $credResult.ClientDataJSON -Vault $Vault
            if ($registerResult.Success) {
                $credentialId = $credResult.CredentialId
                $rpId = $regOptions.rp_id
                $username = $regOptions.user_name
                
                # Store the credential ID for this user
                $storeResult = Set-WindowsHelloCredentialId -Username $username -CredentialId $credentialId
                if ($storeResult) {
                    Write-Host "Credential ID stored for user: $username" -ForegroundColor Green
                } else {
                    Write-Warning "Failed to store credential ID for user: $username"
                }
            } else {
                Write-Host " Windows Hello credential creation failed: $($credResult.ErrorMessage)" -ForegroundColor Red
            }
        } else {
            return @{
                Success = $false
                Error = $credResult.ErrorMessage
                ErrorType = $credResult.ErrorType
                Timestamp = $credResult.Timestamp
            }
        }
    }
    catch {
        Write-Error "Keeper credential creation failed: $($_.Exception.Message)"
        return @{
            Success = $false
            Error = $_.Exception.Message
            ErrorType = $_.Exception.GetType().Name
            Timestamp = [DateTime]::UtcNow
        }
    }
}

# These functions are only available on Windows platforms
if ($IsWindows -or $PSVersionTable.PSVersion.Major -lt 6) {
    # Define registry path for Windows Hello credentials
    $script:WindowsHelloRegistryPath = "HKCU:\Software\Keeper Security\Commander\Biometric" # replace with  Computer\HKEY_CURRENT_USER\Software\Keeper Security\Commander\Biometric
    
    function Register-WindowsHelloCredential {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory=$true)]
            [string]$Username,
            
            [Parameter(Mandatory=$true)]
            [string]$RpId,
            
            [Parameter(Mandatory=$true)]
            [string]$CredentialId,
            
            [Parameter()]
            [bool]$BiometricsEnabled = $true
        )
        
        try {
            # Create a safe key name: username_rpid_credentialId (first 20 chars of credentialId)
            $safeUsername = $Username -replace '@', '_' -replace '\\', '_' -replace '/', '_'
            $safeRpId = $RpId -replace '\.', '_'
            $shortCredId = $CredentialId.Substring(0, [Math]::Min(20, $CredentialId.Length))
            $keyName = "${safeUsername}___${safeRpId}___${shortCredId}"
            
            # Ensure the registry path exists
            if (-not (Test-Path $script:WindowsHelloRegistryPath)) {
                New-Item -Path $script:WindowsHelloRegistryPath -Force | Out-Null
            }
            
            # Set the credential info
            $regValue = if ($BiometricsEnabled) { 1 } else { 0 }
            New-ItemProperty -Path $script:WindowsHelloRegistryPath -Name $keyName -Value $regValue -PropertyType DWord -Force | Out-Null
            
            Write-Host "Successfully registered credential for $Username@$RpId" -ForegroundColor Green
            Write-Verbose "Registry key: $keyName = $regValue"
            return $true
        }
        catch {
            Write-Error "Failed to register credential: $($_.Exception.Message)"
            return $false
        }
    }
    
    function Unregister-WindowsHelloCredential {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory=$true)]
            [string]$Username,
            
            [Parameter(Mandatory=$true)]
            [string]$RpId,
            
            [Parameter(Mandatory=$true)]
            [string]$CredentialId
        )
        
        try {
            # Create the same key name as registration
            $safeUsername = $Username -replace '@', '_' -replace '\\', '_' -replace '/', '_'
            $safeRpId = $RpId -replace '\.', '_'
            $shortCredId = $CredentialId.Substring(0, [Math]::Min(20, $CredentialId.Length))
            $keyName = "${safeUsername}___${safeRpId}___${shortCredId}"
            
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
    
    function Get-WindowsHelloRegisteredCredentials {
        [CmdletBinding()]
        param(
            [Parameter()]
            [string]$Username,
            
            [Parameter()]
            [string]$RpId
        )
        
        try {
            $credentials = @()
            
            if (Test-Path $script:WindowsHelloRegistryPath) {
                $properties = Get-ItemProperty -Path $script:WindowsHelloRegistryPath
                
                foreach ($prop in $properties.PSObject.Properties) {
                    if ($prop.Name -notlike "PS*") {
                        $keyName = $prop.Name
                        $keyParts = $keyName -split '___'
                        if ($keyParts.Length -eq 3) {
                            # Simple parsing with ___ separators
                            $usernamePart = $keyParts[0].replace('_', '')
                            $rpIdPart = $keyParts[1]
                            $credentialIdPart = $keyParts[2]
                            $biometricsEnabled = $prop.Value -eq 1
                            
                            # Clean up username for comparison
                            $cleanUsername = $Username -replace '@', '' -replace '_', ''
                            $cleanUsernamePart = $usernamePart -replace '_', ''
                            $cleanRpId = $RpId -replace '_', '.'

                            # Apply filters if specified
                            if ((!$Username -or $cleanUsernamePart -like "*$cleanUsername*") -and
                                (!$RpId -or $rpId -like "*$cleanRpId*")) {
                                
                                $credentials += [PSCustomObject]@{
                                    Username = $usernamePart
                                    RpId = $rpIdPart
                                    CredentialId = $credentialIdPart
                                    BiometricsEnabled = $biometricsEnabled
                                    RegistryKey = $prop.Name
                                }                                
                            }
                        }
                    }
                }
            }
            
            return ,$credentials
        }
        catch {
            Write-Error "Failed to get registered credentials: $($_.Exception.Message)"
            return @()
        }
    }
    
    function Clear-AllWindowsHelloCredentials {
        [CmdletBinding()]
        param()
        
        try {
            if (Test-Path $script:WindowsHelloRegistryPath) {
                Remove-Item -Path $script:WindowsHelloRegistryPath -Recurse -Force
                Write-Host "Successfully cleared all registered credentials" -ForegroundColor Green
            } else {
                Write-Host "No credentials found to clear" -ForegroundColor Yellow
            }
            return $true
        }
        catch {
            Write-Error "Failed to clear registered credentials: $($_.Exception.Message)"
            return $false
        }
    }
    
    function Get-WindowsHelloCredentialId {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $true)]
            [string]$Username
        )
        
        try {
            if (Test-Path $script:WindowsHelloRegistryPath) {
                # Get the credential ID value for the username key
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
        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $true)]
            [string]$Username,
            
            [Parameter(Mandatory = $false)]
            [string]$CredentialId
        )
        
        try {
            # Ensure registry path exists
            if (!(Test-Path $script:WindowsHelloRegistryPath)) {
                New-Item -Path $script:WindowsHelloRegistryPath -Force | Out-Null
            }
            
            if ($CredentialId) {
                # Store the credential ID for the username
                Set-ItemProperty -Path $script:WindowsHelloRegistryPath -Name $Username -Value $CredentialId -Type String
            } else {
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
        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $true)]
            [string]$Username
        )
        
        try {
            if (Test-Path $script:WindowsHelloRegistryPath) {
                # Check if the credential key exists for the username
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
} # End of Windows conditional compilation

$exportFunctions = @(
    "Test-WindowsHelloCapabilities","Invoke-KeeperWindowsHelloAuthentication","Invoke-KeeperCredentialCreation"
)

Export-ModuleMember -Function $exportFunctions

#endregion
