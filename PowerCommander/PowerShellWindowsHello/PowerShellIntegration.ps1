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
    It works with both Vault and AuthSync objects, automatically detecting which one is provided.
    Based on the Python generate_authentication_options function.
    
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
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 'AllowedCredentials', Justification='Credential IDs are public identifiers, not sensitive data')]
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
            Write-Warning "Windows Hello Assertion failed: $($result.ErrorMessage)"
            return @{
                Success = $false
                ErrorMessage = $result.ErrorMessage
                ErrorType = $result.ErrorType
                HResult = $result.HResult
            }
        }
                
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
    
    .PARAMETER Vault
    Keeper Vault instance (optional - will use global vault if not provided)
    
    .PARAMETER PassThru
    Return the authentication result object. If not specified, function returns nothing.
    
    .EXAMPLE
    Invoke-KeeperWindowsHelloAuthentication
    # Performs authentication without returning a result object
    
    .EXAMPLE
    $result = Invoke-KeeperWindowsHelloAuthentication -PassThru
    if ($result.Success) {
        Write-Host "Authentication successful!"
    }
    
    .EXAMPLE
    $result = Invoke-KeeperWindowsHelloAuthentication -Purpose "vault" -PassThru
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
                    ErrorMessage = "Failed to complete Keeper authentication: $($completion.ErrorMessage)"
                    ErrorType = "KeeperAuthenticationError"
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
    Based on the Python disable_passkey function.
    
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
        # Create the UpdatePasskeyRequest
        $request = [Authentication.UpdatePasskeyRequest]::new()
        $request.UserId = $UserId
        # Convert credential ID to bytes if it's Base64Url encoded
        $credentialIdBytes = $null
        if ($CredentialId -match '^[A-Za-z0-9_-]+$') {
            # Base64Url decode
            $base64 = $CredentialId.Replace('-', '+').Replace('_', '/')
            while ($base64.Length % 4 -ne 0) { $base64 += '=' }
            $credentialIdBytes = [Convert]::FromBase64String($base64)
        } else {
            # Assume it's already bytes or convert from string
            $credentialIdBytes = [System.Text.Encoding]::UTF8.GetBytes($CredentialId)
        }
        
        $request.CredentialId = [Google.Protobuf.ByteString]::CopyFrom($credentialIdBytes)
        # Execute the API call
        $response = $auth.ExecuteAuthRest("authentication/passkey/disable", $request).GetAwaiter().GetResult()
        return @{
            Success = $true
            Message = "Passkey disabled successfully"
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

function Remove-KeeperBiometricCredentials {
    <#
    .SYNOPSIS
    Remove/disable biometric credentials from Keeper
    
    .DESCRIPTION
    This function removes or disables biometric credentials (passkeys) from the Keeper account.
    It can remove specific credentials by ID or disable all biometric authentication for the user.
    
    .PARAMETER CredentialId
    Specific credential ID to remove (optional - if not provided, disables all biometric auth)
    
    .PARAMETER Username
    Username to disable biometric auth for (optional - uses current user if not provided)
    
    .PARAMETER Confirm
    Skip confirmation prompt (default: false)
    
    .PARAMETER Vault
    Keeper vault instance (optional - will use global vault if not provided)
    
    .EXAMPLE
    # Disable all biometric authentication for current user
    Remove-KeeperBiometricCredentials
    
    .EXAMPLE
    # Remove specific credential
    Remove-KeeperBiometricCredentials -CredentialId "abc123def456"
    
    .EXAMPLE
    # Disable for specific user without confirmation
    Remove-KeeperBiometricCredentials -Username "user@company.com" -Confirm
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory=$false)]
        [string]$CredentialId,
        
        [Parameter(Mandatory=$false)]
        [string]$Username,
        
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
        
        if (-not $Username) {
            $Username = $auth.Username
        }
        
        $hasBiometric = Test-WindowsHelloBiometricPreviouslyUsed -Username $Username
        if (-not $hasBiometric) {
            Write-Verbose "Biometric authentication is already disabled for user '$Username'." -ForegroundColor Yellow
            return @{
                Success = $true
                Message = "Biometric authentication already disabled"
            }
        }
        
        # Confirmation prompt
        if (-not $PSCmdlet.ShouldProcess("Remove biometric credentials for user '$Username'", "Remove", "Are you sure you want to remove biometric authentication?")) {
            return @{
                Success = $false
                Message = "Operation cancelled by user"
            }
        }
        
        # Get RP ID from server (assuming keepersecurity.com)
        $rpId = "keepersecurity.com"
        
        # Disable server passkeys - following Python pattern
        Write-Host "Disabling server passkeys..." -ForegroundColor Yellow
        $disableResult = $true
        
        # Get stored credential ID from registry
        $storedCredentialId = Get-WindowsHelloCredentialId -Username $Username
        if ($storedCredentialId) {
            
            try {
                # Get all available credentials (following Python pattern)
                $availableCredentials = Get-KeeperAvailableBiometricCredentials -Vault $vault
                
                # Find the target passkey by credential ID
                $targetPasskey = $null
                foreach ($credential in $availableCredentials) {
                    $credentialId = $credential.CredentialId
                    
                    # Compare credential IDs (handle both string and byte array formats)
                    if ($credentialId -eq $storedCredentialId) {
                        $targetPasskey = $credential
                        break
                    }
                }
                
                if ($targetPasskey) {
                    # Call server API to disable the passkey using the credential's user ID and credential ID
                    try {
                        $disableResult = Disable-KeeperPasskey -Vault $vault -UserId $targetPasskey.Id -CredentialId $targetPasskey.CredentialId
                        if ($disableResult.Success) {
                            Write-Host "Successfully disabled passkey on server" -ForegroundColor Green
                        } else {
                            Write-Warning "Failed to disable passkey on server: $($disableResult.ErrorMessage)"
                            $disableResult = $false
                        }
                    } catch {
                        Write-Warning "Error calling server API to disable passkey: $($_.Exception.Message)"
                        $disableResult = $false
                    }
                } else {
                    Write-Host "Stored credential ID not found in available credentials - may already be disabled" -ForegroundColor Yellow
                }
            } catch {
                Write-Warning "Failed to get available credentials: $($_.Exception.Message)"
                $disableResult = $false
            }
        } else {
            Write-Host "No stored credential ID found for user" -ForegroundColor Yellow
        }

        $cleanupSuccess = $true
        if ($CredentialId) {
            $cleanupSuccess = Unregister-WindowsHelloCredential -Username $Username -RpId $rpId -CredentialId $CredentialId
        }
        
        # Verify cleanup
        $verificationSuccess = -not (Test-WindowsHelloBiometricPreviouslyUsed -Username $Username)
        
        if ($cleanupSuccess -and $verificationSuccess) {
            return @{
                Success = $true
                Message = "Biometric credentials removed successfully"
                Username = $Username
                CredentialId = $CredentialId
            }
        } else {
            return @{
                Success = $false
                Message = "Biometric credential removal may have failed"
                Username = $Username
                CredentialId = $CredentialId
            }
        }
    }
    catch {
        Write-Error "Failed to remove biometric credentials: $($_.Exception.Message)"
        return @{
            Success = $false
            ErrorMessage = $_.Exception.Message
            ErrorType = $_.Exception.GetType().Name
        }
    }
}

function Show-KeeperBiometricCredentials {
    <#
    .SYNOPSIS
    Display biometric credentials in a formatted table
    
    .DESCRIPTION
    This function retrieves and displays all registered biometric credentials (passkeys) 
    in a formatted table, similar to the Python _display_credentials function.
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
        # Get the credentials
        $credentials = Get-KeeperAvailableBiometricCredentials -Vault $Vault -IncludeDisabled:$IncludeDisabled
        
        if (-not $credentials -or $credentials.Count -eq 0) {
            Write-Host "No biometric authentication methods found." -ForegroundColor Yellow
            return
        }
        
        Write-Host "`nRegistered Biometric Authentication Methods:" -ForegroundColor Green
        Write-Host ("-" * 70) -ForegroundColor Gray
        
        foreach ($credential in $credentials) {
            # Format timestamps
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
            
            # Use friendly name, fallback to AAGUID mapping if name is empty
            $displayName = $credential.Name
            if ([string]::IsNullOrWhiteSpace($displayName)) {
                $aaguid = $credential.AAGUID
                if ($aaguid) {
                    $displayName = Get-ProviderNameFromAAGUID -AAGUID $aaguid
                } else {
                    $displayName = "Unknown Provider"
                }
            }
            
            # Show disabled status if applicable
            if ($credential.Disabled) {
                $displayName += " (DISABLED)"
            }
            # Convert ByteString to readable format for display
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

        $username = $regOptions.user_name
        $excludeCredentials = $regOptions.creation_options.excludeCredentials
        if ($excludeCredentials -isnot [array]) {
            $excludeCredentials = @($excludeCredentials)
        } 
        
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
    $script:WindowsHelloRegistryPath = "HKCU:\Software\Keeper Security\Commander\Biometric"
    
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
    "Test-WindowsHelloCapabilities","Invoke-KeeperWindowsHelloAuthentication","Invoke-KeeperCredentialCreation","Show-KeeperBiometricCredentials","Remove-KeeperBiometricCredentials"
)

Export-ModuleMember -Function $exportFunctions

#endregion
