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
        
        if (-not $Quiet) {
            # Display formatted information
            Write-Host "Windows Hello Capabilities Report" -ForegroundColor Yellow
            Write-Host "══════════════════════════════════" -ForegroundColor Yellow
            Write-Host ""
            
            # Status
            Write-Host "Status: " -NoNewline -ForegroundColor Cyan
            Write-Host $capabilities.WindowsHello.Status -ForegroundColor $(if ($capabilities.WindowsHello.Available) { "Green" } else { "Red" })
            
            if ($capabilities.WindowsHello.Available) {
                Write-Host "API Version: " -NoNewline -ForegroundColor Cyan
                Write-Host $capabilities.WindowsHello.ApiVersion -ForegroundColor White
                
                Write-Host "Platform: " -NoNewline -ForegroundColor Cyan
                Write-Host $capabilities.WindowsHello.Platform -ForegroundColor White
                
                Write-Host "Supported Methods: " -NoNewline -ForegroundColor Cyan
                Write-Host ($capabilities.WindowsHello.Methods -join ", ") -ForegroundColor White
                
                Write-Host ""
                Write-Host "PowerShell Integration:" -ForegroundColor Yellow
                Write-Host "  Can Create Credentials: " -NoNewline -ForegroundColor Cyan
                Write-Host $capabilities.PowerShellIntegration.CanCreateCredentials -ForegroundColor $(if ($capabilities.PowerShellIntegration.CanCreateCredentials) { "Green" } else { "Yellow" })
                
                Write-Host "  Can Authenticate: " -NoNewline -ForegroundColor Cyan
                Write-Host $capabilities.PowerShellIntegration.CanAuthenticate -ForegroundColor $(if ($capabilities.PowerShellIntegration.CanAuthenticate) { "Green" } else { "Yellow" })
                
                Write-Host "  Recommended Command: " -NoNewline -ForegroundColor Cyan
                Write-Host $capabilities.PowerShellIntegration.RecommendedCommand -ForegroundColor Magenta
                
                Write-Host ""
                Write-Host "System Information:" -ForegroundColor Yellow
                Write-Host "  WebAuthn DLL: " -NoNewline -ForegroundColor Cyan
                Write-Host $capabilities.PowerShellIntegration.WebAuthnDllStatus -ForegroundColor White
                
                Write-Host "  Production Ready: " -NoNewline -ForegroundColor Cyan
                Write-Host $capabilities.SystemInfo.ProductionReady -ForegroundColor $(if ($capabilities.SystemInfo.ProductionReady) { "Green" } else { "Yellow" })
                
                Write-Host "  Runtime Version: " -NoNewline -ForegroundColor Cyan
                Write-Host $capabilities.SystemInfo.RuntimeVersion -ForegroundColor White
                
                Write-Host "  64-bit Process: " -NoNewline -ForegroundColor Cyan
                Write-Host $capabilities.SystemInfo.Is64BitProcess -ForegroundColor White
                
                Write-Host "  Last Checked: " -NoNewline -ForegroundColor Cyan
                Write-Host $capabilities.WindowsHello.LastChecked -ForegroundColor White
            } else {
                Write-Host "Error: " -NoNewline -ForegroundColor Red
                Write-Host $capabilities.WindowsHello.Error -ForegroundColor White
                
                Write-Host "WebAuthn DLL Status: " -NoNewline -ForegroundColor Cyan
                Write-Host $capabilities.PowerShellIntegration.WebAuthnDllStatus -ForegroundColor White
            }
        }
        
        if ($PassThru) {
            return $capabilities
        }
        else {
            return $capabilities.WindowsHello.Available
        }
    }
    catch {
        if (-not $Quiet) {
            Write-Error "Failed to check Windows Hello capabilities: $($_.Exception.Message)"
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
        Write-Host " Starting Windows Hello Authentication" -ForegroundColor Green
        Write-Host "Relying Party: $RpId" -ForegroundColor Cyan
        Write-Host "Challenge Length: $($Challenge.Length) bytes" -ForegroundColor Cyan
        Write-Host "Timeout: $($TimeoutMs / 1000) seconds" -ForegroundColor Cyan
        Write-Host ""
        
        # Create authentication options
        $authOptions = New-Object PowerShellWindowsHello.AuthenticationOptions
        $authOptions.Challenge = $Challenge
        $authOptions.RpId = $RpId
        $authOptions.AllowedCredentialIds = $AllowedCredentials
        $authOptions.TimeoutMs = $TimeoutMs
        $authOptions.UserVerification = $UserVerification
        
        Write-Host "Please complete Windows Hello verification when prompted..." -ForegroundColor Yellow
        
        # Perform authentication
        $task = [PowerShellWindowsHello.WindowsHelloApi]::AuthenticateAsync($authOptions)
        $result = $task.GetAwaiter().GetResult()
        
        if ($result.Success) {
            Write-Host " Windows Hello authentication successful!" -ForegroundColor Green
            Write-Host "Credential ID: $($result.CredentialId.Substring(0, [Math]::Min(16, $result.CredentialId.Length)))..." -ForegroundColor Cyan
            Write-Host "Method: $($result.Method)" -ForegroundColor Cyan
            Write-Host "Timestamp: $($result.Timestamp)" -ForegroundColor Cyan
        } else {
            Write-Host " Windows Hello authentication failed" -ForegroundColor Red
            Write-Host "Error: $($result.ErrorMessage)" -ForegroundColor Red
            Write-Host "Error Type: $($result.ErrorType)" -ForegroundColor Red
        }
        
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
        [string]$AuthenticatorAttachment = "platform"
    )
    
    if (-not $PowerShellWindowsHelloAvailable) {
        throw "PowerShellWindowsHello assembly not available. Please build the project first."
    }
    
    try {
        Write-Host " Starting Windows Hello Credential Creation" -ForegroundColor Green
        Write-Host "Relying Party: $RpId" -ForegroundColor Cyan
        Write-Host "Username: $UserName" -ForegroundColor Cyan
        Write-Host "Challenge Length: $($Challenge.Length) bytes" -ForegroundColor Cyan
        Write-Host "Timeout: $($TimeoutMs / 1000) seconds" -ForegroundColor Cyan
        Write-Host ""
        
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
        $task = [PowerShellWindowsHello.WindowsHelloApi]::CreateCredentialAsync($regOptions)
        $result = $task.GetAwaiter().GetResult()
        
        if ($result.Success) {
            Write-Host " Windows Hello credential created successfully!" -ForegroundColor Green
            Write-Host "Credential ID: $($result.CredentialId.Substring(0, [Math]::Min(16, $result.CredentialId.Length)))..." -ForegroundColor Cyan
            Write-Host "Method: $($result.Method)" -ForegroundColor Cyan
            Write-Host "Timestamp: $($result.Timestamp)" -ForegroundColor Cyan
        } else {
            Write-Host " Windows Hello credential creation failed" -ForegroundColor Red
            Write-Host "Error: $($result.ErrorMessage)" -ForegroundColor Red
            Write-Host "Error Type: $($result.ErrorType)" -ForegroundColor Red
        }
        
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
        Write-Verbose "Generating passkey registration options from Keeper API"
        
        $request = [Authentication.PasskeyRegistrationRequest]::new()
        $request.AuthenticatorAttachment = [Authentication.AuthenticatorAttachment]::Platform
        
        $response = $auth.ExecuteAuthRest("authentication/passkey/generate_registration", $request, [Authentication.PasskeyRegistrationResponse]).GetAwaiter().GetResult()
        
        $creationOptions = $response.PkCreationOptions | ConvertFrom-Json
        
        # Debug the challenge token type and value
        Write-Host "=== DEBUGGING CHALLENGE TOKEN ===" -ForegroundColor Yellow
        Write-Host "response for registration options : $($response)" -ForegroundColor Cyan
        
        # Try to get the actual byte array from the ByteString
        $challengeTokenBytes = $null
        if ($response.ChallengeToken -is [Google.Protobuf.ByteString]) {
            Write-Host "ChallengeToken is ByteString - converting to byte array" -ForegroundColor Green
            $challengeTokenBytes = $response.ChallengeToken.ToByteArray()
        } elseif ($response.ChallengeToken -is [byte[]]) {
            Write-Host "ChallengeToken is already byte array" -ForegroundColor Green
            $challengeTokenBytes = $response.ChallengeToken
        } else {
            Write-Host "ChallengeToken is unexpected type, trying ToString then parse" -ForegroundColor Red
            $challengeTokenBytes = $response.ChallengeToken
        }
        
        Write-Host "Processed ChallengeToken Type: $($challengeTokenBytes.GetType().FullName)" -ForegroundColor Cyan
        Write-Host "Processed ChallengeToken Length: $($challengeTokenBytes.Length)" -ForegroundColor Cyan

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
        
        Write-Host "Registration Options Retrieved:" -ForegroundColor Green
        Write-Host "  Challenge Token Type: $($result.challenge_token.GetType().FullName)" -ForegroundColor Cyan
        Write-Host "  Challenge Token Length: $($result.challenge_token.Length)" -ForegroundColor Cyan
        Write-Host "  RP ID: $($result.rp_id)" -ForegroundColor Cyan
        Write-Host "  User: $($result.user_name)" -ForegroundColor Cyan
        
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
    
    Write-Host "=== DEBUGGING ConvertTo-ByteString ===" -ForegroundColor Yellow
    Write-Host "Input Type: $($InputData.GetType().FullName)" -ForegroundColor Cyan
    Write-Host "Input Value: $InputData" -ForegroundColor Cyan
    
    if ($null -eq $InputData) {
        Write-Host "Input is null, returning null" -ForegroundColor Red
        return $null
    }
    
    # Handle different input types
    if ($InputData -is [Google.Protobuf.ByteString]) {
        Write-Host "Input is already ByteString, returning as-is" -ForegroundColor Green
        return $InputData
    }
    elseif ($InputData -is [byte[]]) {
        Write-Host "Input is byte array, converting to ByteString" -ForegroundColor Green
        return [Google.Protobuf.ByteString]::CopyFrom($InputData)
    }
    elseif ($InputData -is [string]) {
        Write-Host "Input is string, attempting to parse as byte array" -ForegroundColor Yellow
        try {
            # Try to parse string like "1 2 3 4" into byte array
            $bytes = $InputData -split '\s+' | ForEach-Object { [byte]$_ }
            Write-Host "Successfully parsed string to $($bytes.Length) bytes" -ForegroundColor Green
            return [Google.Protobuf.ByteString]::CopyFrom([byte[]]$bytes)
        }
        catch {
            Write-Host "Failed to parse string as bytes: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }
    else {
        Write-Host "Unexpected input type, trying direct conversion" -ForegroundColor Red
        try {
            return [Google.Protobuf.ByteString]::CopyFrom($InputData)
        }
        catch {
            Write-Host "Direct conversion failed: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }
}

function Utf8BytesToString {
    param($InputData)
    
    Write-Host "=== DEBUGGING Utf8BytesToString ===" -ForegroundColor Yellow
    Write-Host "Input Type: $($InputData.GetType().FullName)" -ForegroundColor Cyan
    Write-Host "Input Value (first 100 chars): $($InputData.ToString().Substring(0, [Math]::Min(100, $InputData.ToString().Length)))" -ForegroundColor Cyan
    
    if ($null -eq $InputData) {
        Write-Host "Input is null, returning null" -ForegroundColor Red
        return $null
    }
    
    try {
        # Handle different input types
        if ($InputData -is [Google.Protobuf.ByteString]) {
            Write-Host "Input is ByteString, converting to byte array then UTF-8 string" -ForegroundColor Green
            $bytes = $InputData.ToByteArray()
            $result = [System.Text.Encoding]::UTF8.GetString($bytes)
            Write-Host "Converted to UTF-8 string: $($result.Substring(0, [Math]::Min(50, $result.Length)))..." -ForegroundColor Green
            return $result
        }
        elseif ($InputData -is [byte[]]) {
            Write-Host "Input is byte array, converting to UTF-8 string" -ForegroundColor Green
            $result = [System.Text.Encoding]::UTF8.GetString($InputData)
            Write-Host "Converted to UTF-8 string: $($result.Substring(0, [Math]::Min(50, $result.Length)))..." -ForegroundColor Green
            return $result
        }
        elseif ($InputData -is [string]) {
            Write-Host "Input is already string, attempting to parse as space-separated bytes first" -ForegroundColor Yellow
            try {
                # Try to parse string like "1 2 3 4" into byte array, then to UTF-8 string
                $bytes = $InputData -split '\s+' | ForEach-Object { [byte]$_ }
                $result = [System.Text.Encoding]::UTF8.GetString([byte[]]$bytes)
                Write-Host "Successfully parsed space-separated bytes to UTF-8 string: $($result.Substring(0, [Math]::Min(50, $result.Length)))..." -ForegroundColor Green
                return $result
            }
            catch {
                Write-Host "Failed to parse as space-separated bytes, returning original string" -ForegroundColor Yellow
                return $InputData
            }
        }
        else {
            Write-Host "Unexpected input type, trying direct ToString()" -ForegroundColor Yellow
            return $InputData.ToString()
        }
    }
    catch {
        Write-Host "Conversion failed: $($_.Exception.Message)" -ForegroundColor Red
        throw
    }
}

function Debug-AttestationObject {
    param([string]$Base64AttestationObject)
    
    if ([string]::IsNullOrEmpty($Base64AttestationObject)) {
        Write-Host "AttestationObject is null or empty" -ForegroundColor Red
        return
    }
    
    try {
        Write-Host "=== DEBUGGING ATTESTATION OBJECT ===" -ForegroundColor Yellow
        Write-Host "Base64 Length: $($Base64AttestationObject.Length)" -ForegroundColor Cyan
        Write-Host "Base64 (first 100 chars): $($Base64AttestationObject.Substring(0, [Math]::Min(100, $Base64AttestationObject.Length)))..." -ForegroundColor Cyan
        
        # Decode base64 to bytes (handle both base64 and base64url)
        $base64 = $Base64AttestationObject.Replace('-', '+').Replace('_', '/')
        # Add padding if needed
        switch ($base64.Length % 4) {
            2 { $base64 += '==' }
            3 { $base64 += '=' }
        }
        
        $attestationBytes = [Convert]::FromBase64String($base64)
        Write-Host "Decoded Bytes Length: $($attestationBytes.Length)" -ForegroundColor Green
        
        # Show first few bytes (CBOR data typically starts with specific patterns)
        $hexBytes = ($attestationBytes[0..([Math]::Min(20, $attestationBytes.Length-1))] | ForEach-Object { $_.ToString("X2") }) -join " "
        Write-Host "First 20 bytes (hex): $hexBytes" -ForegroundColor Cyan
        
        # Try to identify CBOR structure patterns
        if ($attestationBytes.Length -gt 0) {
            $firstByte = $attestationBytes[0]
            Write-Host "First Byte: 0x$($firstByte.ToString('X2')) ($firstByte)" -ForegroundColor Cyan
            
            # CBOR map detection (major type 5)
            if (($firstByte -band 0xE0) -eq 0xA0) {
                $mapSize = $firstByte -band 0x1F
                Write-Host "  -> CBOR Map detected with $mapSize items" -ForegroundColor Green
            }
            # CBOR text string (major type 3)
            elseif (($firstByte -band 0xE0) -eq 0x60) {
                Write-Host "  -> CBOR Text String detected" -ForegroundColor Green
            }
            # CBOR byte string (major type 2)
            elseif (($firstByte -band 0xE0) -eq 0x40) {
                Write-Host "  -> CBOR Byte String detected" -ForegroundColor Green
            }
            else {
                Write-Host "  -> CBOR type: Major type $(($firstByte -shr 5) -band 0x07)" -ForegroundColor White
            }
        }
        
        # Try to find readable strings in the data (for debugging)
        $attestationString = [System.Text.Encoding]::UTF8.GetString($attestationBytes)
        $readableChars = ($attestationString.ToCharArray() | Where-Object { $_ -ge 32 -and $_ -le 126 }) -join ""
        if ($readableChars.Length -gt 10) {
            Write-Host "Readable strings found: $($readableChars.Substring(0, [Math]::Min(100, $readableChars.Length)))..." -ForegroundColor Magenta
        }
        
        Write-Host "=========================================" -ForegroundColor Yellow
    }
    catch {
        Write-Host "Error decoding attestation object: $($_.Exception.Message)" -ForegroundColor Red
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
    
    .PARAMETER Vault
    Keeper vault instance (optional - will use global vault if not provided)
    
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
        Write-Verbose "Generating passkey authentication options from Keeper API"
        
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
            Write-Verbose "Adding device token to authentication request"
            $request.EncryptedDeviceToken = [Google.Protobuf.ByteString]::CopyFrom([byte[]]$auth.DeviceToken)
        }
        
        # Execute the REST API call
        $response = $auth.ExecuteAuthRest("authentication/passkey/generate_authentication", $request, [Authentication.PasskeyAuthenticationResponse]).GetAwaiter().GetResult()
        
        # Parse the request options JSON
        $requestOptions = $response.PkRequestOptions | ConvertFrom-Json
        
        # Return structured result
        $result = @{
            challenge_token = $response.ChallengeToken
            request_options = $requestOptions
            login_token = $response.EncryptedLoginToken
            purpose = $Purpose
            username = $request.Username
            success = $true
            
            # Add convenience properties for PowerShell usage
            challenge = $requestOptions.challenge
            allowCredentials = $requestOptions.allowCredentials
            timeout = $requestOptions.timeout
            userVerification = $requestOptions.userVerification
            rpId = $requestOptions.rpId
            
            # Note: Actual structure for rpId extraction is:
            # $result.request_options.publicKeyCredentialRequestOptions.rpId
        }
        
        Write-Verbose "Successfully generated authentication options for user: $($request.Username)"
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
        Write-Verbose "Starting Windows Hello assertion for RP: $RpId"
        
        # Handle challenge input - can be byte array, Base64Url string, or ByteString
        $challengeBytes = $null
        Write-Verbose "Challenge type: $($Challenge.GetType().FullName)"
        Write-Verbose "Challenge value: $Challenge"
        
        if ($Challenge -is [byte[]]) {
            Write-Verbose "Challenge is byte array"
            $challengeBytes = $Challenge
        }
        elseif ($Challenge -is [string]) {
            Write-Verbose "Challenge is string, converting from Base64Url"
            # Convert from Base64Url to bytes
            $challengeBytes = [System.Convert]::FromBase64String($Challenge.Replace('-', '+').Replace('_', '/').PadRight(($Challenge.Length + 3) -band -4, '='))
        }
        elseif ($Challenge.GetType().Name -eq "ByteString" -or $Challenge.GetType().FullName -like "*ByteString*") {
            Write-Verbose "Challenge is ByteString, converting to byte array"
            # Handle Google.Protobuf.ByteString
            $challengeBytes = $Challenge.ToByteArray()
        }
        elseif ($Challenge -and $Challenge.GetType().GetMethod("ToByteArray")) {
            Write-Verbose "Challenge has ToByteArray method, attempting conversion"
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
        
        Write-Verbose "Performing Windows Hello authentication..."
        Write-Host "Please complete biometric authentication..." -ForegroundColor Yellow
        
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
    
    .PARAMETER Vault
    Keeper vault instance (optional - will use global vault if not provided)
    
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
        Write-Host "Completing Keeper authentication with assertion data"
        if ($RpId) {
            Write-Host "Using RP ID: $RpId"
        }
        
        # Create the authentication completion request
        $request = [Authentication.PasskeyValidationRequest]::new()
        
        Write-Host "Setting challenge token..."
        $request.ChallengeToken = [Google.Protobuf.ByteString]::CopyFrom([byte[]]$ChallengeToken)
        
        # Set passkey purpose based on the purpose parameter
        # if ($Purpose -ne 'vault') {
        #     $request.PasskeyPurpose = [Authentication.PasskeyPurpose]::PkReauth
        # } else {
        #     $request.PasskeyPurpose = [Authentication.PasskeyPurpose]::PkLogin
        # }
        Write-Host "Set PasskeyPurpose to: $($request.PasskeyPurpose)"
        
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
 
        $response = $auth.ExecuteAuthRest("authentication/passkey/verify_authentication", $request, [Authentication.PasskeyValidationResponse]).GetAwaiter().GetResult()
                
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
    
    .PARAMETER Vault
    Keeper vault instance (optional - will use global vault if not provided)
    
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
        [object]$Vault
    )
    
    try {
        # Step 1: Get authentication options from Keeper API
        Write-Host "`nStep 1: Getting authentication options from Keeper..." -ForegroundColor Yellow
        $authOptions = Get-KeeperAuthenticationOptions -Username $Username -Purpose $Purpose -Vault $Vault
        
        if (-not $authOptions.success) {
            return @{
                Success = $false
                ErrorMessage = "Failed to get authentication options: $($authOptions.error_message)"
                ErrorType = "AuthenticationOptionsError"
            }
        }
        $rpid = $authOptions.request_options.publicKeyCredentialRequestOptions.rpId
        Write-Host "Authentication options retrieved successfully" -ForegroundColor Green
        $authOptionsJson = $authOptions | ConvertTo-Json -Depth 10
        Write-Host "Authentication options JSON: $authOptionsJson" -ForegroundColor Cyan
        
        Write-Host "RP ID: $($rpid)" -ForegroundColor Cyan
        $allowCredentials = $authOptions.request_options.publicKeyCredentialRequestOptions.allowCredentials
        if ($allowCredentials) {
            Write-Host "Allowed credentials: $($allowCredentials.Count)" -ForegroundColor Cyan
        } else {
            Write-Host "Allowed credentials: 0 (any registered credential)" -ForegroundColor Cyan
        }
        
        # Step 2: Perform Windows Hello assertion
        Write-Host "`nStep 2: Performing Windows Hello authentication..." -ForegroundColor Yellow
        
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
        
        Write-Host "Windows Hello assertion completed successfully" -ForegroundColor Green
        
        # Step 3: Complete authentication with Keeper
        Write-Host "`nStep 3: Completing authentication with Keeper..." -ForegroundColor Yellow
        $completion = Complete-KeeperAuthentication -ChallengeToken $authOptions.challenge_token -LoginToken $authOptions.login_token -CredentialId $assertion.CredentialId -AuthenticatorData $assertion.AuthenticatorData -ClientDataJSON $assertion.ClientDataJSON -Signature $assertion.Signature -UserHandle $assertion.UserHandle -Vault $Vault -RpId $rpid -Purpose $Purpose
        
        if (-not $completion.Success) {
            return @{
                Success = $false
                ErrorMessage = "Failed to complete Keeper authentication: $($completion.ErrorMessage)"
                ErrorType = "KeeperAuthenticationError"
            }
        }
        
        Write-Host "`nAuthentication flow completed successfully!" -ForegroundColor Green
        
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
        Write-Host "Registering WebAuthn credential with Keeper API"
        
        # Debug the incoming challenge token
        Write-Host "=== DEBUGGING REGISTER-KEEPERCREDENTIAL INPUTS ===" -ForegroundColor Yellow
        Write-Host "ChallengeToken Type: $($ChallengeToken.GetType().FullName)" -ForegroundColor Cyan
        Write-Host "ChallengeToken Value (first 100 chars): $($ChallengeToken.ToString().Substring(0, [Math]::Min(100, $ChallengeToken.ToString().Length)))" -ForegroundColor Cyan
        Write-Host "ChallengeToken Length: $($ChallengeToken.Length)" -ForegroundColor Cyan
        
        # Create the registration completion request
        $request = [Authentication.PasskeyRegistrationFinalization]::new()
        
        Write-Host "Converting challenge token to ByteString..." -ForegroundColor Yellow
        $request.ChallengeToken = [Google.Protobuf.ByteString]::CopyFrom([byte[]]$ChallengeToken)

        write-host "AttestationObject: $AttestationObject"        
        write-host "ClientDataJSON: $ClientDataJSON"
        
        # Reconstruct rawId from CredentialId (Base64Url -> raw bytes -> Base64Url)
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
        
        Write-Host "Authenticator Response JSON: $authenticatorResponseJson" -ForegroundColor Cyan
        
        $request.authenticatorResponse = $authenticatorResponseJson
        $request.FriendlyName = $friendly_name
        
        write-host "Request: $request"
        Write-Host "=== REQUEST OBJECT CONTENT ===" -ForegroundColor Yellow
        $request | Format-List * | Out-String | Write-Host -ForegroundColor Green
        Write-Host "=============================" -ForegroundColor Yellow
        $response = $auth.ExecuteAuthRest("authentication/passkey/verify_registration", $request).GetAwaiter().GetResult()
        
        $responseJson = $response | ConvertTo-Json -Depth 10

        write-host $responseJson

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
        Write-Host "===========================================" -ForegroundColor Yellow
        
        # Step 1: Get registration options from Keeper
        Write-Host "Step 1: Getting registration options from Keeper..." -ForegroundColor Yellow
        $regOptions = Get-KeeperRegistrationOptions -Vault $Vault
        
        # Step 2: Check for existing credentials before creating new ones
        Write-Host "Step 2: Checking for existing Windows Hello credentials..." -ForegroundColor Yellow

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
        write-host "pkCreationOptions: $($excludeCredentials)"
        Write-Host "Checking registry for existing credentials for: $username@$rpId" -ForegroundColor Cyan
        Write-Host "ExcludeCredentials count: $($excludeCredentials.Count)" -ForegroundColor Gray
        
        # Get all existing registry entries for this user
        $existingRegistryCreds = @()
        if ($IsWindows -or $PSVersionTable.PSVersion.Major -lt 6) {
            $existingRegistryCreds = Get-WindowsHelloRegisteredCredentials -Username $username -RpId $rpId
            Write-Host "Found $(@($existingRegistryCreds).Count) registered credential(s) in local registry" -ForegroundColor Cyan
            write-host "existingRegistryCreds: $($existingRegistryCreds)"
        }
        write-host "result: $($existingRegistryCreds.Count -gt 0 )"
        
        # Check for matches between registry entries and excludeCredentials
        $matchedCredential = $null
        if ($existingRegistryCreds.Count -gt 0 -and $excludeCredentials.Count -gt 0 -and -not $Force) {
            Write-Host "Comparing registry entries with existing credentials..." -ForegroundColor Yellow
                        
            foreach ($regCred in $existingRegistryCreds) {
                write-host "regCred: $($regCred)"
                $regCredId = $regCred.CredentialId
                Write-Host "Checking registry credential: $($regCredId.Substring(0, [Math]::Min(20, $regCredId.Length)))..." -ForegroundColor Gray
                
                foreach ($excludeCred in $excludeCredentials) {
                    write-host "excludeCred: $($excludeCred)"
                    $excludeCredId = $excludeCred.id
                    $excludeCredIdShort = $excludeCredId.Substring(0, [Math]::Min(20, $excludeCredId.Length))
                    Write-Host "  Against excludeCredential: $excludeCredIdShort..." -ForegroundColor Gray
                    
                    # Compare the first 20 characters (our registry key format)
                    if ($regCredId -eq $excludeCredIdShort) {
                        Write-Host "  MATCH FOUND! Registry credential matches excludeCredential" -ForegroundColor Green
                        $matchedCredential = $regCred
                        break
                    }
                }
                
                if ($matchedCredential) { break }
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
            -UserDisplayName $displayName

        if ($credResult.Success) {
            Write-Host " Windows Hello credential creation completed!" -ForegroundColor Green
            $registerResult = Register-KeeperCredential -ChallengeToken $regOptions.challenge_token -CredentialId $credResult.CredentialId -AttestationObject $credResult.AttestationObject -ClientDataJSON $credResult.ClientDataJSON -Vault $Vault
            if ($registerResult.Success) {
                $credentialId = $credResult.CredentialId
                $rpId = $regOptions.rp_id
                $username = $regOptions.user_name
                
                $registryResult = Register-WindowsHelloCredential -Username $username -RpId $rpId -CredentialId $credentialId -BiometricsEnabled $true
                if ($registryResult) {
                    Write-Host "Credential registered in local registry for tracking" -ForegroundColor Green
                } else {
                    Write-Warning "Failed to register credential in local registry (tracking may be limited)"
                }
            } else {
                Write-Host " Windows Hello credential creation failed: $($credResult.ErrorMessage)" -ForegroundColor Red0
                else {
                    # Credential created but registration failed
                    return @{
                        Success = $false
                        Error = "Credential created but registration failed: $($registerResult.Error)"
                        ErrorType = "RegistrationFailed"
                        PartialSuccess = $true
                        CredentialCreated = $true
                        CredentialId = $credResult.CredentialId
                        Timestamp = $credResult.Timestamp
                        }
                    }
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

#endregion

#region Main PowerCommander Interface

function Invoke-WindowsHelloOperation {
    <#
    .SYNOPSIS
    Unified interface for all Windows Hello operations from PowerCommander
    
    .DESCRIPTION
    This function provides a single entry point for all Windows Hello functionality
    that PowerCommander can use. It supports testing capabilities, authentication,
    and information retrieval through different operation modes.
    
    .PARAMETER Operation
    The operation to perform:
    - "Test" : Test Windows Hello availability and capabilities
    - "Authenticate" : Perform Windows Hello authentication
    - "Info" : Get detailed Windows Hello information
    - "Status" : Get simple availability status
    - "CreateCredential" : Create a new Windows Hello credential
    - "Register" : Complete Keeper registration flow (get options + create credential)
    
    .PARAMETER Challenge
    Authentication challenge (required for Authenticate operation)
    Registration challenge (required for CreateCredential operation)
    
    .PARAMETER RpId
    Relying party identifier (default: "keepersecurity.com")
    
    .PARAMETER RpName
    Relying party display name (optional, used for CreateCredential operation)
    
    .PARAMETER UserId
    User identifier as byte array (required for CreateCredential operation)
    
    .PARAMETER Username
    Username for context (optional, used for logging/display)
    For CreateCredential: used as the WebAuthn user name
    
    .PARAMETER UserDisplayName
    User display name (optional, used for CreateCredential operation)
    
    .PARAMETER TimeoutMs
    Authentication/Registration timeout in milliseconds (default: 60000)
    
    .PARAMETER AllowedCredentials
    Array of allowed credential IDs (base64 encoded, for Authenticate operation)
    
    .PARAMETER Vault
    Keeper vault instance (optional, used for Register operation)
    
    .PARAMETER Quiet
    Suppress console output for Test operation
    
    .EXAMPLE
    # Test if Windows Hello is available
    $result = Invoke-WindowsHelloOperation -Operation "Test"
    if ($result.Success) {
        Write-Host "Windows Hello is available"
    }
    
    .EXAMPLE
    # Perform authentication
    $challenge = [System.Text.Encoding]::UTF8.GetBytes("test-challenge")
    $result = Invoke-WindowsHelloOperation -Operation "Authenticate" -Challenge $challenge -Username "user@example.com"
    if ($result.Success) {
        # Use $result.Data.Signature, $result.Data.CredentialId, etc.
    }
    
    .EXAMPLE
    # Get detailed information
    $result = Invoke-WindowsHelloOperation -Operation "Info"
    $info = $result.Data
    Write-Host "API Version: $($info.ApiVersion)"
    
    .EXAMPLE
    # PowerCommander integration pattern
    function Connect-KeeperWithWindowsHello {
        param([string]$Username, [byte[]]$Challenge)
        
        # Single call to handle Windows Hello
        $result = Invoke-WindowsHelloOperation -Operation "Authenticate" -Challenge $Challenge -Username $Username -RpId "keepersecurity.com"
        
        if ($result.Success) {
            return $result.Data  # Contains Signature, CredentialId, etc.
        } else {
            throw $result.ErrorMessage
        }
    }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet("Test", "Authenticate", "Info", "Status", "CreateCredential", "Register")]
        [string]$Operation,
        
        [Parameter()]
        [byte[]]$Challenge,
        
        [Parameter()]
        [string]$RpId = "keepersecurity.com",
        
        [Parameter()]
        [string]$RpName,
        
        [Parameter()]
        [byte[]]$UserId,
        
        [Parameter()]
        [string]$Username,
        
        [Parameter()]
        [string]$UserDisplayName,
        
        [Parameter()]
        [int]$TimeoutMs = 60000,
        
        [Parameter()]
        [AllowEmptyCollection()]
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 'AllowedCredentials', Justification='Credential IDs are public identifiers, not sensitive data')]
        [string[]]$AllowedCredentials,
        
        [Parameter()]
        [object]$Vault,
        
        [Parameter()]
        [switch]$Quiet
    )
    
    # Check if assembly is available
    if (-not $PowerShellWindowsHelloAvailable) {
        return @{
            Success = $false
            Operation = $Operation
            ErrorMessage = "PowerShellWindowsHello assembly not available. Please build the project first."
            ErrorType = "AssemblyNotFound"
            Data = $null
            Timestamp = [DateTime]::UtcNow
        }
    }
    
    try {
        switch ($Operation) {
            "Test" {
                $capabilities = Test-WindowsHelloCapabilities -PassThru -Quiet:$Quiet
                return @{
                    Success = $capabilities.WindowsHello.Available
                    Operation = "Test"
                    Data = @{
                        IsAvailable = $capabilities.WindowsHello.Available
                        ApiVersion = $capabilities.WindowsHello.ApiVersion
                        Platform = $capabilities.WindowsHello.Platform
                        SupportedMethods = $capabilities.WindowsHello.Methods
                        CanCreateCredentials = $capabilities.PowerShellIntegration.CanCreateCredentials
                        CanAuthenticate = $capabilities.PowerShellIntegration.CanAuthenticate
                        ProductionReady = $capabilities.SystemInfo.ProductionReady
                        RecommendedCommand = $capabilities.PowerShellIntegration.RecommendedCommand
                    }
                    ErrorMessage = $capabilities.WindowsHello.Error
                    ErrorType = $null
                    Timestamp = [DateTime]::UtcNow
                }
            }
            
            "Authenticate" {
                if (-not $Challenge) {
                    throw "Challenge parameter is required for Authenticate operation"
                }
                
                if (-not $Quiet -and $Username) {
                    Write-Host " Windows Hello Authentication for: $Username" -ForegroundColor Green
                }
                
                $authResult = Invoke-WindowsHelloAuthentication -Challenge $Challenge -RpId $RpId -AllowedCredentials $AllowedCredentials -TimeoutMs $TimeoutMs
                
                return @{
                    Success = $authResult.Success
                    Operation = "Authenticate"
                    Data = if ($authResult.Success) { 
                        @{
                            CredentialId = $authResult.CredentialId
                            Signature = $authResult.Signature
                            AuthenticatorData = $authResult.AuthenticatorData
                            ClientDataJSON = $authResult.ClientDataJSON
                            UserHandle = $authResult.UserHandle
                            Method = $authResult.Method
                        }
                    } else { $null }
                    ErrorMessage = $authResult.ErrorMessage
                    ErrorType = $authResult.ErrorType
                    Timestamp = $authResult.Timestamp
                }
            }
            
            "Info" {
                $info = Get-WindowsHelloInfo
                return @{
                    Success = $info.IsAvailable
                    Operation = "Info"
                    Data = $info
                    ErrorMessage = $info.ErrorMessage
                    ErrorType = if ($info.ErrorMessage) { "InfoRetrievalError" } else { $null }
                    Timestamp = $info.LastChecked
                }
            }
            
            "Status" {
                $info = Get-WindowsHelloInfo
                return @{
                    Success = $info.IsAvailable
                    Operation = "Status"
                    Data = @{
                        IsAvailable = $info.IsAvailable
                        CanAuthenticate = $info.CanPerformAuthentication
                        Status = if ($info.IsAvailable) { "Ready" } else { "NotAvailable" }
                    }
                    ErrorMessage = $info.ErrorMessage
                    ErrorType = $null
                    Timestamp = [DateTime]::UtcNow
                }
            }
            
            "CreateCredential" {
                if (-not $Challenge) {
                    throw "Challenge parameter is required for CreateCredential operation"
                }
                if (-not $UserId) {
                    throw "UserId parameter is required for CreateCredential operation"
                }
                if (-not $Username) {
                    throw "Username parameter is required for CreateCredential operation"
                }
                
                if (-not $Quiet) {
                    Write-Host " Windows Hello Credential Creation for: $Username" -ForegroundColor Green
                }
                
                $credResult = Invoke-WindowsHelloCredentialCreation `
                    -Challenge $Challenge `
                    -RpId $RpId `
                    -RpName $RpName `
                    -UserId $UserId `
                    -UserName $Username `
                    -UserDisplayName $UserDisplayName `
                    -TimeoutMs $TimeoutMs
                
                return @{
                    Success = $credResult.Success
                    Operation = "CreateCredential"
                    Data = if ($credResult.Success) { 
                        @{
                            CredentialId = $credResult.CredentialId
                            AttestationObject = $credResult.AttestationObject
                            ClientDataJSON = $credResult.ClientDataJSON
                            PublicKey = $credResult.PublicKey
                            Method = $credResult.Method
                            SignatureCount = $credResult.SignatureCount
                        }
                    } else { $null }
                    ErrorMessage = $credResult.ErrorMessage
                    ErrorType = $credResult.ErrorType
                    Timestamp = $credResult.Timestamp
                }
            }
            
            "Register" {
                if (-not $Quiet) {
                    Write-Host " Windows Hello Registration for Keeper" -ForegroundColor Green
                    if ($Username) {
                        Write-Host "User: $Username" -ForegroundColor Cyan
                    }
                }
                
                $regResult = Invoke-KeeperCredentialCreation -Vault $Vault
                
                return @{
                    Success = $regResult.Success
                    Operation = "Register"
                    Data = if ($regResult.Success) { 
                        @{
                            ChallengeToken = $regResult.ChallengeToken
                            CredentialId = $regResult.CredentialId
                            AttestationObject = $regResult.AttestationObject
                            ClientDataJSON = $regResult.ClientDataJSON
                            PublicKey = $regResult.PublicKey
                            Method = $regResult.Method
                            RegistrationComplete = $true
                        }
                    } else { $null }
                    ErrorMessage = $regResult.Error
                    ErrorType = $regResult.ErrorType
                    Timestamp = $regResult.Timestamp
                }
            }
        }
    }
    catch {
        return @{
            Success = $false
            Operation = $Operation
            Data = $null
            ErrorMessage = $_.Exception.Message
            ErrorType = $_.Exception.GetType().Name
            Timestamp = [DateTime]::UtcNow
        }
    }
}

#endregion

#region Aliases and Exports

# Create convenient aliases
New-Alias -Name 'Test-WHello' -Value 'Test-WindowsHelloCapabilities' -Description 'Test Windows Hello capabilities' -Force
New-Alias -Name 'Get-WHello' -Value 'Get-WindowsHelloInfo' -Description 'Get Windows Hello info' -Force
New-Alias -Name 'Invoke-WHAuth' -Value 'Invoke-WindowsHelloAuthentication' -Description 'Windows Hello authentication' -Force
New-Alias -Name 'Invoke-WHOp' -Value 'Invoke-WindowsHelloOperation' -Description 'Unified Windows Hello interface for PowerCommander' -Force
New-Alias -Name 'New-WHCredential' -Value 'Invoke-WindowsHelloCredentialCreation' -Description 'Create Windows Hello credential' -Force
New-Alias -Name 'Get-KeeperRegOpts' -Value 'Get-KeeperRegistrationOptions' -Description 'Get Keeper registration options' -Force
New-Alias -Name 'Get-KeeperAuthOpts' -Value 'Get-KeeperAuthenticationOptions' -Description 'Get Keeper authentication options' -Force
New-Alias -Name 'Invoke-WHAssertion' -Value 'Invoke-WindowsHelloAssertion' -Description 'Windows Hello assertion' -Force
New-Alias -Name 'Complete-KeeperAuth' -Value 'Complete-KeeperAuthentication' -Description 'Complete Keeper authentication' -Force
New-Alias -Name 'Invoke-KeeperWHAuth' -Value 'Invoke-KeeperWindowsHelloAuthentication' -Description 'Keeper Windows Hello authentication flow' -Force
New-Alias -Name 'Register-KeeperCred' -Value 'Register-KeeperCredential' -Description 'Register credential with Keeper' -Force
New-Alias -Name 'Invoke-KeeperCredReg' -Value 'Invoke-KeeperCredentialCreation' -Description 'Keeper credential registration' -Force

# Registry-based credential management functions (Pure PowerShell implementation)
# These functions are only available on Windows platforms
if ($IsWindows -or $PSVersionTable.PSVersion.Major -lt 6) {
    # Define registry path for Windows Hello credentials
    $script:WindowsHelloRegistryPath = "HKCU:\Software\Keeper\WindowsHello\Credentials"
    
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
                
                write-host "properties: $($properties)"

                foreach ($prop in $properties.PSObject.Properties) {
                    if ($prop.Name -notlike "PS*") {
                        $keyName = $prop.Name
                        write-host "keyName: $($keyName)"
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
                            write-host "rpIdPart: $($rpIdPart)"
                            write-host "RpId: $($RpId)"
                            write-host "cleanRpId: $($cleanRpId)"
                            write-host (!$Username -or $cleanUsernamePart -like "*$cleanUsername*")
                            write-host (!$rpid -like "*$cleanRpId*")

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
                                
                                Write-Verbose "Parsed credential: $usernamePart@$rpIdPart -> $credentialIdPart"
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
    
    function Test-WindowsHelloCredentialRegistered {
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
                $value = (Get-ItemProperty -Path $script:WindowsHelloRegistryPath -Name $keyName -ErrorAction SilentlyContinue).$keyName
                return $value -ne $null
            }
            return $false
        }
        catch {
            Write-Error "Failed to check credential registration: $($_.Exception.Message)"
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
    
    function Get-WindowsHelloCredentialIds {
        [CmdletBinding()]
        param(
            [Parameter()]
            [string]$Username,
            
            [Parameter()]
            [string]$RpId
        )
        
        try {
            $credentialIds = @()
            
            if (Test-Path $script:WindowsHelloRegistryPath) {
                $properties = Get-ItemProperty -Path $script:WindowsHelloRegistryPath
                
                foreach ($prop in $properties.PSObject.Properties) {
                    if ($prop.Name -notlike "PS*") {
                        # Parse the key format: username___rpid___credentialId
                        # Example: satish.gaddala_metronlabs.com___keepersecurity.com___AC55W4EFR_tvICoiRrz6
                        $keyName = $prop.Name
                        $keyParts = $keyName.Split('___')
                        
                        if ($keyParts.Length -eq 3) {
                            # Simple parsing with ___ separators
                            $usernamePart = $keyParts[0] -replace '_', '@'
                            $rpIdPart = $keyParts[1] -replace '_', '.'
                            $credentialIdPart = $keyParts[2]
                            
                            # Apply filters if specified
                            if ((!$Username -or $usernamePart -like "*$Username*") -and
                                (!$RpId -or $rpIdPart -like "*$RpId*")) {
                                
                                $credentialIds += $credentialIdPart
                                Write-Verbose "Found credential ID: $credentialIdPart"
                            }
                        }
                    }
                }
            }
            
            Write-Host "Found $($credentialIds.Count) credential ID(s) in registry" -ForegroundColor Cyan
            return $credentialIds
        }
        catch {
            Write-Error "Failed to get credential IDs: $($_.Exception.Message)"
            return @()
        }
    }
} # End of Windows conditional compilation

# Export functions and aliases - Primary interface function is Invoke-WindowsHelloOperation
$exportFunctions = @(
    "Invoke-WindowsHelloOperation", "Test-WindowsHelloCapabilities", "Invoke-WindowsHelloAuthentication", 
    "Get-WindowsHelloInfo", "Import-PowerShellWindowsHello", "Invoke-WindowsHelloCredentialCreation", 
    "Get-KeeperRegistrationOptions", "Get-KeeperAuthenticationOptions", "Invoke-WindowsHelloAssertion", 
    "Complete-KeeperAuthentication", "Invoke-KeeperWindowsHelloAuthentication", "Register-KeeperCredential", 
    "Invoke-KeeperCredentialCreation", "ConvertFrom-Base64Url", "ConvertTo-ByteString", "Utf8BytesToString", 
    "Find-WindowsHelloCredentials", "Test-KeeperCredentialExists"
)

# Add Windows-specific registry functions if on Windows
if ($IsWindows -or $PSVersionTable.PSVersion.Major -lt 6) {
    $exportFunctions += @(
        "Register-WindowsHelloCredential", "Unregister-WindowsHelloCredential", 
        "Get-WindowsHelloRegisteredCredentials", "Test-WindowsHelloCredentialRegistered", 
        "Clear-AllWindowsHelloCredentials", "Get-WindowsHelloCredentialIds"
    )
}

Export-ModuleMember -Function $exportFunctions
Export-ModuleMember -Alias Invoke-WHOp, Test-WHello, Get-WHello, Invoke-WHAuth, New-WHCredential, Get-KeeperRegOpts, Get-KeeperAuthOpts, Invoke-WHAssertion, Complete-KeeperAuth, Invoke-KeeperWHAuth, Register-KeeperCred, Invoke-KeeperCredReg, Find-WHCreds

#endregion

#region Integration Examples and Documentation

<#
.AUTHENTICATION FLOW EXAMPLES

# Complete Windows Hello authentication flow
$result = Invoke-KeeperWindowsHelloAuthentication
if ($result.Success) {
    Write-Host "Authentication successful!"
}

# Step-by-step authentication
$authOptions = Get-KeeperAuthenticationOptions -Purpose "vault"
$rpid = $authOptions.request_options.publicKeyCredentialRequestOptions.rpId
$assertion = Invoke-WindowsHelloAssertion -Challenge $authOptions.challenge -RpId $rpid -AllowedCredentials $authOptions.allowCredentials
if ($assertion.Success) {
    $completion = Complete-KeeperAuthentication -ChallengeToken $authOptions.challenge_token -LoginToken $authOptions.login_token -CredentialId $assertion.CredentialId -AuthenticatorData $assertion.AuthenticatorData -ClientDataJSON $assertion.ClientDataJSON -Signature $assertion.Signature -RpId $rpid -Purpose "vault"
}

# Using aliases for shorter commands
$result = Invoke-KeeperWHAuth -Purpose "login"
$authOpts = Get-KeeperAuthOpts
$rpid = $authOpts.request_options.publicKeyCredentialRequestOptions.rpId
$assertion = Invoke-WHAssertion -Challenge $authOpts.challenge_token -RpId $rpid
#>

<#
.EXAMPLE
# Basic capability test
Test-WindowsHelloCapabilities

.EXAMPLE
# Get detailed information programmatically
$caps = Test-WindowsHelloCapabilities -PassThru
if ($caps.SystemInfo.ProductionReady) {
    Write-Host "Ready for production use"
}

.EXAMPLE
# Perform authentication with custom parameters
$challenge = [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes(32)
$result = Invoke-WindowsHelloAuthentication -Challenge $challenge -RpId "mycompany.com" -TimeoutMs 30000

.EXAMPLE
# Simple availability check
$info = Get-WindowsHelloInfo
if ($info.IsAvailable -and $info.CanPerformAuthentication) {
    Write-Host "Windows Hello authentication is available"
}

.EXAMPLE
# Integration with existing Keeper PowerCommander workflow
if ((Get-WindowsHelloInfo).IsAvailable) {
    # Use Windows Hello enhanced authentication
    $challenge = Get-KeeperAuthChallenge -Username "user@example.com"
    $authResult = Invoke-WindowsHelloAuthentication -Challenge $challenge.Challenge -RpId $challenge.RpId
    
    if ($authResult.Success) {
        # Continue with Keeper authentication using the assertion
        Complete-KeeperAuthentication -Username "user@example.com" -AuthResult $authResult
    }
} else {
    # Fall back to regular authentication
    Connect-Keeper -Username "user@example.com"
}
#>

function Find-WindowsHelloCredentials {
    <#
    .SYNOPSIS
    Discover existing Windows Hello credentials (all or filtered by RP ID and username)
    
    .DESCRIPTION
    This function uses the WebAuthn API to enumerate platform credentials directly.
    Lists all Windows Hello credentials by default, or filters by RP ID and username if provided.
    Can also check specific credentials from Keeper authentication options.
    
    .PARAMETER RpId
    The relying party identifier (e.g., "keepersecurity.com") - optional filter
    
    .PARAMETER Username
    The username to search for - optional filter
    
    .PARAMETER AuthenticationOptions
    Keeper authentication options object - if provided, will check which allowCredentials are present
    
    .EXAMPLE
    # List all Windows Hello credentials on the system
    $allCredentials = Find-WindowsHelloCredentials
    
    .EXAMPLE
    # Find credentials for a specific relying party
    $credentials = Find-WindowsHelloCredentials -RpId "keepersecurity.com"
    
    .EXAMPLE
    # Find credentials for specific user and relying party
    $credentials = Find-WindowsHelloCredentials -RpId "keepersecurity.com" -Username "john.doe@company.com"
    
    .EXAMPLE
    # Check which allowCredentials from Keeper authentication options are present
    $authOptions = Get-KeeperAuthenticationOptions -Username "user@example.com"
    $credentials = Find-WindowsHelloCredentials -AuthenticationOptions $authOptions
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$RpId,
        
        [Parameter()]
        [string]$Username,
        
        [Parameter(Mandatory = $true)]
        [object]$AuthenticationOptions
    )
    
    if (-not $PowerShellWindowsHelloAvailable) {
        Write-Warning "PowerShellWindowsHello assembly not available. Please build the project first."
        return @{
            Success = $false
            ErrorMessage = "PowerShellWindowsHello assembly not available"
            HasCredentials = $false
            DiscoveredCredentials = @()
        }
    }
    
    try {
        Write-Host "Discovering Windows Hello credentials..." -ForegroundColor Cyan
        Write-Host "Relying Party: $RpId" -ForegroundColor Gray
        if ($Username) {
            Write-Host "Username: $Username" -ForegroundColor Gray
        }
        
        # Extract allowCredentials from authentication options
        $allowCredentials = $AuthenticationOptions.request_options.publicKeyCredentialRequestOptions.allowCredentials
        if ($allowCredentials -and $allowCredentials.Count -gt 0) {
                Write-Host "Checking specific credentials from authentication options..." -ForegroundColor Yellow
                Write-Host "AllowCredentials count: $($allowCredentials.Count)" -ForegroundColor Gray
                
                # Extract credential IDs from allowCredentials
                $credentialIds = @()
                foreach ($allowedCred in $allowCredentials) {
                    $credentialIds += $allowedCred.id
                }
                
                # Call C# method with specific credential IDs to check
                $allResult = [PowerShellWindowsHello.WindowsHelloApi]::DiscoverCredentials($RpId, $Username, $credentialIds)
                Write-Host "Credential discovery result: $($allResult | ConvertTo-Json -Compress)" -ForegroundColor Gray


                if ($allResult.Success) {
                    # C# method already did the credential ID checking, just return the result
                    return $allResult
                }
        } else {
            Write-Host "No allowCredentials specified - checking all credentials for RP/User" -ForegroundColor Yellow
        }
        
        # Call the simple C# method that uses WebAuthn API directly
        $result = [PowerShellWindowsHello.WindowsHelloApi]::DiscoverCredentials($RpId, $Username)
        Write-Host "Credential discovery result: $($result | ConvertTo-Json -Compress)" -ForegroundColor Gray
        
        if ($result.Success) {
            Write-Host "Credential discovery completed successfully" -ForegroundColor Green
            Write-Host "Method: $($result.Method)" -ForegroundColor Cyan
            Write-Host "Status: $($result.StatusMessage)" -ForegroundColor White
            
            if ($result.HasCredentials) {
                Write-Host "Found $($result.DiscoveredCredentials.Count) credential(s):" -ForegroundColor Green
                foreach ($cred in $result.DiscoveredCredentials) {
                    Write-Host "  Source: $($cred.Source)" -ForegroundColor Gray
                    Write-Host "     RP ID: $($cred.RpId)" -ForegroundColor DarkCyan
                    if ($cred.UserHandle) {
                        Write-Host "     User: $($cred.UserHandle)" -ForegroundColor DarkCyan
                    }
                    Write-Host "     Credential ID: $($cred.CredentialId.Substring(0, [Math]::Min(20, $cred.CredentialId.Length)))..." -ForegroundColor DarkMagenta
                }
            } else {
                Write-Host "No credentials found" -ForegroundColor Red
                Write-Host "Try creating a credential first with Invoke-WindowsHelloCredentialCreation" -ForegroundColor Yellow
            }
        } else {
            Write-Host "Failed to discover credentials" -ForegroundColor Red
            Write-Host "Error: $($result.ErrorMessage)" -ForegroundColor Red
        }
        
        return $result
    }
    catch {
        Write-Error "Credential discovery failed: $($_.Exception.Message)"
        return @{
            Success = $false
            ErrorMessage = $_.Exception.Message
            HasCredentials = $false
            DiscoveredCredentials = @()
        }
    }
}

# Alias for convenience  
Set-Alias -Name Find-WHCreds -Value Find-WindowsHelloCredentials

function Test-KeeperCredentialExists {
    <#
    .SYNOPSIS
    Check if Windows Hello credentials exist using Keeper authentication options
    
    .DESCRIPTION
    This function checks if Windows Hello credentials exist by using Keeper authentication
    options to get the allowCredentials list and checking which ones are present on the system.
    
    .PARAMETER Username
    The username to get authentication options for
    
    .PARAMETER Purpose
    The purpose for authentication (default: "login")
    
    .PARAMETER Vault
    Keeper vault instance (optional - will use global vault if not provided)
    
    .EXAMPLE
    $exists = Test-KeeperCredentialExists -Username "user@company.com"
    if ($exists) {
        Write-Host "Credentials exist for this user"
    }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Username,
        
        [Parameter()]
        [string]$Purpose = "login",
        
        [Parameter()]
        [object]$Vault
    )
    
    try {
        # Get authentication options from Keeper
        $authOptions = Get-KeeperAuthenticationOptions -Username $Username -Purpose $Purpose -Vault $Vault
        
        if (-not $authOptions.success) {
            Write-Warning "Failed to get authentication options: $($authOptions.error_message)"
            return $false
        }

        # Get RP ID and username from authentication options for diagnostic
        $diagnosticRpId = $authOptions.request_options.publicKeyCredentialRequestOptions.rpId
        $diagnosticUsername = $Username
        
        # First, check our local registry for fast credential lookup (Windows only)
        if ($IsWindows -or $PSVersionTable.PSVersion.Major -lt 6) {
            Write-Host "Checking local registry for registered credentials..." -ForegroundColor Cyan
            $registeredCreds = Get-WindowsHelloRegisteredCredentials -Username $diagnosticUsername -RpId $diagnosticRpId
            if ($registeredCreds.Count -gt 0) {
                Write-Host "Found $($registeredCreds.Count) registered credential(s) in local registry" -ForegroundColor Green
                foreach ($cred in $registeredCreds) {
                    Write-Host "  - $($cred.Username)@$($cred.RpId): $($cred.CredentialId.Substring(0, [Math]::Min(20, $cred.CredentialId.Length)))... (biometrics: $($cred.BiometricsEnabled))" -ForegroundColor Gray
                }
                return $true
            }
            
            Write-Host "No credentials found in local registry, checking Windows Hello directly..." -ForegroundColor Yellow
        } else {
            Write-Host "Checking Windows Hello directly (registry tracking not available on this platform)..." -ForegroundColor Yellow
        }
        
        Write-Host "Running diagnostic to show all Windows Hello credentials..." -ForegroundColor Yellow
        [PowerShellWindowsHello.WindowsHelloApi]::DumpAllWindowsHelloCredentials($diagnosticRpId, $diagnosticUsername)
        
        # Test specific credentials from allowCredentials if they exist
        $allowCredentials = $authOptions.request_options.publicKeyCredentialRequestOptions.allowCredentials
        if ($allowCredentials -and $allowCredentials.Count -gt 0) {
            Write-Host "`nTesting specific credentials from allowCredentials..." -ForegroundColor Yellow
            foreach ($allowedCred in $allowCredentials) {
                $credId = $allowedCred.id
                $exists = [PowerShellWindowsHello.WindowsHelloApi]::TestCredentialExists($diagnosticRpId, $credId)
                Write-Host "Credential $($credId.Substring(0, [Math]::Min(20, $credId.Length)))... exists: $exists" -ForegroundColor $(if($exists) {"Green"} else {"Red"})
            }
        }
        
        # Check credentials using authentication options
        $credentials = Find-WindowsHelloCredentials -AuthenticationOptions $authOptions
        
        if ($credentials.Success) {
            if ($credentials.AllowCredentialsAnalysis) {
                # If we have allowCredentials analysis, check if any are present
                $hasCredentials = $credentials.AllowCredentialsAnalysis.Present -gt 0
                Write-Verbose "Found $($credentials.AllowCredentialsAnalysis.Present) of $($credentials.AllowCredentialsAnalysis.TotalAllowed) allowed credentials"
                return $hasCredentials
            } else {
                # Fallback to general credential check
                $hasCredentials = $credentials.HasCredentials
                Write-Verbose "Found $($credentials.DiscoveredCredentials.Count) credential(s) for $Username"
                return $hasCredentials
            }
        } else {
            Write-Verbose "No credentials found for $Username"
            return $false
        }
    }
    catch {
        Write-Warning "Error checking for existing credentials: $($_.Exception.Message)"
        return $false
    }
}

#endregion


# $auth.DeviceToken