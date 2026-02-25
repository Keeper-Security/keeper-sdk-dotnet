$KeeperBiometricAvailable = $false
if ($IsWindows -or ($PSVersionTable.Platform -eq 'Win32NT') -or ($env:OS -like '*Windows*')) {
    try {
        $null = [KeeperBiometrics.PasskeyManager]
        $KeeperBiometricAvailable = $true
    }
    catch {
        Write-Warning "KeeperBiometric assembly not available: $($_.Exception.Message)"
        $KeeperBiometricAvailable = $false
    }
}
else {
    $KeeperBiometricAvailable = $false
}

function Test-AssemblyAvailable {
    <#
    .SYNOPSIS
    Tests if the KeeperBiometric assembly is available
    
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
    
    if ($KeeperBiometricAvailable) {
        return $true
    }
    
    if (-not $Quiet -and ($IsWindows -or ($PSVersionTable.Platform -eq 'Win32NT') -or ($env:OS -like '*Windows*'))) {
        Write-Warning "KeeperBiometrics assembly not available. Please build the project first."
    }
    
    return $false
}


function Test-WindowsHelloCapabilities {
    <#
    .SYNOPSIS
    Tests Windows Hello capabilities with comprehensive information
    
    .DESCRIPTION
    This function checks if Windows Hello is available and returns detailed capability information.
    
    .EXAMPLE
    Test-WindowsHelloCapabilities
    
    .EXAMPLE
    $caps = Test-WindowsHelloCapabilities -PassThru
    if ($caps.IsAvailable) {
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
        if ($PassThru) {
            return [KeeperBiometric.PasskeyManager]::GetCapabilities()
        }
        else {
            return [KeeperBiometric.PasskeyManager]::IsAvailable()
        }
    }
    catch {
        if (-not $Quiet) {
            Write-Debug "Failed to check Windows Hello capabilities: $($_.Exception.Message)"
        }
        return $false
    }
}

function Assert-KeeperBiometricCredential {
    <#
    .SYNOPSIS
    Performs Windows Hello authentication using native WebAuthn APIs
    
    .DESCRIPTION
    This function performs the complete Windows Hello authentication flow using PasskeyManager.
        
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
    
    if (-not (Test-AssemblyAvailable)) {
        if ($PassThru) {
            return @{
                Success = $false
                IsValid = $false
                EncryptedLoginToken = $null
                ErrorMessage = "KeeperBiometrics assembly not available"
                ErrorType = "AssemblyNotFound"
            }
        }
        return
    }
    
    try {
        $auth = $null
        if ($Vault) {
            $auth = $Vault.Auth
        } elseif ($AuthSyncObject) {
            $auth = $AuthSyncObject
        } else {
            if (Get-Command getVault -ErrorAction SilentlyContinue) {
                $vault = getVault
                $auth = $vault.Auth
            } elseif ($Script:Context.Vault) {
                $vault = $Script:Context.Vault
                $auth = $vault.Auth
            } elseif (Get-Command getAuthSync -ErrorAction SilentlyContinue) {
                $auth = getAuthSync
            } elseif ($Script:Context.AuthSync) {
                $auth = $Script:Context.AuthSync
            } else {
                throw "No Vault or AuthSync instance available. Please connect to Keeper first."
            }
        }
        
        if ([string]::IsNullOrEmpty($Username)) {
            $Username = $auth.Username
        }
        
        $task = [KeeperBiometrics.PasskeyManager]::AuthenticatePasskeyAsync($auth, $Username, $Purpose)
        $result = $task.GetAwaiter().GetResult()
        
        if ($result.Success) {
            Write-Host "Verification completed successfully!" -ForegroundColor Green
        } else {
            if ($result.ErrorMessage -match "cancelled|cancel" -or $result.ErrorType -eq "OperationCanceledException") {
                Write-Host "Windows Hello authentication was cancelled." -ForegroundColor Yellow
            } else {
                Write-Warning "Verification failed: $($result.ErrorMessage)"
            }
        }
        
        if ($PassThru) {
            return $result
        }
    }
    catch {
        Write-Error "Windows Hello authentication flow failed: $($_.Exception.Message)"
        if ($PassThru) {
            return @{
                Success = $false
                IsValid = $false
                EncryptedLoginToken = $null
                ErrorMessage = $_.Exception.Message
                ErrorType = $_.Exception.GetType().Name
            }
        }
    }
}

function Get-KeeperAvailableBiometricCredentials {
    <#
    .SYNOPSIS
    Get list of available biometric credentials from Keeper
    
    .DESCRIPTION
    This function retrieves a list of all registered biometric credentials (passkeys) 
    associated with the current Keeper account.
    
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
    
    if (-not (Test-AssemblyAvailable)) {
        throw "KeeperBiometrics assembly not available. Please build the project first."
    }
    
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
        
        $task = [KeeperBiometrics.PasskeyManager]::ListPasskeysAsync($auth, $IncludeDisabled.IsPresent)
        $passkeyList = $task.GetAwaiter().GetResult()
        
        $credentials = @()
        foreach ($passkey in $passkeyList) {
            $credential = [PSCustomObject]@{
                Id = $passkey.UserId
                Name = $passkey.FriendlyName
                Created = $passkey.CreatedAt
                LastUsed = $passkey.LastUsedAt
                CredentialId = $passkey.CredentialId
                AAGUID = $passkey.AAGUID
                Disabled = $passkey.IsDisabled
            }
            $credentials += $credential
        }
        
        return $credentials
    }
    catch {
        Write-Error "Failed to get available biometrics credentials: $($_.Exception.Message)"
        throw "Error getting available biometrics credentials: $($_.Exception.Message)"
    }
}

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


function Unregister-KeeperBiometricCredential {
    <#
    .SYNOPSIS
    Remove/unregister biometric credentials from Keeper
    
    .DESCRIPTION
    This function removes biometric credentials (passkeys) from the Keeper account.
    
    .PARAMETER CredentialId
    Specific credential ID to remove (deprecated - not used, function removes for current username)
    
    .PARAMETER Username
    Username to unregister biometric auth for (optional - uses current user if not provided)
    
    .PARAMETER Confirm
    Skip confirmation prompt (default: false)
    
    .PARAMETER Vault
    Keeper vault instance (optional - will use global vault if not provided)
    
    .PARAMETER PassThru
    Return the result object. If not specified, function returns nothing.
    
    .EXAMPLE
    Unregister-KeeperBiometricCredential
    
    .EXAMPLE
    Unregister-KeeperBiometricCredential -Username "user@company.com"
    
    .EXAMPLE
    $result = Unregister-KeeperBiometricCredential -PassThru
    if ($result.Success) {
        Write-Host "Unregistration successful!"
    }
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 'CredentialId', Justification='Credential IDs are public identifiers, not sensitive data')]
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
    
    if (-not (Test-AssemblyAvailable)) {
        if ($PassThru) {
            return @{
                Success = $false
                ErrorMessage = "KeeperBiometrics assembly not available"
                ErrorType = "AssemblyNotFound"
            }
        }
        return
    }
    
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
        
        $credentialId = [KeeperBiometrics.CredentialStorage]::GetCredentialId($Username)
        if (-not $credentialId) {
            $result = @{
                Success = $true
                Message = "Biometrics authentication is not registered for user: $Username"
            }
            if ($PassThru) {
                return $result
            }
            Write-Host $result.Message -ForegroundColor Yellow
            return
        }
        
        if (-not $PSCmdlet.ShouldProcess($Username, "Remove biometrics authentication")) {
            $result = @{
                Success = $false
                Message = "Operation cancelled by user"
            }
            if ($PassThru) {
                return $result
            }
            return
        }
        
        $task = [KeeperBiometrics.PasskeyManager]::RemovePasskeyAsync($auth, $Username)
        $success = $task.GetAwaiter().GetResult()
        
        $result = if ($success) {
            Write-Host "Successfully unregistered biometrics credentials for user: $Username" -ForegroundColor Green
            @{
                Success = $true
                Message = "Biometrics credentials unregistered successfully"
                Username = $Username
            }
        } else {
            @{
                Success = $false
                Message = "Failed to unregister biometrics credentials"
                Username = $Username
            }
        }
        
        if ($PassThru) {
            return $result
        }
    }
    catch {
        Write-Error "Failed to unregister biometrics credentials: $($_.Exception.Message)"
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
            Write-Host "No biometrics authentication methods found." -ForegroundColor Yellow
            return
        }
    
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
            
            # Determine status
            $status = if ($credential.Disabled) { "DISABLED" } else { "ACTIVE" }
            $statusColor = if ($credential.Disabled) { "Red" } else { "Green" }
            
            $credentialIdDisplay = $credential.CredentialId
            Write-Host "Id: $credentialIdDisplay" -ForegroundColor Cyan
            Write-Host "Name: $displayName" -ForegroundColor White
            Write-Host "Status: $status" -ForegroundColor $statusColor
            Write-Host "Created: $createdDate" -ForegroundColor Cyan
            Write-Host "Last Used: $lastUsedDate" -ForegroundColor Cyan
            Write-Host ("-" * 70) -ForegroundColor Gray
        }
    }
    catch {
        Write-Error "Failed to display biometrics credentials: $($_.Exception.Message)"
        throw "Error displaying biometrics credentials: $($_.Exception.Message)"
    }
}

function Register-KeeperBiometricCredential {
    <#
    .SYNOPSIS
    Complete Windows Hello credential creation flow for Keeper
    
    .DESCRIPTION
    This function performs the complete Windows Hello credential creation flow using PasskeyManager.
    
    .PARAMETER Vault
    Keeper vault instance (optional)
    
    .PARAMETER Force
    Force creation of new credential even if existing credentials are found
    
    .PARAMETER FriendlyName
    Friendly name for the credential (optional)
    
    .PARAMETER PassThru
    Return the registration result object. If not specified, function returns nothing on success or false on failure.
    
    .EXAMPLE
    Register-KeeperBiometricCredential
    
    .EXAMPLE
    Register-KeeperBiometricCredential -Force
    
    .EXAMPLE
    Register-KeeperBiometricCredential -FriendlyName "My Work Laptop"
    
    .EXAMPLE
    $result = Register-KeeperBiometricCredential -PassThru
    if ($result.Success) {
        Write-Host "Registration successful"
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
    
    if (-not (Test-AssemblyAvailable)) {
        if ($PassThru) {
            return @{
                Success = $false
                ErrorMessage = "KeeperBiometric assembly not available"
                ErrorType = "AssemblyNotFound"
            }
        }
        return $false
    }
    
    try {
        Write-Host "Biometrics Credential Creation for Keeper" -ForegroundColor Yellow
        
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
        
        $task = [KeeperBiometrics.PasskeyManager]::RegisterPasskeyAsync($auth, $FriendlyName, $Force.IsPresent)
        $result = $task.GetAwaiter().GetResult()
        
        if ($result.Success) {
            Write-Host "Credential created successfully" -ForegroundColor Green
            Write-Host "Success! Biometrics authentication has been registered." -ForegroundColor Green
            Write-Host "Please register your device using the `"Set-KeeperDeviceSettings -Register`" command to set biometrics authentication as your default login method." -ForegroundColor Yellow
        } else {
            Write-Warning "Registration failed: $($result.ErrorMessage)"
        }
        
        if ($PassThru) {
            return @{
                Success = $result.Success
                ErrorMessage = $result.ErrorMessage
                Username = $result.Username
                CredentialId = $result.CredentialId
            }
        } 
        
        return $result.Success
    }
    catch {
        Write-Error "Keeper credential creation failed: $($_.Exception.Message)"
        $errorResult = @{
            Success = $false
            Error = $_.Exception.Message
            ErrorType = $_.Exception.GetType().Name
            Timestamp = [DateTime]::UtcNow
        }
        if ($PassThru) {
            return $errorResult
        }
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
        return [KeeperBiometrics.CredentialStorage]::GetCredentialId($Username)
    }
    catch {
        return $null
    }
}

function Test-WindowsHelloBiometricPreviouslyUsed {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Username
    )
    
    try {
        $credId = [KeeperBiometrics.CredentialStorage]::GetCredentialId($Username)
        return (-not [string]::IsNullOrEmpty($credId))
    }
    catch {
        return $false
    }
}

$exportFunctions = @(
    "Test-WindowsHelloCapabilities","Assert-KeeperBiometricCredential","Register-KeeperBiometricCredential","Show-KeeperBiometricCredentials","Unregister-KeeperBiometricCredential"
)

Export-ModuleMember -Function $exportFunctions
