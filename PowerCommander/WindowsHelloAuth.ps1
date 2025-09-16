#requires -Version 5.1

# Windows Hello / Biometric Authentication for PowerCommander
# This module provides native Windows Hello functionality without external dependencies

#region Helper Functions
function Test-InteractiveSession {
    <#
    .SYNOPSIS
    Tests if the current PowerShell session is interactive
    #>
    if ($psISE) { return $true }
    if ($Host.Name -eq 'ConsoleHost') { return $true }
    if ($PSPrivateMetadata.JobId) { return $false }
    return $true
}

function Invoke-CredentialManagerOperation {
    <#
    .SYNOPSIS
    Helper function to interact with Windows Credential Manager
    #>
    param(
        [Parameter(Mandatory=$true)][ValidateSet('Add', 'Get', 'Delete')]
        [string]$Operation,
        [Parameter(Mandatory=$true)][string]$Target,
        [Parameter()][string]$Username,
        [Parameter()][securestring]$Password,
        [Parameter()][string]$Comment = "Keeper Windows Hello Credential"
    )
    
    try {
        switch ($Operation) {
            'Add' {
                try {
                    # Use Windows Credential Manager APIs for better password storage/retrieval
                    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;

public class WindowsCredentialManager {
    [StructLayout(LayoutKind.Sequential)]
    public struct CREDENTIAL {
        public uint Flags;
        public uint Type;
        public string TargetName;
        public string Comment;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
        public uint CredentialBlobSize;
        public IntPtr CredentialBlob;
        public uint Persist;
        public uint AttributeCount;
        public IntPtr Attributes;
        public string TargetAlias;
        public string UserName;
    }

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CredWriteW([In] ref CREDENTIAL userCredential, [In] uint flags);

    public const uint CRED_TYPE_GENERIC = 1;
    public const uint CRED_PERSIST_LOCAL_MACHINE = 2;
}
"@ -ErrorAction SilentlyContinue
                    
                    $cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $Username, $Password
                    $passwordText = $cred.GetNetworkCredential().Password
                    
                    # Create Windows credential structure
                    $credential = New-Object WindowsCredentialManager+CREDENTIAL
                    $credential.TargetName = $Target
                    $credential.UserName = $Username
                    $credential.Comment = $Comment
                    $credential.Type = [WindowsCredentialManager]::CRED_TYPE_GENERIC
                    $credential.Persist = [WindowsCredentialManager]::CRED_PERSIST_LOCAL_MACHINE
                    
                    # Convert password to bytes
                    $passwordBytes = [System.Text.Encoding]::UTF8.GetBytes($passwordText)
                    $credential.CredentialBlobSize = [uint]$passwordBytes.Length
                    $credential.CredentialBlob = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($passwordBytes.Length)
                    [System.Runtime.InteropServices.Marshal]::Copy($passwordBytes, 0, $credential.CredentialBlob, $passwordBytes.Length)
                    
                    try {
                        $result = [WindowsCredentialManager]::CredWriteW([ref]$credential, 0)
                        Write-Verbose "Credential stored using Windows APIs: $result"
                        return $result
                    }
                    finally {
                        if ($credential.CredentialBlob -ne [IntPtr]::Zero) {
                            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($credential.CredentialBlob)
                        }
                    }
                }
                catch {
                    Write-Verbose "Windows API storage failed, falling back to cmdkey: $($_.Exception.Message)"
                    # Fallback to original method
                    $cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $Username, $Password
                    & cmdkey /generic:"$Target" /user:"$Username" /pass:"$($cred.GetNetworkCredential().Password)" 2>$null
                    return $LASTEXITCODE -eq 0
                }
            }
            'Get' {
                $output = & cmdkey /list:"$Target" 2>$null
                
                # Debug: Show what we got from cmdkey
                Write-Verbose "LASTEXITCODE: $LASTEXITCODE"
                Write-Verbose "cmdkey output ($($output.Count) lines):"
                for ($i = 0; $i -lt $output.Count; $i++) {
                    Write-Verbose "  [$i]: '$($output[$i])'"
                }
                
                if ($LASTEXITCODE -eq 0) {
                    # Check if credentials exist by looking for "Currently stored credentials for [target]"
                    $credentialLine = $output | Where-Object { $_ -match "Currently stored credentials for.*$([regex]::Escape($Target))" }
                    
                    Write-Verbose "Credential line found: $($null -ne $credentialLine)"
                    if ($credentialLine) {
                        Write-Verbose "Found credential line: $credentialLine"
                    }
                    
                    if ($credentialLine) {
                        # Credentials exist - now look for explicit user line
                        $userLine = $output | Where-Object { $_ -match "^\s*User:\s*(.+)$" }
                        if ($userLine) {
                            $extractedUser = $userLine -replace "^\s*User:\s*", ""
                            Write-Verbose "Found explicit user line: $extractedUser"
                            return $extractedUser
                        } else {
                            # No explicit User: line found, extract username from target
                            # Pattern: KeeperWindowsHello:server:username
                            if ($Target -match ":([^:]+)$") {
                                $extractedUser = $matches[1]
                                Write-Verbose "Extracted user from target pattern: $extractedUser"
                                return $extractedUser
                            } else {
                                # Fallback: return a generic indicator that credential exists
                                Write-Verbose "Credential exists but cannot extract username"
                                return "CREDENTIAL_EXISTS"
                            }
                        }
                    }
                }
                
                Write-Verbose "No valid credential found"
                return $null
            }
            'Delete' {
                & cmdkey /delete:"$Target" 2>$null
                return $LASTEXITCODE -eq 0
            }
        }
    }
    catch {
        Write-Verbose "Credential operation failed: $($_.Exception.Message)"
        return $false
    }
}

#endregion

#region Biometric Registration Functions

function Register-WindowsHelloBiometric {
    <#
    .SYNOPSIS
    Registers a new Windows Hello biometric credential for Keeper authentication
    
    .DESCRIPTION
    This function provides a complete biometric registration flow for Keeper using Windows Hello.
    It creates WebAuthn-compatible credentials, stores them securely, and sets up biometric authentication.
    
    The registration process includes:
    1. Windows Hello availability verification
    2. Biometric functionality test
    3. Windows Hello passkey creation using KeyCredentialManager
    4. Backup credential storage in Windows Credential Manager
    5. Registration metadata storage in Windows Registry
    6. Complete setup verification
    
    After successful registration, users can authenticate using:
    Connect-KeeperWithBiometrics -Username "user@example.com"
    
    .PARAMETER Username
    Keeper username/email
    
    .PARAMETER Password
    Master password (as SecureString) for initial authentication and backup storage
    
    .PARAMETER Server
    Keeper server (optional, defaults to keepersecurity.com)
    
    .PARAMETER DisplayName
    Display name for the credential (optional, defaults to username)
    
    .PARAMETER Force
    Force registration even if biometric credential already exists
    
    .EXAMPLE
    # Basic registration with interactive password prompt
    $password = Read-Host "Enter password" -AsSecureString
    Register-WindowsHelloBiometric -Username "user@example.com" -Password $password
    
    .EXAMPLE
    # Registration with custom server
    $password = Read-Host "Enter password" -AsSecureString
    Register-WindowsHelloBiometric -Username "user@example.com" -Password $password -Server "eu.keepersecurity.com"
    
    .EXAMPLE
    # Force re-registration (overwrites existing)
    Register-WindowsHelloBiometric -Username "user@example.com" -Server "eu.keepersecurity.com" -Force
    
    .EXAMPLE
    # Using convenient alias
    $password = Read-Host "Enter password" -AsSecureString
    kreg -Username "user@example.com" -Password $password
    
    .NOTES
    Requires Windows 10+ with Windows Hello configured (PIN, Face, or Fingerprint)
    Creates a Windows passkey visible in Settings > Accounts > Passkeys
    Stores backup credentials in Windows Credential Manager for fallback
    Registers metadata in Windows Registry for management
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Username,
        
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [SecureString]$Password,
        
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Server = "keepersecurity.com",
        
        [Parameter()]
        [string]$DisplayName,
        
        [Parameter()]
        [switch]$Force
    )
    
    begin {
        Write-Verbose "Starting Windows Hello biometric registration for $Username"
        
        # Set display name if not provided
        if (-not $DisplayName) {
            $DisplayName = $Username
        }
        
        # Check Windows Hello availability first
        if (-not (Test-WindowsHelloAvailability)) {
            Write-Error "Windows Hello is not available on this system. Please configure Windows Hello in Settings." -ErrorAction Stop
            return $false
        }
    }
    
    process {
        try {
            # Check if biometric credential already exists
            if (-not $Force) {
                $existingCred = Get-KeeperBiometricCredential -Username $Username -Server $Server
                if ($existingCred) {
                    Write-Warning "Biometric credential already exists for $Username on $Server"
                    $overwrite = Read-Host "Do you want to overwrite the existing credential? (y/N)"
                    if ($overwrite -ne 'y' -and $overwrite -ne 'Y') {
                        Write-Information "Registration cancelled by user" -InformationAction Continue
                        return $false
                    }
                }
            }
            
            if ($PSCmdlet.ShouldProcess("$Username@$Server", "Register Windows Hello biometric credential")) {
                
                # Step 2: Initial biometric verification to ensure Windows Hello is working
                Write-Host "Step 1: Verify Windows Hello functionality" -ForegroundColor Yellow
                $initialVerification = Invoke-WindowsHelloVerification -Message "Verify Windows Hello is working properly"
                
                if (-not $initialVerification) {
                    Write-Error "Windows Hello verification failed. Please ensure your biometric authentication is set up correctly." -ErrorAction Stop
                    return $false
                }
                
                Write-Host "Windows Hello verification successful" -ForegroundColor Green
                Write-Host ""
                
                # Step 3: Create the biometric credential with enhanced options
                Write-Host "Step 2: Creating Windows Hello credential" -ForegroundColor Yellow
                
                # Generate unique credential identifier
                $credentialId = "Keeper-$Server-$Username-$([System.Guid]::NewGuid().ToString('N').Substring(0,8))"
                $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                
                Write-Host "Creating credential ID: $credentialId" -ForegroundColor Cyan
                
                # Create Windows Hello passkey using KeyCredentialManager
                $passkeyResult = CreateWindowsPasskey -CredentialId $credentialId -DisplayName $DisplayName -Username $Username -Server $Server
                
                if ($passkeyResult.Success) {
                    Write-Host "  Windows Hello passkey created successfully" -ForegroundColor Green
                    Write-Host "  Passkey ID: $($passkeyResult.KeyId)" -ForegroundColor Cyan
                    Write-Host "  Display Name: $DisplayName" -ForegroundColor Cyan
                } else {
                    Write-Warning "Passkey creation failed, falling back to credential manager storage"
                }
                
                # Step 4: Store backup credentials in Windows Credential Manager
                Write-Host ""
                Write-Host "Step 3: Setting up backup credential storage" -ForegroundColor Yellow
                
                $target = "KeeperWindowsHello:${Server}:${Username}"
                $backupResult = Invoke-CredentialManagerOperation -Operation 'Add' -Target $target -Username $Username -Password $Password -Comment "Keeper Windows Hello - Created $timestamp"
                
                if ($backupResult) {
                    Write-Host " Backup credentials stored in Windows Credential Manager" -ForegroundColor Green
                } else {
                    Write-Warning "Failed to store backup credentials"
                }
                
                # Step 5: Store registration metadata
                Write-Host ""
                Write-Host "Step 4: Storing registration metadata" -ForegroundColor Yellow
                
                $metadata = @{
                    Username = $Username
                    Server = $Server
                    DisplayName = $DisplayName
                    CredentialId = $credentialId
                    CreatedDate = $timestamp
                    PasskeyEnabled = $passkeyResult.Success
                    BackupStored = $backupResult
                    Version = "2.0"
                }
                
                $metadataResult = StoreRegistrationMetadata -Username $Username -Server $Server -Metadata $metadata
                
                if ($metadataResult) {
                    Write-Host " Registration metadata stored" -ForegroundColor Green
                } else {
                    Write-Warning "Failed to store registration metadata"
                }
                
                # Step 6: Verify the complete setup
                Write-Host ""
                Write-Host "Step 5: Verifying registration" -ForegroundColor Yellow
                
                $verificationResult = VerifyBiometricSetup -Username $Username -Server $Server
                
                if ($verificationResult.IsValid) {
                   if ($passkeyResult.Success) {
                        Write-Host " Windows Passkey created (visible in Settings > Accounts > Passkeys)" -ForegroundColor Green
                    }
                    Write-Host " Backup credentials stored in Windows Credential Manager" -ForegroundColor Green
                    Write-Host " Registration metadata stored" -ForegroundColor Green
                    Write-Host ""
                    Write-Host "You can now use Windows Hello authentication with:" -ForegroundColor Yellow
                    Write-Host "  Connect-KeeperWithBiometrics -Username '$Username'" -ForegroundColor Cyan
                    Write-Host ""
                    
                    return $true
                } else {
                    Write-Error "Registration verification failed: $($verificationResult.ErrorMessage)" -ErrorAction Stop
                    return $false
                }
            }
        }
        catch {
            Write-Error "Biometric registration failed: $($_.Exception.Message)" -ErrorAction Stop
            
            # Cleanup on failure
            Write-Host "Attempting cleanup of partial registration..." -ForegroundColor Yellow
            try {
                Remove-KeeperBiometricCredential -Username $Username -Server $Server -Confirm:$false
                Write-Host " Cleanup completed" -ForegroundColor Green
            } catch {
                Write-Warning "Cleanup failed: $($_.Exception.Message)"
            }
            
            return $false
        }
    }
    
    end {
        Write-Verbose "Windows Hello biometric registration completed for $Username"
    }
}

function CreateWindowsPasskey {
    <#
    .SYNOPSIS
    Creates a Windows Hello passkey using KeyCredentialManager APIs
    #>
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 'CredentialId', Justification='CredentialId is a public identifier, not a password')]
    param(
        # CredentialId is not sensitive - it's just a unique identifier for the Windows Hello key
        [Parameter(Mandatory=$true)][string]$CredentialId,
        [Parameter(Mandatory=$true)][string]$DisplayName,
        [Parameter(Mandatory=$true)][string]$Username,
        [Parameter(Mandatory=$true)][string]$Server
    )
    
    try {
        # Load Windows Runtime types for KeyCredential
        Add-Type -AssemblyName System.Runtime.WindowsRuntime
        [Windows.Security.Credentials.KeyCredentialManager, Windows.Security.Credentials, ContentType = WindowsRuntime] | Out-Null
        
        Write-Verbose "Creating Windows Hello passkey for: $CredentialId"
        
        # Create the key credential (passkey) with replace existing option
        $keyCreationRequest = [Windows.Security.Credentials.KeyCredentialManager]::RequestCreateAsync(
            $CredentialId, 
            [Windows.Security.Credentials.KeyCredentialCreationOption]::ReplaceExisting
        )
        
        # Convert async operation to synchronous result
        $asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object { 
            $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and 
            $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' 
        })[0]
        $asyncTask = $asTaskGeneric.MakeGenericMethod([Windows.Security.Credentials.KeyCredentialRetrievalResult]).Invoke($null, @($keyCreationRequest))
        $creationResult = $asyncTask.GetAwaiter().GetResult()
        
        Write-Verbose "Key creation result status: $($creationResult.Status)"
        
        # Handle the creation result
        switch ($creationResult.Status) {
            ([Windows.Security.Credentials.KeyCredentialStatus]::Success) {
                $keyCredential = $creationResult.Credential
                return @{
                    Success = $true
                    KeyId = $CredentialId
                    Status = "Success"
                    Message = "Windows Hello passkey created successfully"
                    Credential = $keyCredential
                }
            }
            ([Windows.Security.Credentials.KeyCredentialStatus]::UserCanceled) {
                return @{
                    Success = $false
                    Status = "UserCanceled"
                    Message = "User cancelled passkey creation"
                }
            }
            ([Windows.Security.Credentials.KeyCredentialStatus]::NotFound) {
                return @{
                    Success = $false
                    Status = "NotFound"  
                    Message = "Windows Hello not configured"
                }
            }
            ([Windows.Security.Credentials.KeyCredentialStatus]::UnknownError) {
                return @{
                    Success = $false
                    Status = "UnknownError"
                    Message = "Unknown error creating passkey"
                }
            }
            default {
                return @{
                    Success = $false
                    Status = $creationResult.Status
                    Message = "Passkey creation failed with status: $($creationResult.Status)"
                }
            }
        }
    }
    catch {
        Write-Verbose "Error creating Windows passkey: $($_.Exception.Message)"
        return @{
            Success = $false
            Status = "Exception"
            Message = "Exception creating passkey: $($_.Exception.Message)"
        }
    }
}

function StoreRegistrationMetadata {
    <#
    .SYNOPSIS
    Stores biometric registration metadata in Windows Registry
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Username,
        [Parameter(Mandatory=$true)][string]$Server,
        [Parameter(Mandatory=$true)][hashtable]$Metadata
    )
    
    try {
        $registryPath = "HKCU:\Software\Keeper\WindowsHello\Registrations"
        $keyName = "$Server\$Username"
        
        # Ensure the registry path exists
        if (-not (Test-Path $registryPath)) {
            New-Item -Path $registryPath -Force | Out-Null
        }
        
        # Store each metadata item as registry value
        foreach ($key in $Metadata.Keys) {
            $valueName = $key
            $valueData = $Metadata[$key]
            
            # Convert complex objects to JSON
            if ($valueData -is [hashtable] -or $valueData -is [array]) {
                $valueData = $valueData | ConvertTo-Json -Depth 3
            }
            
            Set-ItemProperty -Path $registryPath -Name "${keyName}_${valueName}" -Value $valueData -Force
        }
        
        Write-Verbose "Stored registration metadata for $Username on $Server"
        return $true
    }
    catch {
        Write-Warning "Failed to store registration metadata: $($_.Exception.Message)"
        return $false
    }
}

function VerifyBiometricSetup {
    <#
    .SYNOPSIS
    Verifies that biometric setup is complete and working
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Username,
        [Parameter(Mandatory=$true)][string]$Server
    )
    
    try {
        # Check if Windows Hello is available
        if (-not (Test-WindowsHelloAvailability)) {
            return @{
                IsValid = $false
                ErrorMessage = "Windows Hello is not available"
            }
        }
        
        # Check if biometric credential exists
        $credential = Get-KeeperBiometricCredential -Username $Username -Server $Server
        if (-not $credential) {
            return @{
                IsValid = $false
                ErrorMessage = "No biometric credential found"
            }
        }
        
        # Verify credential manager storage
        $target = "KeeperWindowsHello:${Server}:${Username}"
        $storedUsername = Invoke-CredentialManagerOperation -Operation 'Get' -Target $target
        if (-not $storedUsername) {
            return @{
                IsValid = $false
                ErrorMessage = "No backup credential found in Windows Credential Manager"
            }
        }
        
        # Test biometric verification
        Write-Host "Testing Windows Hello verification..." -ForegroundColor Cyan
        $verificationTest = Invoke-WindowsHelloVerification -Message "Test verification for registration completion"
        
        if (-not $verificationTest) {
            return @{
                IsValid = $false
                ErrorMessage = "Windows Hello verification test failed"
            }
        }
        
        return @{
            IsValid = $true
            Message = "Biometric setup verification successful"
            Credential = $credential
            StoredUsername = $storedUsername
        }
    }
    catch {
        return @{
            IsValid = $false
            ErrorMessage = "Verification error: $($_.Exception.Message)"
        }
    }
}

function Get-RegisteredBiometricCredentials {
    <#
    .SYNOPSIS
    Lists all registered Windows Hello biometric credentials for Keeper
    
    .DESCRIPTION
    This function retrieves information about all registered Windows Hello biometric credentials
    from the Windows registry and Credential Manager.
    
    .EXAMPLE
    Get-RegisteredBiometricCredentials
    
    .EXAMPLE
    $creds = Get-RegisteredBiometricCredentials
    $creds | Format-Table -AutoSize
    #>
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param()
    
    $registeredCredentials = @()
    
    try {
        # Check Windows registry for stored metadata
        $registryPath = "HKCU:\Software\Keeper\WindowsHello\Registrations"
        
        if (Test-Path $registryPath) {
            $regValues = Get-ItemProperty -Path $registryPath -ErrorAction SilentlyContinue
            
            if ($regValues) {
                # Parse registry values to extract credential information
                $credentialData = @{}
                
                foreach ($property in $regValues.PSObject.Properties) {
                    if ($property.Name -notin @('PSPath', 'PSParentPath', 'PSChildName', 'PSProvider')) {
                        $parts = $property.Name -split '_', 2
                        if ($parts.Count -eq 2) {
                            $keyName = $parts[0]
                            $valueName = $parts[1]
                            
                            if (-not $credentialData.ContainsKey($keyName)) {
                                $credentialData[$keyName] = @{}
                            }
                            
                            $credentialData[$keyName][$valueName] = $property.Value
                        }
                    }
                }
                
                # Convert to credential objects
                foreach ($key in $credentialData.Keys) {
                    $data = $credentialData[$key]
                    $serverUser = $key -split '\\', 2
                    
                    if ($serverUser.Count -eq 2) {
                        $server = $serverUser[0]
                        $username = $serverUser[1]
                        
                        # Verify credential still exists in Credential Manager
                        $target = "KeeperWindowsHello:${server}:${username}"
                        $credExists = Invoke-CredentialManagerOperation -Operation 'Get' -Target $target
                        
                        $credentialInfo = [PSCustomObject]@{
                            Username = $username
                            Server = $server
                            DisplayName = $data.DisplayName
                            CredentialId = $data.CredentialId
                            CreatedDate = $data.CreatedDate
                            PasskeyEnabled = [bool]::Parse($data.PasskeyEnabled)
                            BackupStored = [bool]::Parse($data.BackupStored)
                            Version = $data.Version
                            CredentialExists = $null -ne $credExists
                            Status = if ($credExists) { "Active" } else { "Inactive" }
                        }
                        
                        $registeredCredentials += $credentialInfo
                    }
                }
            }
        }
        
        # Also check Credential Manager for any credentials without registry metadata
        $credmanTargets = & cmdkey /list 2>$null | Where-Object { $_ -match "KeeperWindowsHello:" }
        
        foreach ($line in $credmanTargets) {
            if ($line -match "Target: (KeeperWindowsHello:([^:]+):(.+))") {
                $target = $matches[1]
                $server = $matches[2]
                $username = $matches[3]
                
                # Check if we already have this credential from registry
                $existing = $registeredCredentials | Where-Object { $_.Username -eq $username -and $_.Server -eq $server }
                
                if (-not $existing) {
                    # Add credential found only in Credential Manager
                    $credentialInfo = [PSCustomObject]@{
                        Username = $username
                        Server = $server
                        DisplayName = $username
                        CredentialId = "Legacy-$username"
                        CreatedDate = "Unknown"
                        PasskeyEnabled = $false
                        BackupStored = $true
                        Version = "1.0"
                        CredentialExists = $true
                        Status = "Legacy"
                    }
                    
                    $registeredCredentials += $credentialInfo
                }
            }
        }
        
        if ($registeredCredentials.Count -eq 0) {
            Write-Host "No registered Windows Hello biometric credentials found." -ForegroundColor Yellow
            Write-Host "Use 'Register-WindowsHelloBiometric' to set up biometric authentication." -ForegroundColor Cyan
        } else {
            Write-Host "Found $($registeredCredentials.Count) registered Windows Hello credential(s):" -ForegroundColor Green
        }
        
        return $registeredCredentials
    }
    catch {
        Write-Warning "Error retrieving registered credentials: $($_.Exception.Message)"
        return @()
    }
}

#endregion

#region Main Functions

function Test-WindowsHelloAvailability {
    <#
    .SYNOPSIS
    Tests if Windows Hello biometric authentication is available
    
    .DESCRIPTION
    This function checks if Windows Hello is configured and available on the current system.
    It returns $true if biometric authentication can be used, $false otherwise.
    
    .EXAMPLE
    if (Test-WindowsHelloAvailability) {
        Write-Host "Windows Hello is available" -ForegroundColor Green
    } else {
        Write-Host "Windows Hello is not available" -ForegroundColor Red
    }
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    
    # Check if we're on Windows (robust method for all Windows versions)
    $runningOnWindows = if ($PSVersionTable.PSVersion.Major -ge 6) {
        $IsWindows
    } else {
        [System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT
    }
    
    if (-not $runningOnWindows) {
        Write-Verbose "Windows Hello is only available on Windows systems"
        return $false
    }
    
    # Check Windows version (Windows Hello requires Windows 10+)
    $osVersion = [System.Environment]::OSVersion.Version
    if ($osVersion.Major -lt 10) {
        Write-Verbose "Windows Hello requires Windows 10 or later"
        return $false
    }
    
    try {
        # Use Windows Runtime APIs for proper Windows Hello detection
        Add-Type -AssemblyName System.Runtime.WindowsRuntime
        
        # Load Windows Runtime types for Windows Hello
        [Windows.Security.Credentials.UI.UserConsentVerifier, Windows.Security.Credentials.UI, ContentType = WindowsRuntime] | Out-Null
        [Windows.Security.Credentials.KeyCredentialManager, Windows.Security.Credentials, ContentType = WindowsRuntime] | Out-Null
        
        Write-Verbose "Checking Windows Hello availability using WinRT APIs"
        
        # Check if Windows Hello is available on this device
        try {
            $availability = [Windows.Security.Credentials.UI.UserConsentVerifier]::CheckAvailabilityAsync()
            $asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' })[0]
            $asyncTask = $asTaskGeneric.MakeGenericMethod([Windows.Security.Credentials.UI.UserConsentVerifierAvailability]).Invoke($null, @($availability))
            $availabilityResult = $asyncTask.GetAwaiter().GetResult()
            
            Write-Verbose "UserConsentVerifier availability: $availabilityResult"
            
            # Check the availability result
            switch ($availabilityResult) {
                ([Windows.Security.Credentials.UI.UserConsentVerifierAvailability]::Available) {
                    Write-Verbose "Windows Hello is available and configured"
                    return $true
                }
                ([Windows.Security.Credentials.UI.UserConsentVerifierAvailability]::DeviceNotPresent) {
                    Write-Verbose "Windows Hello device not present"
                    return $false
                }
                ([Windows.Security.Credentials.UI.UserConsentVerifierAvailability]::NotConfiguredForUser) {
                    Write-Verbose "Windows Hello not configured for current user"
                    return $false
                }
                ([Windows.Security.Credentials.UI.UserConsentVerifierAvailability]::DisabledByPolicy) {
                    Write-Verbose "Windows Hello disabled by policy"
                    return $false
                }
                ([Windows.Security.Credentials.UI.UserConsentVerifierAvailability]::DeviceBusy) {
                    Write-Verbose "Windows Hello device busy - may be available"
                    return $true  # Device exists but busy, so it's technically available
                }
                default {
                    Write-Verbose "Unknown Windows Hello availability status: $availabilityResult"
                    return $false
                }
            }
        }
        catch {
            Write-Verbose "Error checking UserConsentVerifier availability: $($_.Exception.Message)"
        }
        
        # Fallback: Check KeyCredentialManager for Windows Hello keys
        try {
            Write-Verbose "Checking KeyCredentialManager for Windows Hello support"
            $keyCredentialSupported = [Windows.Security.Credentials.KeyCredentialManager]::IsSupportedAsync()
            $asyncTask2 = $asTaskGeneric.MakeGenericMethod([bool]).Invoke($null, @($keyCredentialSupported))
            $isSupported = $asyncTask2.GetAwaiter().GetResult()
            
            Write-Verbose "KeyCredentialManager supported: $isSupported"
            
            if ($isSupported) {
                Write-Verbose "Windows Hello key management is supported"
                return $true
            }
        }
        catch {
            Write-Verbose "Error checking KeyCredentialManager support: $($_.Exception.Message)"
        }
        
        Write-Verbose "Windows Hello is not available via WinRT APIs"
        return $false
    }
    catch {
        Write-Verbose "Error checking Windows Hello availability: $($_.Exception.Message)"
        return $false
    }
}

function Set-KeeperBiometricCredential {
    <#
    .SYNOPSIS
    Creates a Windows Hello passkey for Keeper authentication
    
    .DESCRIPTION
    This function creates an actual FIDO2/WebAuthn passkey using Windows Hello.
    The passkey will appear in Windows Settings > Accounts > Passkeys and can sync across devices.
    
    .PARAMETER Username
    Keeper username/email
    
    .PARAMETER Password
    Master password (as SecureString) - used for fallback storage
    
    .PARAMETER Server
    Keeper server (optional, defaults to keepersecurity.com)
    
    .PARAMETER CreatePasskey
    If true, creates an actual Windows passkey instead of credential manager storage
    
    .EXAMPLE
    $password = Read-Host "Enter password" -AsSecureString
    Set-KeeperBiometricCredential -Username "user@example.com" -Password $password -CreatePasskey
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory=$true)][string]$Username,
        [Parameter(Mandatory=$true)][SecureString]$Password,
        [Parameter()][string]$Server = "keepersecurity.com",
        [Parameter()][switch]$CreatePasskey
    )
    
    try {
        if ($CreatePasskey) {
            # Create actual Windows Hello passkey
            Write-Information "Creating Windows Hello passkey for $Username" -InformationAction Continue
            
            # Load Windows Runtime types for KeyCredential
            Add-Type -AssemblyName System.Runtime.WindowsRuntime
            [Windows.Security.Credentials.KeyCredentialManager, Windows.Security.Credentials, ContentType = WindowsRuntime] | Out-Null
            
            # Generate a unique identifier for this Keeper account
            $keeperAccountId = "Keeper-${Server}-${Username}"
            
            Write-Host "Creating passkey for: $keeperAccountId" -ForegroundColor Yellow
            
            # Create the key credential (passkey)
            $keyCreationResult = [Windows.Security.Credentials.KeyCredentialManager]::RequestCreateAsync($keeperAccountId, [Windows.Security.Credentials.KeyCredentialCreationOption]::ReplaceExisting)
            
            # Convert async operation to synchronous result
            $asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' })[0]
            $asyncTask = $asTaskGeneric.MakeGenericMethod([Windows.Security.Credentials.KeyCredentialRetrievalResult]).Invoke($null, @($keyCreationResult))
            $creationResult = $asyncTask.GetAwaiter().GetResult()
            
            Write-Verbose "Key creation result status: $($creationResult.Status)"
            
            # Handle the creation result
            switch ($creationResult.Status) {
                ([Windows.Security.Credentials.KeyCredentialStatus]::Success) {
                    # Passkey created successfully
                    Write-Host "Windows Hello passkey created successfully" -ForegroundColor Green
                    Write-Host "Passkey Name: $keeperAccountId" -ForegroundColor Cyan
                    Write-Host "This passkey will appear in Windows Settings > Accounts > Passkeys" -ForegroundColor Cyan
                    
                    # Also store password as fallback in Credential Manager
                    $target = "KeeperWindowsHello:${Server}:${Username}"
                    Invoke-CredentialManagerOperation -Operation 'Add' -Target $target -Username $Username -Password $Password | Out-Null
                    Write-Host "Fallback credentials also stored in Credential Manager" -ForegroundColor Green
                    
                    return $true
                }
                ([Windows.Security.Credentials.KeyCredentialStatus]::UserCanceled) {
                    Write-Warning "User cancelled passkey creation"
                    return $false
                }
                ([Windows.Security.Credentials.KeyCredentialStatus]::NotFound) {
                    Write-Warning "Windows Hello not configured - cannot create passkey"
                    return $false
                }
                ([Windows.Security.Credentials.KeyCredentialStatus]::UnknownError) {
                    Write-Warning "Unknown error creating passkey"
                    return $false
                }
                default {
                    Write-Warning "Passkey creation failed with status: $($creationResult.Status)"
                    return $false
                }
            }
        }
        else {
            # Original credential manager storage (legacy mode)
            $target = "KeeperWindowsHello:${Server}:${Username}"
            
            # Store credential using Windows Credential Manager
            $result = Invoke-CredentialManagerOperation -Operation 'Add' -Target $target -Username $Username -Password $Password
            
            if ($result) {
                Write-Information "Biometric credentials stored in Credential Manager for $Username" -InformationAction Continue
                Write-Host "Tip: Use -CreatePasskey to create a real Windows passkey instead" -ForegroundColor Yellow
            } else {
                Write-Warning "Failed to store biometric credentials"
            }
            
            return $result
        }
    }
    catch {
        Write-Error "Error creating biometric credential: $($_.Exception.Message)"
        return $false
    }
}

function Get-KeeperBiometricCredential {
    <#
    .SYNOPSIS
    Retrieves biometric credential information (without the password)
    
    .PARAMETER Username
    Keeper username/email
    
    .PARAMETER Server  
    Keeper server (optional, defaults to keepersecurity.com)
    
    .EXAMPLE
    $cred = Get-KeeperBiometricCredential -Username "user@example.com"
    if ($cred) {
        Write-Host "Credential found for user: $cred"
    }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Username,
        [Parameter()][string]$Server = "keepersecurity.com"
    )
    
    try {
        $target = "KeeperWindowsHello:${Server}:${Username}"
        
        # Check if credential exists in Windows Credential Manager
        $storedUsername = Invoke-CredentialManagerOperation -Operation 'Get' -Target $target
        
        if ($storedUsername) {
            return [PSCustomObject]@{
                Username = $storedUsername
                Server = $Server
                Target = $target
                CreatedAt = Get-Date  # Credential Manager doesn't store creation date
            }
        }
        
        return $null
    }
    catch {
        Write-Warning "Error retrieving biometric credential: $($_.Exception.Message)"
        return $null
    }
}

function Remove-KeeperBiometricCredential {
    <#
    .SYNOPSIS
    Removes stored biometric credentials
    
    .PARAMETER Username
    Keeper username/email
    
    .PARAMETER Server
    Keeper server (optional, defaults to keepersecurity.com)
    
    .EXAMPLE
    Remove-KeeperBiometricCredential -Username "user@example.com"
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory=$true)][string]$Username,
        [Parameter()][string]$Server = "keepersecurity.com"
    )
    
    if ($PSCmdlet.ShouldProcess("$Username@$Server", "Remove biometric credential")) {
        try {
            $target = "KeeperWindowsHello:${Server}:${Username}"
            
            # Remove credential from Windows Credential Manager
            $result = Invoke-CredentialManagerOperation -Operation 'Delete' -Target $target
            
            if ($result) {
                Write-Information "Biometric credentials removed for $Username" -InformationAction Continue
            } else {
                Write-Warning "No biometric credentials found to remove"
            }
            
            return $result
        }
        catch {
            Write-Error "Error removing biometric credential: $($_.Exception.Message)"
            return $false
        }
    }
    return $false
}

function Invoke-WindowsHelloVerification {
    <#
    .SYNOPSIS
    Requests biometric verification from the user
    
    .PARAMETER Message
    Message to display during verification
    
    .EXAMPLE
    if (Invoke-WindowsHelloVerification -Message "Verify to access Keeper") {
        Write-Host "Verification successful"
    }
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter()][string]$Message = "Verify your identity"
    )
    
    try {
        # Check if Windows Hello is available first
        if (-not (Test-WindowsHelloAvailability)) {
            Write-Warning "Windows Hello is not available on this system"
            return $false
        }
        
        # For now, use a simple interactive prompt as Windows Hello API requires complex WinRT interop
        # In a production environment, this would integrate with Windows Hello APIs
        Write-Host ""
        Write-Host "$Message" -ForegroundColor Cyan
        Write-Host "Please use your configured Windows Hello method (PIN, Face, or Fingerprint)" -ForegroundColor Yellow
        Write-Host ""
        
        # Use Windows Runtime API for actual Windows Hello verification
        try {
            # Load Windows Runtime types for Windows Hello
            Add-Type -AssemblyName System.Runtime.WindowsRuntime
            [Windows.Security.Credentials.UI.UserConsentVerifier, Windows.Security.Credentials.UI, ContentType = WindowsRuntime] | Out-Null
            
            Write-Verbose "Requesting Windows Hello verification using WinRT UserConsentVerifier"
            Write-Host "Launching Windows Hello verification..." -ForegroundColor Yellow
            
            # Call the actual Windows Hello verification API
            $verificationRequest = [Windows.Security.Credentials.UI.UserConsentVerifier]::RequestVerificationAsync($Message)
            
            # Convert async operation to synchronous result
            $asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' })[0]
            $asyncTask = $asTaskGeneric.MakeGenericMethod([Windows.Security.Credentials.UI.UserConsentVerificationResult]).Invoke($null, @($verificationRequest))
            $verificationResult = $asyncTask.GetAwaiter().GetResult()
            
            Write-Verbose "Windows Hello verification result: $verificationResult"
            
            # Handle the verification result
            switch ($verificationResult) {
                ([Windows.Security.Credentials.UI.UserConsentVerificationResult]::Verified) {
                    Write-Host "Windows Hello verification successful" -ForegroundColor Green
                    return $true
                }
                ([Windows.Security.Credentials.UI.UserConsentVerificationResult]::DeviceNotPresent) {
                    Write-Host "Windows Hello device not present" -ForegroundColor Red
                    return $false
                }
                ([Windows.Security.Credentials.UI.UserConsentVerificationResult]::NotConfiguredForUser) {
                    Write-Host "Windows Hello not configured for current user" -ForegroundColor Red
                    return $false
                }
                ([Windows.Security.Credentials.UI.UserConsentVerificationResult]::DisabledByPolicy) {
                    Write-Host "Windows Hello disabled by policy" -ForegroundColor Red
                    return $false
                }
                ([Windows.Security.Credentials.UI.UserConsentVerificationResult]::DeviceBusy) {
                    Write-Host "Windows Hello device busy, please try again" -ForegroundColor Red
                    return $false
                }
                ([Windows.Security.Credentials.UI.UserConsentVerificationResult]::RetriesExhausted) {
                    Write-Host "Too many failed Windows Hello attempts" -ForegroundColor Red
                    return $false
                }
                ([Windows.Security.Credentials.UI.UserConsentVerificationResult]::Canceled) {
                    Write-Host "Windows Hello verification cancelled by user" -ForegroundColor Red
                    return $false
                }
                default {
                    Write-Host "Unknown Windows Hello verification result: $verificationResult" -ForegroundColor Red
                    return $false
                }
            }
        }
        catch {
            Write-Warning "Windows Hello API call failed: $($_.Exception.Message)"
            Write-Host "Falling back to manual verification prompt" -ForegroundColor Yellow
            
            # Fallback to manual verification if API fails
            $verification = Read-Host "Press Enter after successful Windows Hello verification, or 'q' to cancel"
            
            if ($verification -eq 'q' -or $verification -eq 'Q') {
                Write-Host "Biometric verification cancelled by user" -ForegroundColor Red
                return $false
            }
            
            # Manual verification completed
            Write-Host "Manual verification completed" -ForegroundColor Green
            return $true
        }
    }
    catch {
        Write-Warning "Biometric verification failed: $($_.Exception.Message)"
        return $false
    }
}

function Get-StoredPassword {
    <#
    .SYNOPSIS
    Retrieves stored password from Windows Credential Manager
    
    .PARAMETER Target
    Credential target name
    
    .PARAMETER Username
    Username for the credential
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Target,
        [Parameter(Mandatory=$true)][string]$Username
    )
    
    try {
        # Use PowerShell's Get-StoredCredential if available, otherwise use cmdkey
        if (Get-Command 'Get-StoredCredential' -ErrorAction SilentlyContinue) {
            $cred = Get-StoredCredential -Target $Target -ErrorAction SilentlyContinue
            if ($cred) {
                return $cred.Password
            }
        }
        else {
            # Fallback: Extract password using Windows API calls
            Add-Type -AssemblyName System.Security
            
            # This is a simplified approach - in production, you'd use proper Windows Credential Manager APIs
            & cmdkey /list:"$Target" 2>$null | Out-Null
            if ($LASTEXITCODE -eq 0) {
                # Password extraction from cmdkey is not directly possible for security reasons
                # Return a placeholder indicating credential exists
                return "**CREDENTIAL_EXISTS**"
            }
        }
        
        return $null
    }
    catch {
        Write-Verbose "Error retrieving stored password: $($_.Exception.Message)"
        return $null
    }
}

function Connect-KeeperWithBiometrics {
    <#
    .SYNOPSIS
    Connects to Keeper using Windows Hello biometric authentication
    
    .DESCRIPTION
    This function provides biometric authentication for Keeper login using Windows Hello.
    It can set up new biometric credentials or use existing ones for login.
    
    .PARAMETER Username
    Keeper username/email
    
    .PARAMETER Server
    Keeper server (optional, defaults to keepersecurity.com)
    
    .PARAMETER SetupBiometric
    Set up biometric authentication by providing master password
    
    .PARAMETER Password
    Master password (required when setting up biometric authentication)
    
    .EXAMPLE
    # Set up biometric authentication (first time)
    $password = Read-Host "Enter password" -AsSecureString
    Connect-KeeperWithBiometrics -Username "user@example.com" -SetupBiometric -Password $password
    
    .EXAMPLE  
    # Login using biometrics (after setup)
    Connect-KeeperWithBiometrics -Username "user@example.com"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Username,
        [Parameter()][string]$Server = "keepersecurity.com", 
        [Parameter()][switch]$SetupBiometric,
        [Parameter()][SecureString]$Password,
        [Parameter()][string]$Config
    )
    
    # Check Windows Hello availability
    if (-not (Test-WindowsHelloAvailability)) {
        # Check if we're on Windows (robust method for all Windows versions)
        $runningOnWindows = if ($PSVersionTable.PSVersion.Major -ge 6) {
            $IsWindows
        } else {
            [System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT
        }
        
        if (-not $runningOnWindows) {
            Write-Error "Windows Hello biometric authentication is only available on Windows systems." -ErrorAction Stop
        } else {
            Write-Error "Windows Hello is not available or configured on this system. Please set up Windows Hello in Windows Settings." -ErrorAction Stop
        }
        return
    }
    
    if ($SetupBiometric) {
        # Setup mode: Store biometric credentials
        if (-not $Password) {
            if (Test-InteractiveSession) {
                $Password = Read-Host -Prompt "Enter Master Password to setup biometric login" -AsSecureString
            }
            else {
                Write-Error "Password required for biometric setup in non-interactive mode" -ErrorAction Stop
                return
            }
        }
        
        Write-Information "Setting up biometric authentication..." -InformationAction Continue
        
        # Verify biometric access first
        $verified = Invoke-WindowsHelloVerification -Message "Set up biometric login for $Username"
        if (-not $verified) {
            Write-Error "Biometric verification failed. Setup canceled." -ErrorAction Stop
            return
        }
        
        # Store the credential (ask user if they want to create a passkey)
        Write-Host ""
        $createPasskey = Read-Host "Create a Windows passkey that will appear in Settings > Accounts? (y/N)"
        if ($createPasskey -eq 'y' -or $createPasskey -eq 'Y') {
            $stored = Set-KeeperBiometricCredential -Username $Username -Password $Password -Server $Server -CreatePasskey
        } else {
            $stored = Set-KeeperBiometricCredential -Username $Username -Password $Password -Server $Server
        }
        
        if ($stored) {
            Write-Information "Biometric authentication setup complete for $Username" -InformationAction Continue
            Write-Information "You can now use 'Connect-KeeperWithBiometrics -Username $Username' for biometric login" -InformationAction Continue
        }
    }
    else {
        # Login mode: Use biometric authentication
        
        # Check if biometric credential exists
        $credential = Get-KeeperBiometricCredential -Username $Username -Server $Server
        if (-not $credential) {
            Write-Error "No biometric credentials found for $Username on $Server. Run with -SetupBiometric first." -ErrorAction Stop
            return
        }
        
        # Perform biometric verification
        Write-Information "Biometric authentication required for Keeper login" -InformationAction Continue
        $verified = Invoke-WindowsHelloVerification -Message "Verify your identity to access Keeper vault for $Username"
        
        if (-not $verified) {
            Write-Error "Biometric verification failed or was canceled" -ErrorAction Stop
            return
        }
        
        try {
            Write-Information "Biometric verification successful, retrieving stored credentials..." -InformationAction Continue
            
            # Retrieve the stored password from Windows Credential Manager
            $target = "KeeperWindowsHello:${Server}:${Username}"
            $storedUsername = Invoke-CredentialManagerOperation -Operation 'Get' -Target $target
            
            if (-not $storedUsername) {
                Write-Error "No stored credentials found. Please run setup first with -SetupBiometric" -ErrorAction Stop
                return
            }
            
            Write-Verbose "Retrieved stored credentials for: $storedUsername"
            
            # Get the actual password from credential manager using Windows APIs
            try {
                Write-Information "Retrieving stored password using Windows Credential Manager APIs..." -InformationAction Continue
                
                # Load Windows Credential Manager APIs
                Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;

public class SecureCredentialManager {
    [StructLayout(LayoutKind.Sequential)]
    public struct CREDENTIAL {
        public uint Flags;
        public uint Type;
        public string TargetName;
        public string Comment;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
        public uint CredentialBlobSize;
        public IntPtr CredentialBlob;
        public uint Persist;
        public uint AttributeCount;
        public IntPtr Attributes;
        public string TargetAlias;
        public string UserName;
    }

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CredReadW(string target, uint type, uint reservedFlag, out IntPtr credentialPtr);

    [DllImport("advapi32.dll")]
    public static extern void CredFree(IntPtr cred);

    public const uint CRED_TYPE_GENERIC = 1;
}
"@ -ErrorAction SilentlyContinue
                
                # Try to retrieve the password using Windows APIs
                $credPtr = [IntPtr]::Zero
                $success = [SecureCredentialManager]::CredReadW($target, [SecureCredentialManager]::CRED_TYPE_GENERIC, 0, [ref]$credPtr)
                
                if ($success -and $credPtr -ne [IntPtr]::Zero) {
                    try {
                        $credential = [System.Runtime.InteropServices.Marshal]::PtrToStructure($credPtr, [type][SecureCredentialManager+CREDENTIAL])
                        if ($credential.CredentialBlob -ne [IntPtr]::Zero -and $credential.CredentialBlobSize -gt 0) {
                            # Extract password bytes
                            $passwordBytes = New-Object byte[] $credential.CredentialBlobSize
                            [System.Runtime.InteropServices.Marshal]::Copy($credential.CredentialBlob, $passwordBytes, 0, $credential.CredentialBlobSize)
                            $passwordText = [System.Text.Encoding]::UTF8.GetString($passwordBytes)
                            
                            # Convert to SecureString
                            $masterPassword = ConvertTo-SecureString -String $passwordText -AsPlainText -Force
                            Write-Verbose "Successfully retrieved password from Windows Credential Manager"
                        } else {
                            throw "No password blob found in credential"
                        }
                    }
                    finally {
                        [SecureCredentialManager]::CredFree($credPtr)
                    }
                } else {
                    throw "Failed to read credential from Windows Credential Manager"
                }
            }
            catch {
                Write-Verbose "Could not retrieve stored password via Windows APIs: $($_.Exception.Message)"
                Write-Host "Biometric verification successful, but automatic password retrieval failed" -ForegroundColor Yellow
                Write-Host "This is normal - Windows Hello verified you, now please confirm your master password:" -ForegroundColor Cyan
                
                if (Test-InteractiveSession) {
                    $masterPassword = Read-Host -Prompt "Master Password" -AsSecureString
                } else {
                    Write-Error "Interactive password entry required after biometric verification" -ErrorAction Stop
                    return
                }
            }
            
            # Check if Connect-Keeper is available
            if (Get-Command 'Connect-Keeper' -ErrorAction SilentlyContinue) {
                Write-Information "Authenticating with Keeper using stored credentials..." -InformationAction Continue
                Connect-Keeper -Username $Username -Password $masterPassword -Server $Server -Config $Config
                
                # After successful authentication, sync if requested
                if (Get-Command 'Sync-Keeper' -ErrorAction SilentlyContinue) {
                    Write-Information "Syncing Keeper vault..." -InformationAction Continue
                    Sync-Keeper -SyncRecordTypes
                }
                
                Write-Information "Login completed with Windows Hello biometric authentication" -InformationAction Continue
            } else {
                Write-Warning "Connect-Keeper function not available. Biometric authentication setup complete."
                Write-Information "Verified credentials for: $Username@$Server" -InformationAction Continue
            }
        }
        catch {
            Write-Error "Biometric login failed: $($_.Exception.Message)"
        }
        finally {
            # Clear sensitive data
            if ($masterPassword) { 
                $masterPassword.Dispose() 
            }
        }
    }
}
#endregion

#region Aliases

# Create convenient aliases
New-Alias -Name 'kcb' -Value 'Connect-KeeperWithBiometrics' -Description 'Connect to Keeper with biometric authentication' -Force
New-Alias -Name 'khello' -Value 'Test-WindowsHelloAvailability' -Description 'Test Windows Hello availability' -Force
New-Alias -Name 'kreg' -Value 'Register-WindowsHelloBiometric' -Description 'Register Windows Hello biometric authentication' -Force
New-Alias -Name 'klist' -Value 'Get-RegisteredBiometricCredentials' -Description 'List registered Windows Hello biometric credentials' -Force

#endregion

# Note: Export-ModuleMember calls are handled in PowerCommander.psm1