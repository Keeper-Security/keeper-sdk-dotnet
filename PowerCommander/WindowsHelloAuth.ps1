#requires -Version 5.1

# Windows Hello / Biometric Authentication for PowerCommander
# This module provides a PowerShell wrapper for the Windows Hello functionality in KeeperSdk

# Load the KeeperSdk assembly
Add-Type -Path "$PSScriptRoot\KeeperSdk.dll"

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
    
    # Check if we're on Windows
    if (-not $IsWindows) {
        Write-Verbose "Windows Hello is only available on Windows systems"
        return $false
    }
    
    try {
        # Check if the WindowsHelloProvider class is available (requires .NET Framework 4.7.2+)
        $providerType = [KeeperSecurity.Authentication.WindowsHelloProvider] -as [type]
        if (-not $providerType) {
            Write-Verbose "Windows Hello provider not available - requires .NET Framework 4.7.2+ build"
            return $false
        }
        
        # Use SDK method to check availability
        $task = [KeeperSecurity.Authentication.WindowsHelloProvider]::IsAvailableAsync()
        $result = $task.GetAwaiter().GetResult()
        return $result
    }
    catch {
        Write-Verbose "Error checking Windows Hello availability: $($_.Exception.Message)"
        return $false
    }
}

function Set-KeeperBiometricCredential {
    <#
    .SYNOPSIS
    Stores biometric credentials for a Keeper user
    
    .DESCRIPTION
    This function stores encrypted credentials for biometric authentication.
    The credentials are encrypted using Windows DPAPI and stored securely.
    
    .PARAMETER Username
    Keeper username/email
    
    .PARAMETER Password
    Master password (as SecureString)
    
    .PARAMETER Server
    Keeper server (optional, defaults to keepersecurity.com)
    
    .EXAMPLE
    $password = Read-Host "Enter password" -AsSecureString
    Set-KeeperBiometricCredential -Username "user@example.com" -Password $password
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory=$true)][string]$Username,
        [Parameter(Mandatory=$true)][SecureString]$Password,
        [Parameter()][string]$Server = "keepersecurity.com"
    )
    
    try {
        # Convert SecureString to plain text for storage
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
        $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        
        # Store using SDK method
        $result = [KeeperSecurity.Authentication.WindowsHelloProvider]::StoreBiometricCredential($Username, $plainPassword, $Server)
        
        if ($result) {
            Write-Information "✓ Biometric credentials stored for $Username" -InformationAction Continue
        } else {
            Write-Warning "Failed to store biometric credentials"
        }
        
        return $result
    }
    catch {
        Write-Error "Error storing biometric credential: $($_.Exception.Message)"
        return $false
    }
    finally {
        # Clear password from memory
        if ($plainPassword) {
            $plainPassword = $null
        }
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
        Write-Host "Credential found, created: $($cred.CreatedAt)"
    }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Username,
        [Parameter()][string]$Server = "keepersecurity.com"
    )
    
    try {
        $credential = [KeeperSecurity.Authentication.WindowsHelloProvider]::GetBiometricCredential($Username, $Server)
        return $credential
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
            $result = [KeeperSecurity.Authentication.WindowsHelloProvider]::RemoveBiometricCredential($Username, $Server)
            if ($result) {
                Write-Information "✓ Biometric credentials removed for $Username" -InformationAction Continue
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
        $task = [KeeperSecurity.Authentication.WindowsHelloProvider]::RequestVerificationAsync($Message, $true)
        $result = $task.GetAwaiter().GetResult()
        
        return ($result -eq [KeeperSecurity.Authentication.BiometricVerificationResult]::Verified)
    }
    catch {
        Write-Warning "Biometric verification failed: $($_.Exception.Message)"
        return $false
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
        if (-not $IsWindows) {
            Write-Error "Windows Hello biometric authentication is only available on Windows systems." -ErrorAction Stop
        } else {
            Write-Error "Windows Hello is not available or configured on this system. Please set up Windows Hello in Windows Settings, or use the .NET Framework 4.7.2+ build of PowerCommander." -ErrorAction Stop
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
        
        # Store the credential
        $stored = Set-KeeperBiometricCredential -Username $Username -Password $Password -Server $Server
        
        if ($stored) {
            Write-Information "✅ Biometric authentication setup complete for $Username" -InformationAction Continue
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
        Write-Information "🔐 Biometric authentication required for Keeper login" -InformationAction Continue
        $verified = Invoke-WindowsHelloVerification -Message "Verify your identity to access Keeper vault for $Username"
        
        if (-not $verified) {
            Write-Error "Biometric verification failed or was canceled" -ErrorAction Stop
            return
        }
        
        try {
            # Decrypt stored password
            Write-Information "🔓 Biometric verification successful, logging into Keeper..." -InformationAction Continue
            
            $plainPassword = [KeeperSecurity.Authentication.WindowsHelloProvider]::DecryptPassword($credential)
            if (-not $plainPassword) {
                Write-Error "Failed to decrypt stored password. Please set up biometric authentication again." -ErrorAction Stop
                return
            }
            
            # Convert to SecureString
            $securePassword = ConvertTo-SecureString -String $plainPassword -AsPlainText -Force
            $plainPassword = $null # Clear from memory
            
            # Check if Connect-Keeper is available
            if (Get-Command 'Connect-Keeper' -ErrorAction SilentlyContinue) {
                Connect-Keeper -Username $Username -Password $securePassword -Server $Server -Config $Config
                
                if ((Get-Variable -Name 'Context' -Scope Script -ErrorAction SilentlyContinue) -and 
                    $Script:Context.Auth -and $Script:Context.Auth.IsAuthenticated()) {
                    Write-Information "✅ Successfully logged into Keeper with biometric authentication" -InformationAction Continue
                }
            } else {
                Write-Error "Connect-Keeper function not available. Please import the full PowerCommander module first."
            }
        }
        catch {
            Write-Error "Biometric login failed: $($_.Exception.Message)"
        }
        finally {
            # Clear sensitive data
            if ($securePassword) { $securePassword.Dispose() }
            if ($plainPassword) { $plainPassword = $null }
        }
    }
}

#endregion

#region Aliases

# Create convenient aliases
New-Alias -Name 'kcb' -Value 'Connect-KeeperWithBiometrics' -Description 'Connect to Keeper with biometric authentication' -Force
New-Alias -Name 'khello' -Value 'Test-WindowsHelloAvailability' -Description 'Test Windows Hello availability' -Force

#endregion

# Note: Export-ModuleMember calls are handled in PowerCommander.psm1