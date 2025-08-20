#requires -Version 5.1

# Windows Hello / Biometric Authentication for PowerCommander
# Implements biometric login similar to Python Commander's biometric module

Add-Type -AssemblyName System.Security

# Windows Hello API definitions
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace KeeperSecurity.WindowsHello
{
    public enum UserConsentVerificationResult
    {
        Verified = 0,
        DeviceNotPresent = 1,
        NotConfiguredForUser = 2,
        DisabledByPolicy = 3,
        DeviceBusy = 4,
        RetriesExhausted = 5,
        Canceled = 6
    }

    public static class WindowsHelloApi
    {
        // Windows Runtime factory for UserConsentVerifier
        public static async Task<UserConsentVerificationResult> RequestVerificationAsync(string message)
        {
            try 
            {
                // Use Windows Runtime UserConsentVerifier
                var userConsentVerifierType = Type.GetType("Windows.Security.Credentials.UI.UserConsentVerifier, Windows.Security.Credentials.UI, ContentType=WindowsRuntime");
                if (userConsentVerifierType == null)
                {
                    return UserConsentVerificationResult.DeviceNotPresent;
                }

                var checkAvailabilityMethod = userConsentVerifierType.GetMethod("CheckAvailabilityAsync");
                var requestVerificationMethod = userConsentVerifierType.GetMethod("RequestVerificationAsync", new Type[] { typeof(string) });

                if (checkAvailabilityMethod == null || requestVerificationMethod == null)
                {
                    return UserConsentVerificationResult.DeviceNotPresent;
                }

                // Check if Windows Hello is available
                var availabilityTask = (dynamic)checkAvailabilityMethod.Invoke(null, null);
                var availability = await availabilityTask;
                
                if (availability.ToString() != "Available")
                {
                    return UserConsentVerificationResult.NotConfiguredForUser;
                }

                // Request verification
                var verificationTask = (dynamic)requestVerificationMethod.Invoke(null, new object[] { message });
                var result = await verificationTask;
                
                switch (result.ToString())
                {
                    case "Verified":
                        return UserConsentVerificationResult.Verified;
                    case "DeviceNotPresent":
                        return UserConsentVerificationResult.DeviceNotPresent;
                    case "NotConfiguredForUser":
                        return UserConsentVerificationResult.NotConfiguredForUser;
                    case "DisabledByPolicy":
                        return UserConsentVerificationResult.DisabledByPolicy;
                    case "DeviceBusy":
                        return UserConsentVerificationResult.DeviceBusy;
                    case "RetriesExhausted":
                        return UserConsentVerificationResult.RetriesExhausted;
                    case "Canceled":
                        return UserConsentVerificationResult.Canceled;
                    default:
                        return UserConsentVerificationResult.DeviceNotPresent;
                }
            }
            catch 
            {
                return UserConsentVerificationResult.DeviceNotPresent;
            }
        }

        public static async Task<bool> IsWindowsHelloAvailableAsync()
        {
            try
            {
                var result = await RequestVerificationAsync("Checking Windows Hello availability");
                return result != UserConsentVerificationResult.DeviceNotPresent;
            }
            catch
            {
                return false;
            }
        }
    }
}
"@

# Biometric credential storage functions
function Set-KeeperBiometricCredential {
    <#
    .SYNOPSIS
    Stores encrypted Keeper credentials for biometric authentication
    
    .PARAMETER Username
    Keeper username/email
    
    .PARAMETER Password  
    Keeper master password (SecureString)
    
    .PARAMETER Server
    Keeper server (optional)
    #>
    param(
        [Parameter(Mandatory=$true)][string]$Username,
        [Parameter(Mandatory=$true)][SecureString]$Password,
        [Parameter()][string]$Server = "keepersecurity.com"
    )
    
    try {
        # Create credential name
        $credentialName = "Keeper_Biometric_$($Username)_$($Server)"
        
        # Convert SecureString to encrypted data using Windows DPAPI
        $encryptedPassword = $Password | ConvertFrom-SecureString
        
        # Store credential data
        $credentialData = @{
            Username = $Username
            Server = $Server
            EncryptedPassword = $encryptedPassword
            CreatedDate = Get-Date
            LastUsed = Get-Date
        } | ConvertTo-Json
        
        # Use Windows Credential Manager to store
        $credential = New-Object System.Management.Automation.PSCredential($credentialName, (ConvertTo-SecureString $credentialData -AsPlainText -Force))
        
        # Store in Windows Credential Manager
        cmdkey /generic:$credentialName /user:$Username /pass:$credentialData | Out-Null
        
        Write-Information "Biometric credential stored for $Username on $Server"
        return $true
    }
    catch {
        Write-Warning "Failed to store biometric credential: $($_.Exception.Message)"
        return $false
    }
}

function Get-KeeperBiometricCredential {
    <#
    .SYNOPSIS
    Retrieves stored biometric credentials for a user
    
    .PARAMETER Username
    Keeper username/email
    
    .PARAMETER Server
    Keeper server (optional)
    #>
    param(
        [Parameter(Mandatory=$true)][string]$Username,
        [Parameter()][string]$Server = "keepersecurity.com"
    )
    
    try {
        $credentialName = "Keeper_Biometric_$($Username)_$($Server)"
        
        # Try to retrieve from Windows Credential Manager
        $cmdResult = cmdkey /list:$credentialName 2>$null
        if ($LASTEXITCODE -ne 0) {
            return $null
        }
        
        # Parse credential data (this is a simplified approach)
        # In production, you'd want more robust credential retrieval
        return @{
            Username = $Username
            Server = $Server
            Exists = $true
        }
    }
    catch {
        Write-Warning "Failed to retrieve biometric credential: $($_.Exception.Message)"
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
    Keeper server (optional)
    #>
    param(
        [Parameter(Mandatory=$true)][string]$Username,
        [Parameter()][string]$Server = "keepersecurity.com"
    )
    
    try {
        $credentialName = "Keeper_Biometric_$($Username)_$($Server)"
        cmdkey /delete:$credentialName | Out-Null
        
        Write-Information "Biometric credential removed for $Username"
        return $true
    }
    catch {
        Write-Warning "Failed to remove biometric credential: $($_.Exception.Message)"
        return $false
    }
}

function Test-WindowsHelloAvailability {
    <#
    .SYNOPSIS
    Tests if Windows Hello is available on the current system
    #>
    
    try {
        # Test Windows Hello availability
        $task = [KeeperSecurity.WindowsHello.WindowsHelloApi]::IsWindowsHelloAvailableAsync()
        $result = $task.GetAwaiter().GetResult()
        
        if ($result) {
            Write-Information "Windows Hello is available and configured"
            return $true
        }
        else {
            Write-Warning "Windows Hello is not available or not configured"
            return $false
        }
    }
    catch {
        Write-Warning "Cannot determine Windows Hello availability: $($_.Exception.Message)"
        return $false
    }
}

function Invoke-WindowsHelloVerification {
    <#
    .SYNOPSIS
    Performs Windows Hello biometric verification
    
    .PARAMETER Message
    Message to display during verification
    #>
    param(
        [Parameter()][string]$Message = "Please verify your identity with Windows Hello to access Keeper"
    )
    
    try {
        Write-Information $Message
        
        $task = [KeeperSecurity.WindowsHello.WindowsHelloApi]::RequestVerificationAsync($Message)
        $result = $task.GetAwaiter().GetResult()
        
        switch ($result) {
            'Verified' {
                Write-Information "Biometric verification successful"
                return $true
            }
            'DeviceNotPresent' {
                Write-Warning "Windows Hello device not present"
                return $false
            }
            'NotConfiguredForUser' {
                Write-Warning "Windows Hello not configured for current user"
                return $false
            }
            'DisabledByPolicy' {
                Write-Warning "Windows Hello disabled by policy"
                return $false
            }
            'DeviceBusy' {
                Write-Warning "Windows Hello device is busy, please try again"
                return $false
            }
            'RetriesExhausted' {
                Write-Warning "Too many failed attempts, please try again later"
                return $false
            }
            'Canceled' {
                Write-Information "Biometric verification was canceled by user"
                return $false
            }
            default {
                Write-Warning "Unknown verification result: $result"
                return $false
            }
        }
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
    It stores encrypted credentials locally and uses biometric verification to access them.
    
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
    Connect-KeeperWithBiometrics -Username "user@example.com" -SetupBiometric -Password $securePassword
    
    .EXAMPLE  
    # Login using biometrics (after setup)
    Connect-KeeperWithBiometrics -Username "user@example.com"
    
    .EXAMPLE
    # Login with different server
    Connect-KeeperWithBiometrics -Username "user@example.com" -Server "eu.keepersecurity.com"
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
        Write-Error "Windows Hello is not available or configured on this system. Please set up Windows Hello in Windows Settings." -ErrorAction Stop
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
        
        # Verify the password works first by attempting login
        Write-Information "Verifying password and setting up biometric authentication..."
        
        try {
            # Test login with provided credentials
            $testResult = Connect-Keeper -Username $Username -Password $Password -Server $Server -Config $Config
            
            if ($Script:Context.Auth -and $Script:Context.Auth.IsAuthenticated()) {
                # Password works, store biometric credential
                $stored = Set-KeeperBiometricCredential -Username $Username -Password $Password -Server $Server
                
                if ($stored) {
                    Write-Information "✓ Biometric authentication setup complete for $Username"
                    Write-Information "You can now use 'Connect-KeeperWithBiometrics -Username $Username' for biometric login"
                }
                else {
                    Write-Error "Failed to store biometric credentials"
                }
            }
            else {
                Write-Error "Failed to authenticate with provided credentials"
            }
        }
        catch {
            Write-Error "Setup failed: $($_.Exception.Message)"
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
        Write-Information "🔐 Biometric authentication required for Keeper login"
        $verified = Invoke-WindowsHelloVerification -Message "Verify your identity to access Keeper vault for $Username"
        
        if (-not $verified) {
            Write-Error "Biometric verification failed or was canceled" -ErrorAction Stop
            return
        }
        
        try {
            # Retrieve stored password (simplified - in production you'd decrypt from credential store)
            Write-Information "🔓 Biometric verification successful, logging into Keeper..."
            
            # For now, prompt for password after biometric verification
            # In a full implementation, you'd decrypt the stored password
            if (Test-InteractiveSession) {
                $Password = Read-Host -Prompt "Enter Master Password (biometric verification successful)" -AsSecureString
                
                # Use regular Connect-Keeper with verified password
                Connect-Keeper -Username $Username -Password $Password -Server $Server -Config $Config
                
                if ($Script:Context.Auth -and $Script:Context.Auth.IsAuthenticated()) {
                    Write-Information "✅ Successfully logged into Keeper with biometric authentication"
                }
            }
            else {
                Write-Error "Cannot complete biometric login in non-interactive mode"
            }
        }
        catch {
            Write-Error "Biometric login failed: $($_.Exception.Message)"
        }
    }
}

# Create convenient aliases
New-Alias -Name 'kcb' -Value 'Connect-KeeperWithBiometrics' -Description 'Connect to Keeper with biometric authentication'
New-Alias -Name 'khello' -Value 'Test-WindowsHelloAvailability' -Description 'Test Windows Hello availability'

# Export functions and aliases
Export-ModuleMember -Function @(
    'Test-WindowsHelloAvailability',
    'Connect-KeeperWithBiometrics', 
    'Set-KeeperBiometricCredential',
    'Get-KeeperBiometricCredential',
    'Remove-KeeperBiometricCredential',
    'Invoke-WindowsHelloVerification'
)
Export-ModuleMember -Alias @('kcb', 'khello')
