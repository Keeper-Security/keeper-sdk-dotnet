# Windows Hello Biometric Authentication for PowerCommander

This module provides Windows Hello biometric authentication support for PowerCommander, similar to the [Python Commander biometric implementation](https://github.com/Keeper-Security/Commander/blob/master/keepercommander/biometric/README.md).

## Overview

Windows Hello biometric authentication allows you to log into your Keeper vault using:
- **Fingerprint readers** - Touch or swipe fingerprint sensors
- **Face recognition** - Windows Hello compatible cameras with infrared
- **PIN authentication** - As a fallback biometric method
- **Security keys** - FIDO2/WebAuthn compatible hardware keys

This eliminates the need to type your master password each time while maintaining strong security through biometric verification.

## Prerequisites

1. **Windows 10 version 1903 or later** with Windows Hello enabled
2. **PowerShell 5.1 or later**
3. **Compatible biometric hardware**:
   - Fingerprint reader
   - Windows Hello compatible camera with IR
   - PIN setup as fallback
4. **PowerCommander module** installed and working

## Setup

### 1. Check Windows Hello Availability

First, verify that Windows Hello is available and configured on your system:

```powershell
# Import the module
Import-Module PowerCommander

# Check if Windows Hello is available
Test-WindowsHelloAvailability
```

### 2. Enable Biometric Authentication for Your Account

Set up biometric authentication for your Keeper account:

```powershell
# Set up biometric login (first time setup)
Connect-KeeperWithBiometrics -Username "your.email@company.com" -SetupBiometric

# You'll be prompted for your master password to verify and store credentials
```

For different Keeper servers:

```powershell
# EU server example
Connect-KeeperWithBiometrics -Username "your.email@company.com" -SetupBiometric -Server "eu.keepersecurity.com"

# Custom server
Connect-KeeperWithBiometrics -Username "your.email@company.com" -SetupBiometric -Server "your-custom-server.com"
```

### 3. Using Biometric Authentication

After setup, log in using biometric authentication:

```powershell
# Login with biometrics (Windows Hello prompt will appear)
Connect-KeeperWithBiometrics -Username "your.email@company.com"

# With custom server
Connect-KeeperWithBiometrics -Username "your.email@company.com" -Server "eu.keepersecurity.com"
```

## Usage Examples

### Basic Setup and Login

```powershell
# 1. First-time setup with biometric authentication
Connect-KeeperWithBiometrics -Username "john.doe@example.com" -SetupBiometric

# Enter your master password when prompted
# Windows Hello will verify your biometrics to encrypt and store the credentials

# 2. Subsequent logins using biometrics
Connect-KeeperWithBiometrics -Username "john.doe@example.com"

# Windows Hello biometric prompt appears
# Upon successful verification, you're logged into Keeper
```

### Advanced Configuration

```powershell
# Setup with custom configuration file
Connect-KeeperWithBiometrics -Username "user@company.com" -SetupBiometric -Config "C:\MyConfig\keeper.json"

# Login with custom configuration
Connect-KeeperWithBiometrics -Username "user@company.com" -Config "C:\MyConfig\keeper.json"

# Check stored biometric credentials
Get-KeeperBiometricCredential -Username "user@company.com"

# Remove biometric credentials
Remove-KeeperBiometricCredential -Username "user@company.com"
```

### Enterprise/Team Usage

```powershell
# Setup for multiple team members
$teamMembers = @("alice@company.com", "bob@company.com", "charlie@company.com")

foreach ($user in $teamMembers) {
    Write-Host "Setting up biometric auth for $user"
    Connect-KeeperWithBiometrics -Username $user -SetupBiometric -Server "company.keepersecurity.com"
    Disconnect-Keeper
}

# Login script for team environments
$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$keeperUsername = "$($env:USERNAME)@company.com"

if (Test-WindowsHelloAvailability) {
    Connect-KeeperWithBiometrics -Username $keeperUsername -Server "company.keepersecurity.com"
} else {
    Write-Warning "Windows Hello not available, falling back to regular login"
    Connect-Keeper -Username $keeperUsername
}
```

## Security Features

### Credential Protection
- **DPAPI Encryption**: Master passwords are encrypted using Windows Data Protection API
- **User-Specific**: Encrypted credentials are tied to the specific Windows user account
- **Machine-Specific**: Credentials cannot be transferred to other machines
- **Biometric Verification**: Access requires successful biometric authentication

### Authentication Flow
1. **Setup Phase**: Master password is encrypted and stored locally after biometric verification
2. **Login Phase**: Windows Hello biometric verification unlocks stored credentials
3. **Session Management**: Standard Keeper session management applies after authentication

### Fallback Options
- If biometric authentication fails, you can still use regular `Connect-Keeper`
- PIN authentication available as Windows Hello fallback
- Master password entry remains available

## Troubleshooting

### Common Issues

#### "Windows Hello is not available or configured"
```powershell
# Check Windows Hello status
Test-WindowsHelloAvailability

# If false, set up Windows Hello in Windows Settings:
# Settings > Accounts > Sign-in options > Windows Hello
```

#### "No biometric credentials found"
```powershell
# Re-run setup for the user
Connect-KeeperWithBiometrics -Username "your.email@company.com" -SetupBiometric
```

#### "Biometric verification failed"
- Ensure your fingerprint reader or camera is clean and unobstructed
- Try using PIN authentication through Windows Hello
- Restart and try again
- Check Windows Hello settings in Windows Settings

#### "Device not present" errors
- Verify biometric hardware is properly connected
- Update biometric device drivers
- Test Windows Hello with Windows sign-in first

### Debug Information

Enable verbose logging:

```powershell
# Enable information stream
$InformationPreference = 'Continue'

# Run biometric commands to see detailed output
Test-WindowsHelloAvailability
Connect-KeeperWithBiometrics -Username "user@example.com"
```

## Comparison with Python Implementation

This PowerShell implementation provides similar functionality to the [Python Commander biometric module](https://github.com/Keeper-Security/Commander/blob/master/keepercommander/biometric/README.md):

| Feature | Python Commander | PowerCommander (Windows Hello) |
|---------|------------------|--------------------------------|
| Biometric Storage | ✅ | ✅ |
| Fingerprint Auth | ✅ | ✅ |
| Face Recognition | ✅ (platform dependent) | ✅ (Windows Hello) |
| PIN Fallback | ✅ | ✅ |
| Security Key Support | ✅ | ✅ (via Windows Hello) |
| Cross-Platform | ✅ (macOS, Linux, Windows) | ❌ (Windows only) |
| Native Integration | Platform specific | ✅ (Windows Hello) |
| Enterprise Features | ✅ | ✅ |

## API Reference

### Functions

#### `Connect-KeeperWithBiometrics`
Main function for biometric authentication and setup.

**Parameters:**
- `Username` (required): Keeper account email
- `Server` (optional): Keeper server URL (default: "keepersecurity.com")
- `SetupBiometric` (switch): Set up biometric authentication
- `Password` (SecureString): Master password for setup
- `Config` (optional): Custom configuration file path

#### `Test-WindowsHelloAvailability`
Tests if Windows Hello is available and configured.

**Returns:** Boolean indicating availability

#### `Set-KeeperBiometricCredential`
Stores encrypted biometric credentials.

#### `Get-KeeperBiometricCredential`
Retrieves information about stored biometric credentials.

#### `Remove-KeeperBiometricCredential`
Removes stored biometric credentials.

### Examples Integration

```powershell
# Check if biometric login is possible
if (Test-WindowsHelloAvailability) {
    $credential = Get-KeeperBiometricCredential -Username "user@example.com"
    if ($credential) {
        # Biometric login available
        Connect-KeeperWithBiometrics -Username "user@example.com"
    } else {
        # Setup required
        Write-Host "Biometric authentication not set up. Run setup first:"
        Write-Host "Connect-KeeperWithBiometrics -Username 'user@example.com' -SetupBiometric"
    }
} else {
    # Fall back to regular authentication
    Connect-Keeper -Username "user@example.com"
}
```

## Requirements

- Windows 10 version 1903+ or Windows 11
- PowerShell 5.1+
- Windows Hello configured with at least one biometric method or PIN
- PowerCommander module
- .NET Framework 4.7.2+ (for full Windows Hello API support)

## License

This Windows Hello implementation follows the same license as PowerCommander and the Keeper SDK.
