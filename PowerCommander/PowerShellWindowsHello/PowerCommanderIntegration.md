# PowerCommander Integration Guide

This guide shows exactly how to integrate the PowerShell Windows Hello functionality into PowerCommander using the unified interface.

## Single Function Interface

The entire Windows Hello functionality is exposed through one function: **`Invoke-WindowsHelloOperation`**

## Quick Integration

### 1. Import the Module

```powershell
# Add this to your PowerCommander module startup
try {
    . "$PSScriptRoot\PowerShellWindowsHello\PowerShellIntegration.ps1"
    $WindowsHelloSupported = $true
} catch {
    Write-Verbose "Windows Hello not available: $($_.Exception.Message)"
    $WindowsHelloSupported = $false
}
```

### 2. Test Availability

```powershell
function Test-WindowsHelloAvailable {
    if (-not $WindowsHelloSupported) { return $false }
    
    $result = Invoke-WindowsHelloOperation -Operation "Status" -Quiet
    return $result.Success -and $result.Data.CanAuthenticate
}
```

### 3. Perform Authentication

```powershell
function Invoke-KeeperWindowsHelloAuth {
    param(
        [string]$Username,
        [byte[]]$Challenge,
        [string]$Server = "keepersecurity.com"
    )
    
    if (-not $WindowsHelloSupported) {
        throw "Windows Hello not available"
    }
    
    $result = Invoke-WindowsHelloOperation -Operation "Authenticate" -Challenge $Challenge -Username $Username -RpId $Server
    
    if ($result.Success) {
        # Return WebAuthn assertion data in the format Keeper expects
        return @{
            CredentialId = $result.Data.CredentialId          # Base64 encoded
            Signature = $result.Data.Signature                # Base64 encoded
            AuthenticatorData = $result.Data.AuthenticatorData # Base64 encoded
            ClientDataJSON = $result.Data.ClientDataJSON      # Base64 encoded
            UserHandle = $result.Data.UserHandle              # Base64 encoded (optional)
        }
    } else {
        throw "Windows Hello authentication failed: $($result.ErrorMessage)"
    }
}
```

## Complete Integration Example

Here's a complete example of how PowerCommander could integrate Windows Hello:

```powershell
# Enhanced Connect-Keeper function with Windows Hello support
function Connect-Keeper {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Username,
        [Parameter()][string]$Server = "keepersecurity.com",
        [Parameter()][switch]$UseWindowsHello,
        [Parameter()][securestring]$Password
    )
    
    # Auto-detect Windows Hello if not explicitly specified
    if (-not $UseWindowsHello -and -not $Password) {
        if (Test-WindowsHelloAvailable) {
            $UseWindowsHello = $true
            Write-Host "Windows Hello detected and available - using biometric authentication" -ForegroundColor Green
        }
    }
    
    if ($UseWindowsHello) {
        try {
            # Step 1: Start Keeper authentication flow to get challenge
            $authFlow = Start-KeeperAuthFlow -Username $Username -Server $Server
            $challenge = $authFlow.GetWebAuthnChallenge()
            
            # Step 2: Use Windows Hello for authentication
            Write-Host "Please complete Windows Hello verification..." -ForegroundColor Yellow
            $webAuthnResult = Invoke-KeeperWindowsHelloAuth -Username $Username -Challenge $challenge -Server $Server
            
            # Step 3: Complete Keeper authentication with WebAuthn assertion
            $authFlow.CompleteWebAuthnAuthentication($webAuthnResult)
            
            Write-Host "- Successfully authenticated with Windows Hello!" -ForegroundColor Green
            return $authFlow
            
        } catch {
            Write-Warning "Windows Hello authentication failed: $($_.Exception.Message)"
            Write-Host "Falling back to password authentication..." -ForegroundColor Yellow
            
            # Fall back to regular password authentication
            if (-not $Password) {
                $Password = Read-Host "Enter your master password" -AsSecureString
            }
        }
    }
    
    # Regular password authentication (fallback or explicit)
    if ($Password) {
        return Connect-KeeperWithPassword -Username $Username -Server $Server -Password $Password
    } else {
        throw "No authentication method available"
    }
}

# Helper function for capability detection
function Get-KeeperAuthCapabilities {
    $capabilities = @{
        PasswordAuth = $true
        WindowsHello = $false
        WindowsHelloDetails = $null
    }
    
    if ($WindowsHelloSupported) {
        $result = Invoke-WindowsHelloOperation -Operation "Info" -Quiet
        $capabilities.WindowsHello = $result.Success
        $capabilities.WindowsHelloDetails = $result.Data
    }
    
    return $capabilities
}

# Enhanced user experience function
function Show-KeeperAuthOptions {
    param([string]$Username)
    
    $caps = Get-KeeperAuthCapabilities
    
    Write-Host "Available authentication methods for $Username:" -ForegroundColor Yellow
    Write-Host "1. Password authentication" -ForegroundColor Cyan
    
    if ($caps.WindowsHello) {
        Write-Host "2. Windows Hello (biometric)" -ForegroundColor Green
        Write-Host "   Platform: $($caps.WindowsHelloDetails.Platform)" -ForegroundColor Gray
        Write-Host "   Methods: $($caps.WindowsHelloDetails.SupportedMethods -join ', ')" -ForegroundColor Gray
    } else {
        Write-Host "2. Windows Hello (not available)" -ForegroundColor DarkGray
    }
    
    Write-Host ""
}
```

## API Reference

### Operations

#### `"Status"` - Quick Availability Check
```powershell
$result = Invoke-WindowsHelloOperation -Operation "Status" -Quiet
# Returns: Success (bool), Data.IsAvailable (bool), Data.Status (string)
```

#### `"Test"` - Comprehensive Capability Test  
```powershell
$result = Invoke-WindowsHelloOperation -Operation "Test" -Quiet
# Returns: Success (bool), Data.* (comprehensive capability info)
```

#### `"Info"` - Detailed Information
```powershell
$result = Invoke-WindowsHelloOperation -Operation "Info"
# Returns: Success (bool), Data.* (detailed system information)
```

#### `"Authenticate"` - Perform Authentication
```powershell
$result = Invoke-WindowsHelloOperation -Operation "Authenticate" -Challenge $bytes -Username $user
# Returns: Success (bool), Data.CredentialId, Data.Signature, etc.
```

### Return Format

All operations return a consistent format:

```powershell
@{
    Success = $true/$false           # Operation success indicator
    Operation = "Test"/"Status"/etc  # Operation that was performed
    Data = @{ ... }                 # Operation-specific data (null on failure)
    ErrorMessage = "..."            # Error description (null on success)
    ErrorType = "..."               # Error type classification
    Timestamp = [DateTime]          # When the operation was performed
}
```

## Error Handling

```powershell
function Safe-WindowsHelloAuth {
    param([string]$Username, [byte[]]$Challenge)
    
    try {
        $result = Invoke-WindowsHelloOperation -Operation "Authenticate" -Challenge $Challenge -Username $Username
        
        if ($result.Success) {
            return $result.Data
        } else {
            Write-Warning "Windows Hello failed: $($result.ErrorMessage)"
            return $null
        }
    }
    catch {
        Write-Error "Windows Hello exception: $($_.Exception.Message)"
        return $null
    }
}
```

## Best Practices

1. **Always check availability first**:
   ```powershell
   if ((Invoke-WindowsHelloOperation -Operation "Status" -Quiet).Success) {
       # Use Windows Hello
   }
   ```

2. **Provide fallback options**:
   ```powershell
   try {
       $result = Invoke-WindowsHelloOperation -Operation "Authenticate" -Challenge $challenge
   } catch {
       # Fall back to password
   }
   ```

3. **Use -Quiet for programmatic checks**:
   ```powershell
   $status = Invoke-WindowsHelloOperation -Operation "Status" -Quiet
   ```

4. **Handle timeouts gracefully**:
   ```powershell
   $result = Invoke-WindowsHelloOperation -Operation "Authenticate" -Challenge $challenge -TimeoutMs 30000
   ```

## Deployment

1. **Build the project**: `dotnet build PowerCommander\PowerShellWindowsHello\`
2. **Include in PowerCommander**: Copy the `PowerShellWindowsHello` folder
3. **Import in module**: Add the import code to PowerCommander startup
4. **Test integration**: Use the examples to verify functionality

## Troubleshooting

### Assembly Not Found
```powershell
# Check if assembly exists
Test-Path "$PSScriptRoot\PowerShellWindowsHello\bin\Debug\net472\PowerShellWindowsHello.dll"
```

### Windows Hello Not Available
```powershell
# Get detailed error information
$result = Invoke-WindowsHelloOperation -Operation "Info"
Write-Host "Error: $($result.ErrorMessage)"
```

### Authentication Failures
```powershell
# Use verbose output for debugging
$result = Invoke-WindowsHelloOperation -Operation "Authenticate" -Challenge $challenge -Verbose
```

This integration approach gives PowerCommander a clean, single-function interface to all Windows Hello functionality while maintaining backward compatibility and providing comprehensive error handling.
