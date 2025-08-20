# Test script for Windows Hello biometric authentication in PowerCommander
# This script demonstrates and tests the Windows Hello functionality

[CmdletBinding()]
param(
    [Parameter()][string]$TestUsername = "test.user@example.com",
    [Parameter()][switch]$SkipInteractive,
    [Parameter()][switch]$CleanupOnly
)

Write-Host "=" * 60
Write-Host "Windows Hello Biometric Authentication Test for PowerCommander"
Write-Host "=" * 60
Write-Host ""

# Import the module (assuming we're in the PowerCommander directory)
try {
    Import-Module .\PowerCommander.psd1 -Force
    Write-Host "✓ PowerCommander module loaded successfully" -ForegroundColor Green
} catch {
    Write-Error "Failed to load PowerCommander module: $($_.Exception.Message)"
    exit 1
}

# Cleanup function
function Cleanup-TestCredentials {
    param([string]$Username)
    
    Write-Host "Cleaning up test credentials for $Username..." -ForegroundColor Yellow
    try {
        Remove-KeeperBiometricCredential -Username $Username
        Write-Host "✓ Test credentials cleaned up" -ForegroundColor Green
    } catch {
        Write-Warning "Could not clean up credentials: $($_.Exception.Message)"
    }
}

# If cleanup only, do cleanup and exit
if ($CleanupOnly) {
    Cleanup-TestCredentials -Username $TestUsername
    Write-Host "Cleanup complete." -ForegroundColor Green
    exit 0
}

Write-Host "Testing Windows Hello availability..." -ForegroundColor Cyan

# Test 1: Windows Hello Availability
try {
    $helloAvailable = Test-WindowsHelloAvailability
    if ($helloAvailable) {
        Write-Host "✓ Windows Hello is available and configured" -ForegroundColor Green
    } else {
        Write-Host "❌ Windows Hello is not available or not configured" -ForegroundColor Red
        Write-Host "Please set up Windows Hello in Windows Settings > Accounts > Sign-in options" -ForegroundColor Yellow
        exit 1
    }
} catch {
    Write-Host "❌ Error checking Windows Hello availability: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "Testing biometric verification..." -ForegroundColor Cyan

# Test 2: Biometric Verification (without login)
if (-not $SkipInteractive) {
    try {
        Write-Host "This will test Windows Hello biometric verification (no login)..."
        $verified = Invoke-WindowsHelloVerification -Message "PowerCommander Windows Hello Test - Please verify your identity"
        
        if ($verified) {
            Write-Host "✓ Biometric verification successful" -ForegroundColor Green
        } else {
            Write-Host "❌ Biometric verification failed or was canceled" -ForegroundColor Red
            Write-Host "Please ensure your biometric device is working and try again" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "❌ Error during biometric verification: $($_.Exception.Message)" -ForegroundColor Red
    }
} else {
    Write-Host "Skipping interactive biometric verification test..." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Testing credential management..." -ForegroundColor Cyan

# Test 3: Credential Storage (mock test)
try {
    # Test storing a mock credential
    $mockPassword = ConvertTo-SecureString "TestPassword123!" -AsPlainText -Force
    $stored = Set-KeeperBiometricCredential -Username $TestUsername -Password $mockPassword -Server "test.keepersecurity.com"
    
    if ($stored) {
        Write-Host "✓ Mock biometric credential storage successful" -ForegroundColor Green
        
        # Test retrieving the credential
        $retrieved = Get-KeeperBiometricCredential -Username $TestUsername -Server "test.keepersecurity.com"
        if ($retrieved) {
            Write-Host "✓ Mock biometric credential retrieval successful" -ForegroundColor Green
        } else {
            Write-Host "❌ Failed to retrieve stored credential" -ForegroundColor Red
        }
        
        # Cleanup test credential
        Cleanup-TestCredentials -Username $TestUsername
    } else {
        Write-Host "❌ Failed to store mock biometric credential" -ForegroundColor Red
    }
} catch {
    Write-Host "❌ Error testing credential management: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host ""
Write-Host "Testing Windows Hello API integration..." -ForegroundColor Cyan

# Test 4: Windows Hello API Access
try {
    # Test if we can access Windows Hello APIs
    Add-Type -TypeDefinition @"
using System;
using System.Threading.Tasks;

namespace Test.WindowsHello
{
    public static class ApiTest
    {
        public static bool TestApiAccess()
        {
            try 
            {
                var type = Type.GetType("Windows.Security.Credentials.UI.UserConsentVerifier, Windows.Security.Credentials.UI, ContentType=WindowsRuntime");
                return type != null;
            }
            catch 
            {
                return false;
            }
        }
    }
}
"@
    
    $apiAccessible = [Test.WindowsHello.ApiTest]::TestApiAccess()
    if ($apiAccessible) {
        Write-Host "✓ Windows Hello API is accessible" -ForegroundColor Green
    } else {
        Write-Host "❌ Windows Hello API is not accessible" -ForegroundColor Red
        Write-Host "This may indicate Windows Runtime issues or missing Windows Hello support" -ForegroundColor Yellow
    }
} catch {
    Write-Host "❌ Error testing Windows Hello API access: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host ""
Write-Host "=" * 60
Write-Host "Test Summary"
Write-Host "=" * 60

Write-Host "System Information:" -ForegroundColor Cyan
Write-Host "  OS Version: $([System.Environment]::OSVersion.VersionString)"
Write-Host "  PowerShell Version: $($PSVersionTable.PSVersion)"
Write-Host "  .NET Framework: $([System.Runtime.InteropServices.RuntimeInformation]::FrameworkDescription)"
Write-Host "  Current User: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"

Write-Host ""
Write-Host "Windows Hello Status:" -ForegroundColor Cyan
try {
    $helloStatus = Test-WindowsHelloAvailability
    Write-Host "  Available: $helloStatus" -ForegroundColor $(if ($helloStatus) { 'Green' } else { 'Red' })
} catch {
    Write-Host "  Available: Error - $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host ""
Write-Host "Usage Examples:" -ForegroundColor Cyan
Write-Host "  # Set up biometric authentication:"
Write-Host "  Connect-KeeperWithBiometrics -Username 'your.email@company.com' -SetupBiometric" -ForegroundColor Gray
Write-Host ""
Write-Host "  # Login with biometrics:"
Write-Host "  Connect-KeeperWithBiometrics -Username 'your.email@company.com'" -ForegroundColor Gray
Write-Host ""
Write-Host "  # Check availability:"
Write-Host "  Test-WindowsHelloAvailability" -ForegroundColor Gray
Write-Host ""

if (-not $SkipInteractive) {
    Write-Host "For a complete test with actual Keeper login, use:" -ForegroundColor Yellow
    Write-Host "  Connect-KeeperWithBiometrics -Username 'your.real.email@company.com' -SetupBiometric" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Test completed!" -ForegroundColor Green
