# PowerShell Windows Hello - Usage Examples
# This script demonstrates how to use the standalone PowerShell Windows Hello implementation

# Import the PowerShell integration module
. "$PSScriptRoot\PowerShellIntegration.ps1"

Write-Host "PowerShell Windows Hello - Usage Examples" -ForegroundColor Yellow
Write-Host "=========================================" -ForegroundColor Yellow
Write-Host ""

# Example 1: Using the Unified Interface - Status Check
Write-Host "Example 1: Using Unified Interface - Status Check" -ForegroundColor Green
Write-Host "------------------------------------------------" -ForegroundColor Green
$result = Invoke-WindowsHelloOperation -Operation "Status"
Write-Host "Operation Success: $($result.Success)" -ForegroundColor Cyan
Write-Host "Status: $($result.Data.Status)" -ForegroundColor Cyan
Write-Host "Can Authenticate: $($result.Data.CanAuthenticate)" -ForegroundColor Cyan
Write-Host ""

# Example 1b: Traditional method (still available)
Write-Host "Example 1b: Traditional Method (still available)" -ForegroundColor Green
Write-Host "-----------------------------------------------" -ForegroundColor Green
$available = Test-WindowsHelloCapabilities
Write-Host "Windows Hello Available: $available" -ForegroundColor Cyan
Write-Host ""

# Example 2: Using Unified Interface - Detailed Information
Write-Host "Example 2: Using Unified Interface - Detailed Information" -ForegroundColor Green
Write-Host "--------------------------------------------------------" -ForegroundColor Green
$result = Invoke-WindowsHelloOperation -Operation "Info"
if ($result.Success) {
    Write-Host " Windows Hello is ready!" -ForegroundColor Green
    Write-Host "API Version: $($result.Data.ApiVersion)" -ForegroundColor Cyan
    Write-Host "Platform: $($result.Data.Platform)" -ForegroundColor Cyan
    Write-Host "Can Create Credentials: $($result.Data.CanCreateCredentials)" -ForegroundColor Cyan
    Write-Host "Can Perform Authentication: $($result.Data.CanPerformAuthentication)" -ForegroundColor Cyan
    Write-Host "Recommendation: $($result.Data.RecommendedIntegration)" -ForegroundColor Yellow
} else {
    Write-Host " Windows Hello not available" -ForegroundColor Red
    Write-Host "Error: $($result.ErrorMessage)" -ForegroundColor Red
}
Write-Host ""

# Example 3: Using Unified Interface - Authentication Test
$statusResult = Invoke-WindowsHelloOperation -Operation "Status" -Quiet
if ($statusResult.Success -and $statusResult.Data.CanAuthenticate) {
    Write-Host "Example 3: Using Unified Interface - Authentication Test" -ForegroundColor Green
    Write-Host "------------------------------------------------------" -ForegroundColor Green
    
    try {
        # Generate a test challenge
        $challenge = [System.Text.Encoding]::UTF8.GetBytes("PowerShell-Windows-Hello-Test-Challenge")
        
        Write-Host "Performing test authentication with Windows Hello..." -ForegroundColor Yellow
        Write-Host "Challenge: $([System.Convert]::ToBase64String($challenge))" -ForegroundColor Cyan
        Write-Host ""
        
        # Use the unified interface for authentication
        $result = Invoke-WindowsHelloOperation -Operation "Authenticate" -Challenge $challenge -Username "TestUser" -TimeoutMs 30000
        
        if ($result.Success) {
            Write-Host " Test authentication successful!" -ForegroundColor Green
            Write-Host "Credential ID: $($result.Data.CredentialId.Substring(0, [Math]::Min(20, $result.Data.CredentialId.Length)))..." -ForegroundColor Cyan
            Write-Host "Signature Length: $($result.Data.Signature.Length) chars" -ForegroundColor Cyan
            Write-Host "Method: $($result.Data.Method)" -ForegroundColor Cyan
            Write-Host "Timestamp: $($result.Timestamp)" -ForegroundColor Cyan
        } else {
            Write-Host " Test authentication failed" -ForegroundColor Red
            Write-Host "Error: $($result.ErrorMessage)" -ForegroundColor Red
            Write-Host "Error Type: $($result.ErrorType)" -ForegroundColor Red
        }
    }
    catch {
        Write-Host " Authentication test failed with exception:" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
    }
    Write-Host ""
}

# Example 4: PowerCommander Integration Pattern using Unified Interface
Write-Host "Example 4: PowerCommander Integration Pattern (Unified Interface)" -ForegroundColor Green
Write-Host "----------------------------------------------------------------" -ForegroundColor Green
Write-Host "# Example of how PowerCommander would use the unified interface:" -ForegroundColor Gray
Write-Host @"
function Connect-KeeperWithWindowsHello {
    param([string]`$Username, [string]`$Server = "keepersecurity.com")
    
    # Single call to test availability
    `$statusResult = Invoke-WindowsHelloOperation -Operation "Status" -Quiet
    if (-not `$statusResult.Success) {
        throw "Windows Hello not available: `$(`$statusResult.ErrorMessage)"
    }
    
    # Get challenge from Keeper (this would be implemented in PowerCommander)
    `$challenge = Get-KeeperAuthChallenge -Username `$Username -Server `$Server
    
    # Single call to perform Windows Hello authentication
    `$authResult = Invoke-WindowsHelloOperation -Operation "Authenticate" -Challenge `$challenge.Challenge -RpId `$Server -Username `$Username
    
    if (`$authResult.Success) {
        # Use the authentication data
        `$webAuthnAssertion = @{
            CredentialId = `$authResult.Data.CredentialId
            Signature = `$authResult.Data.Signature
            AuthenticatorData = `$authResult.Data.AuthenticatorData
            ClientDataJSON = `$authResult.Data.ClientDataJSON
        }
        
        # Complete Keeper authentication
        Complete-KeeperAuthentication -Username `$Username -WebAuthnAssertion `$webAuthnAssertion
        Write-Host "Successfully connected to Keeper using Windows Hello!"
        return `$true
    } else {
        throw "Windows Hello authentication failed: `$(`$authResult.ErrorMessage)"
    }
}

# Even simpler PowerCommander integration - just one function to import
function Import-WindowsHelloSupport {
    try {
        . `$PSScriptRoot\PowerShellWindowsHello\PowerShellIntegration.ps1
        return `$true
    } catch {
        Write-Warning "Windows Hello support not available: `$(`$_.Exception.Message)"
        return `$false
    }
}
"@ -ForegroundColor Gray
Write-Host ""

# Example 5: Performance and Diagnostics using Unified Interface
Write-Host "Example 5: Performance and Diagnostics (Unified Interface)" -ForegroundColor Green
Write-Host "----------------------------------------------------------" -ForegroundColor Green

$result = Invoke-WindowsHelloOperation -Operation "Test" -Quiet
if ($result.Success) {
    Write-Host "System Diagnostics:" -ForegroundColor Yellow
    Write-Host "  Production Ready: $($result.Data.ProductionReady)" -ForegroundColor Cyan
    Write-Host "  API Version: $($result.Data.ApiVersion)" -ForegroundColor Cyan
    Write-Host "  Platform: $($result.Data.Platform)" -ForegroundColor Cyan
    Write-Host "  Can Create Credentials: $($result.Data.CanCreateCredentials)" -ForegroundColor Cyan
    Write-Host "  Can Authenticate: $($result.Data.CanAuthenticate)" -ForegroundColor Cyan
    Write-Host "  Supported Methods: $($result.Data.SupportedMethods -join ', ')" -ForegroundColor Cyan
    Write-Host "  Last Checked: $($result.Timestamp)" -ForegroundColor Cyan
}

Write-Host ""
Write-Host "Examples completed!" -ForegroundColor Green
Write-Host ""
Write-Host "For PowerCommander Integration:" -ForegroundColor Yellow
Write-Host "- Use the unified function: Invoke-WindowsHelloOperation" -ForegroundColor Green
Write-Host "- Four operations: Test, Status, Info, Authenticate" -ForegroundColor Cyan
Write-Host "- Consistent return format with Success/Data/ErrorMessage" -ForegroundColor Cyan
Write-Host ""
Write-Host "For more information:" -ForegroundColor Yellow
Write-Host "- See README.md for complete documentation" -ForegroundColor Cyan
Write-Host "- Use Get-Help Invoke-WindowsHelloOperation -Full" -ForegroundColor Green
Write-Host "- Use Get-Help Test-WindowsHelloCapabilities -Full" -ForegroundColor Cyan
Write-Host "- Use Get-Help Invoke-WindowsHelloAuthentication -Full" -ForegroundColor Cyan
