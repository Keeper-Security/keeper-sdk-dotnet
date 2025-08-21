using System;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security;
using System.Threading.Tasks;
using CommandLine;
using KeeperSecurity.Authentication;
using KeeperSecurity.Utils;

namespace Commander
{
    [Verb("test-windows-hello", HelpText = "Test Windows Hello availability")]
    public class TestWindowsHelloOptions
    {
        [Option('v', "verbose", Required = false, Default = false, HelpText = "Verbose output")]
        public bool Verbose { get; set; }
    }

    [Verb("setup-biometric", HelpText = "Set up biometric authentication for Keeper")]
    public class SetupBiometricOptions
    {
        [Option('u', "username", Required = true, HelpText = "Keeper username/email")]
        public string Username { get; set; }

        [Option('s', "server", Required = false, Default = "keepersecurity.com", HelpText = "Keeper server")]
        public string Server { get; set; }

        [Option('p', "password", Required = false, HelpText = "Master password (will prompt if not provided)")]
        public string Password { get; set; }
    }

    [Verb("login-biometric", HelpText = "Login to Keeper using biometric authentication")]
    public class LoginBiometricOptions
    {
        [Option('u', "username", Required = true, HelpText = "Keeper username/email")]
        public string Username { get; set; }

        [Option('s', "server", Required = false, Default = "keepersecurity.com", HelpText = "Keeper server")]
        public string Server { get; set; }

        [Option('c', "config", Required = false, HelpText = "Configuration file")]
        public string Config { get; set; }
    }

    [Verb("remove-biometric", HelpText = "Remove stored biometric credentials")]
    public class RemoveBiometricOptions
    {
        [Option('u', "username", Required = true, HelpText = "Keeper username/email")]
        public string Username { get; set; }

        [Option('s', "server", Required = false, Default = "keepersecurity.com", HelpText = "Keeper server")]
        public string Server { get; set; }

        [Option('f', "force", Required = false, Default = false, HelpText = "Force removal without confirmation")]
        public bool Force { get; set; }
    }

    /// <summary>
    /// Windows Hello commands for Commander - works on all targets with runtime platform detection
    /// </summary>
    public static class WindowsHelloCommands
    {
        public static async Task<bool> TestWindowsHelloCommand(TestWindowsHelloOptions options)
        {
            try
            {
                if (options.Verbose)
                {
                    Console.WriteLine("Checking Windows Hello availability...");
                }

                var available = await WindowsHelloProvider.IsAvailableAsync();
                
                if (available)
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("✓ Windows Hello is available and configured");
                    Console.ResetColor();
                    
                    if (options.Verbose)
                    {
                        Console.WriteLine("You can now use biometric authentication commands:");
                        Console.WriteLine("  setup-biometric -u your.email@company.com");
                        Console.WriteLine("  login-biometric -u your.email@company.com");
                    }
                    
                    return true;
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("❌ Windows Hello is not available or not configured");
                    Console.ResetColor();
                    
                    if (options.Verbose)
                    {
                        Console.WriteLine("Please configure Windows Hello in Windows Settings:");
                        Console.WriteLine("  Settings > Accounts > Sign-in options > Windows Hello");
                    }
                    
                    return false;
                }
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"❌ Error checking Windows Hello: {ex.Message}");
                Console.ResetColor();
                return false;
            }
        }

        public static async Task<bool> SetupBiometricCommand(SetupBiometricOptions options)
        {
            try
            {
                // Check Windows Hello availability first
                if (!await WindowsHelloProvider.IsAvailableAsync())
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("❌ Windows Hello is not available. Please configure Windows Hello in Windows Settings.");
                    Console.ResetColor();
                    return false;
                }

                // Get password if not provided
                string password = options.Password;
                if (string.IsNullOrEmpty(password))
                {
                    Console.Write("Enter Master Password: ");
                    password = await Program.GetInputManager().ReadLine(new Cli.ReadLineParameters { IsSecured = true });
                    if (string.IsNullOrEmpty(password))
                    {
                        Console.WriteLine("Password is required for biometric setup.");
                        return false;
                    }
                }

                Console.WriteLine($"Setting up biometric authentication for {options.Username}...");

                // Verify biometric access first
                var verificationResult = await WindowsHelloProvider.RequestVerificationAsync($"Set up biometric login for {options.Username}");
                if (verificationResult != BiometricVerificationResult.Verified)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"❌ Biometric verification failed: {verificationResult}");
                    Console.ResetColor();
                    return false;
                }

                // Store the credential
                var stored = await WindowsHelloProvider.StoreBiometricCredentialAsync(options.Username, password, options.Server);

                if (stored)
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine($"✓ Biometric authentication setup complete for {options.Username}");
                    Console.ResetColor();
                    Console.WriteLine($"You can now use: login-biometric -u {options.Username}");
                    return true;
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("❌ Failed to store biometric credentials");
                    Console.ResetColor();
                    return false;
                }
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"❌ Error setting up biometric authentication: {ex.Message}");
                Console.ResetColor();
                return false;
            }
        }

        public static async Task<bool> LoginBiometricCommand(LoginBiometricOptions options)
        {
            try
            {
                // Check Windows Hello availability
                if (!await WindowsHelloProvider.IsAvailableAsync())
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("❌ Windows Hello is not available");
                    Console.ResetColor();
                    return false;
                }

                // Check if credential exists
                var credential = WindowsHelloProvider.GetBiometricCredential(options.Username, options.Server);
                if (credential == null)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"❌ No biometric credentials found for {options.Username} on {options.Server}");
                    Console.WriteLine($"Please run: setup-biometric -u {options.Username}");
                    Console.ResetColor();
                    return false;
                }

                // Request biometric verification
                Console.WriteLine($"🔐 Biometric authentication required for {options.Username}");
                var verificationResult = await WindowsHelloProvider.RequestVerificationAsync($"Verify your identity to access Keeper vault for {options.Username}");

                if (verificationResult != BiometricVerificationResult.Verified)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"❌ Biometric verification failed: {verificationResult}");
                    Console.ResetColor();
                    return false;
                }

                // Decrypt and get password
                var password = WindowsHelloProvider.DecryptPassword(credential);
                if (password == null)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("❌ Failed to decrypt stored password. Please set up biometric authentication again.");
                    Console.ResetColor();
                    return false;
                }

                Console.WriteLine("✅ Biometric authentication successful, logging into Keeper...");

                // Login using the auth sync logic
                try
                {
                    var loader = Program.CommanderStorage.GetConfigurationLoader();
                    var storage = new KeeperSecurity.Configuration.JsonConfigurationStorage(loader);
                    var auth = new KeeperSecurity.Authentication.Sync.AuthSync(storage)
                    {
                        Endpoint = { DeviceName = "Commander C#", ClientVersion = "c17.0.0" }
                    };
                    
                    auth.Username = options.Username;
                    if (!string.IsNullOrEmpty(options.Server) && options.Server != "keepersecurity.com")
                    {
                        auth.Endpoint.Server = options.Server;
                    }

                    await auth.Login(options.Username, password);

                    // Create connected context and update main loop
                    var connectedContext = new ConnectedContext(auth);
                    Program.Context = connectedContext;
                    Program.GetMainLoop().StateContext = connectedContext;
                    
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine($"✅ Successfully logged into Keeper with biometric authentication");
                    Console.ResetColor();
                    
                    return true;
                }
                catch (Exception ex)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"❌ Login failed: {ex.Message}");
                    Console.ResetColor();
                    return false;
                }
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"❌ Error during biometric login: {ex.Message}");
                Console.ResetColor();
                return false;
            }
        }

        public static async Task<bool> RemoveBiometricCommand(RemoveBiometricOptions options)
        {
            try
            {
                // Check if credential exists
                var credential = WindowsHelloProvider.GetBiometricCredential(options.Username, options.Server);
                if (credential == null)
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine($"⚠️ No biometric credentials found for {options.Username} on {options.Server}");
                    Console.ResetColor();
                    return true;
                }

                // Confirm removal unless forced
                if (!options.Force)
                {
                    Console.Write($"Remove biometric credentials for {options.Username}@{options.Server}? (y/N): ");
                    var response = Console.ReadLine();
                    if (string.IsNullOrEmpty(response) || !response.ToLower().StartsWith("y"))
                    {
                        Console.WriteLine("Operation cancelled");
                        return false;
                    }
                }

                // Request biometric verification for security
                Console.WriteLine("Biometric verification required to remove credentials...");
                var verificationResult = await WindowsHelloProvider.RequestVerificationAsync($"Verify your identity to remove biometric credentials for {options.Username}");
                
                if (verificationResult != BiometricVerificationResult.Verified)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"❌ Biometric verification failed: {verificationResult}");
                    Console.ResetColor();
                    return false;
                }

                // Remove credentials
                var removed = WindowsHelloProvider.RemoveBiometricCredential(options.Username, options.Server);
                
                if (removed)
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine($"✓ Biometric credentials removed for {options.Username}");
                    Console.ResetColor();
                    return true;
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("❌ Failed to remove biometric credentials");
                    Console.ResetColor();
                    return false;
                }
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"❌ Error removing biometric credentials: {ex.Message}");
                Console.ResetColor();
                return false;
            }
        }
    }
}
