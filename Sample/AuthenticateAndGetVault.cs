//  _  __
// | |/ /___ ___ _ __  ___ _ _ ®
// | ' </ -_) -_) '_ \/ -_) '_|
// |_|\_\___\___| .__/\___|_|
//              |_|
//
// Keeper SDK
// Copyright 2021 Keeper Security Inc.
// Contact: ops@keepersecurity.com
//

using System;
using System.Linq;
using System.Threading.Tasks;
using AccountSummary;
using Cli;
using KeeperSecurity.Authentication;
using KeeperSecurity.Authentication.Sync;
using KeeperSecurity.Configuration;
using KeeperSecurity.Vault;

namespace Sample
{
    /// <summary>
    /// Persistent login following the same pattern as Commander / PowerCommander:
    ///   1. First run  → password login, registers device, enables persistent_login
    ///   2. Next runs  → session resume via clone_code (no password)
    ///   3. Within run → cached vault returned to all callers
    /// </summary>
    public static class AuthenticateAndGetVault
    {
        private static VaultOnline _cachedVault;

        public static async Task<VaultOnline> GetVault()
        {
            // if (_cachedVault != null)
            //     return _cachedVault;

            var configurationStorage = new JsonConfigurationStorage("config.json");
            var configuration = configurationStorage.Get();

            var username = configuration.LastLogin;
            if (string.IsNullOrEmpty(username))
            {
                Console.Write("Enter Email Address: ");
                username = Console.ReadLine();
                if (string.IsNullOrEmpty(username))
                {
                    Console.WriteLine("Bye.");
                    return null;
                }
            }
            else
            {
                Console.WriteLine($"Logging in as: {username}");
            }

            var inputManager = new SimpleInputManager();
            var authFlow = new AuthSync(configurationStorage);

            authFlow.ResumeSession = true;
            try
            {
                await KeeperLoginFlow.LoginToKeeper(authFlow, inputManager, username);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Resume attempt error: {ex.Message}");
            }

            if (!authFlow.IsAuthenticated())
            {
                Console.WriteLine("Session resume not available. Using standard login.");
                authFlow.Cancel();
                authFlow.ResumeSession = false;
                try
                {
                    await KeeperLoginFlow.LoginToKeeper(authFlow, inputManager, username);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Login error: {ex.Message}");
                }
            }
            else
            {
                Console.WriteLine("Session resumed successfully (no password needed).");
            }

            if (authFlow.Step is ErrorStep es)
            {
                Console.WriteLine($"Authentication error: {es.Message}");
                return null;
            }

            if (!authFlow.IsAuthenticated())
            {
                Console.WriteLine("Authentication failed.");
                return null;
            }

            // Step 3: Setup persistent login (same as Commander's "this-device" commands)
            await SetupPersistentLogin(authFlow);

            _cachedVault = new VaultOnline(authFlow);
            await _cachedVault.SyncDown();
            return _cachedVault;
        }

        /// <summary>
        /// Mirrors Commander's "this-device persistent_login on" + "this-device register" flow:
        ///   - Loads account summary to check enterprise restrictions
        ///   - Registers device data key if not already registered
        ///   - Enables persistent_login setting
        /// </summary>
        private static async Task SetupPersistentLogin(AuthSync auth)
        {
            try
            {
                var accountSummary = await auth.LoadAccountSummary();

                // Check if enterprise restricts persistent login
                bool restricted = false;
                if (accountSummary.Enforcements?.Booleans != null)
                {
                    var plp = accountSummary.Enforcements.Booleans
                        .FirstOrDefault(x => x.Key == "restrict_persistent_login");
                    if (plp != null)
                    {
                        restricted = plp.Value;
                    }
                }

                if (restricted)
                {
                    Console.WriteLine("Persistent login is restricted by enterprise administrator.");
                    return;
                }

                // Register device data key (same as "this-device register")
                var device = accountSummary.Devices
                    .FirstOrDefault(d => d.EncryptedDeviceToken.SequenceEqual(auth.DeviceToken));

                if (device != null)
                {
                    if (!device.EncryptedDataKeyPresent)
                    {
                        await auth.RegisterDataKeyForDevice(device);
                        Console.WriteLine("Device registered for persistent login.");
                    }
                }

                // Enable persistent login (same as "this-device persistent_login on")
                if (!accountSummary.Settings.PersistentLogin)
                {
                    await auth.SetSessionParameter("persistent_login", "1");
                    Console.WriteLine("Persistent login enabled.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Could not setup persistent login: {ex.Message}");
            }
        }
    }
}
