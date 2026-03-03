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
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Cli;
using KeeperSecurity.Authentication;
using KeeperSecurity.Authentication.Sync;
using KeeperSecurity.Configuration;
using KeeperSecurity.Vault;

namespace Sample
{
    /// <summary>
    /// Authenticate and load vault. Behaves like Commander: prompt for username only; the server
    /// determines whether the account uses password, device approval, 2FA, or SSO. For SSO accounts
    /// the same flow shows the SSO Login URL and token step. Supports server selection and persistent login.
    /// Biometric login is intentionally not used in this sample.
    /// </summary>
    /// <remarks>
    /// Persistent login pattern (same as Commander / PowerCommander):
    ///   1. First run  → full login (password or SSO), registers device, enables persistent_login
    ///   2. Next runs  → session resume via clone_code (no password)
    ///   3. Within run → cached vault returned to all callers
    /// </remarks>
    public static class AuthenticateAndGetVault
    {
        /// <summary>
        /// Keeper public regions (region label -> server host). Used for server selection when LastServer is not set.
        /// </summary>
        private static readonly IReadOnlyDictionary<string, string> KeeperPublicHosts = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { "US", "keepersecurity.com" },
            { "EU", "keepersecurity.eu" },
            { "AU", "keepersecurity.com.au" },
            { "US Gov", "govcloud.keepersecurity.us" },
            { "JP", "keepersecurity.jp" },
            { "CA", "keepersecurity.ca" },
        };

        private static VaultOnline _cachedVault;

        /// <summary>
        /// Returns the given vault, or authenticates and gets the vault if null. Returns null if auth fails.
        /// Use as first line in example methods: vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault); if (vault == null) return;
        /// </summary>
        public static async Task<VaultOnline> ResolveVaultAsync(VaultOnline vault)
        {
            if (vault != null) return vault;
            return await GetVault();
        }

        /// <summary>
        /// Ensures a Keeper server is selected. If configuration has no LastServer, prompts for region and persists choice.
        /// Mirrors Python login.py _ensure_server().
        /// </summary>
        private static async Task EnsureServerAsync(IConfigurationStorage storage, IInputManager inputManager)
        {
            var configuration = storage.Get();
            if (!string.IsNullOrEmpty(configuration.LastServer))
                return;

            Console.WriteLine("Available server options:");
            foreach (var kv in KeeperPublicHosts)
                Console.WriteLine($"  {kv.Key}: {kv.Value}");
            Console.Write("Enter server (default: keepersecurity.com): ");
            var server = await inputManager.ReadLine(new ReadLineParameters { IsHistory = false });
            server = string.IsNullOrWhiteSpace(server) ? "keepersecurity.com" : server.Trim();

            // If user typed a region key, resolve to host
            if (KeeperPublicHosts.TryGetValue(server, out var host))
                server = host;

            configuration.LastServer = server;
            storage.Put(configuration);
        }

        /// <summary>
        /// Prompts for username (email). Same as Commander: one username prompt; SSO is determined by the server.
        /// </summary>
        private static async Task<string> PromptUsernameAsync(IInputManager inputManager, string lastLogin)
        {
            Console.Write("Username: ");
            var input = await inputManager.ReadLine(new ReadLineParameters { IsHistory = false, Text = lastLogin ?? "" });
            input = (input ?? "").Trim();
            if (string.IsNullOrEmpty(input) && !string.IsNullOrEmpty(lastLogin))
                input = lastLogin;
            return string.IsNullOrEmpty(input) ? null : input;
        }

        public static async Task<VaultOnline> GetVault()
        {
            var configurationStorage = new JsonConfigurationStorage("config.json");
            var configuration = configurationStorage.Get();
            var inputManager = new SimpleInputManager();

            // 1. Server selection (like Python ensure_server)
            await EnsureServerAsync(configurationStorage, inputManager);

            // 2. Username (same as Commander: SSO is determined by server; if account is SSO, LoginFlow shows SSO Login URL)
            var username = await PromptUsernameAsync(inputManager, configuration.LastLogin);
            if (string.IsNullOrEmpty(username))
            {
                Console.WriteLine("Bye.");
                return null;
            }

            var authFlow = new AuthSync(configurationStorage);
            // Biometric login is not used in this sample (per requirement).
            authFlow.BiometricLoginProvider = null;

            authFlow.ResumeSession = true;

            // Single login path like Commander: LoginToKeeper handles password, device approval, 2FA, and SSO (server redirects to SSO and shows SSO Login URL)
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

            // 3. Persistent login (like Python enable_persistent_login)
            await SetupPersistentLogin(authFlow);

            _cachedVault = new VaultOnline(authFlow);
            await _cachedVault.SyncDown();
            return _cachedVault;
        }

        /// <summary>
        /// Mirrors Commander's "this-device persistent_login on" + "this-device register" flow
        /// (and Python enable_persistent_login): register data key for device, enable persistent_login setting.
        /// </summary>
        private static async Task SetupPersistentLogin(AuthSync auth)
        {
            try
            {
                var accountSummary = await auth.LoadAccountSummary();

                bool restricted = false;
                if (accountSummary.Enforcements?.Booleans != null)
                {
                    var plp = accountSummary.Enforcements.Booleans
                        .FirstOrDefault(x => x.Key == "restrict_persistent_login");
                    if (plp != null)
                        restricted = plp.Value;
                }

                if (restricted)
                {
                    Console.WriteLine("Persistent login is restricted by enterprise administrator.");
                    return;
                }

                var device = accountSummary.Devices
                    .FirstOrDefault(d => d.EncryptedDeviceToken.SequenceEqual(auth.DeviceToken));

                if (device != null && !device.EncryptedDataKeyPresent)
                {
                    await auth.RegisterDataKeyForDevice(device);
                    Console.WriteLine("Device registered for persistent login.");
                }

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
