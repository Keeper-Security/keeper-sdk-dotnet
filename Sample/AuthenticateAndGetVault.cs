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
    /// Provides authentication and vault resolution for samples.
    /// Implement this interface when you need to obtain the auth object (e.g. for API calls without vault sync).
    /// </summary>
    public interface IAuthenticateAndGetVault
    {
        /// <summary>
        /// Performs login and returns the authentication object. Does not create or sync the vault.
        /// </summary>
        /// <param name="enablePersistentLogin">Enable, disable, or leave unchanged persistent login.</param>
        /// <returns>The authenticated <see cref="IAuthentication"/> or null if authentication failed.</returns>
        Task<IAuthentication> GetAuthAsync(bool? enablePersistentLogin = null);

        /// <summary>
        /// Performs login (if needed) and returns a vault, optionally syncing it.
        /// </summary>
        Task<VaultOnline> GetVaultAsync(bool? enablePersistentLogin = null);

        /// <summary>
        /// Returns the given vault, or authenticates and gets the vault if null.
        /// </summary>
        Task<VaultOnline> ResolveVaultAsync(VaultOnline vault);
    }


    /// <summary>
    /// Basic authentication example demonstrating:
    /// - Master password authentication
    /// - Two-factor authentication
    /// - Device approval
    /// - Vault synchronization
    /// </summary>
    /// <remarks>
    /// Persistent login:
    ///   1. First run  → full login (password or SSO), registers device, enables persistent_login
    ///   2. Next runs → session resume via clone_code (no password)
    ///   3. Within run → cached vault returned to all callers
    ///
    /// YubiKey / Security Key (FIDO2/WebAuthn): When the server returns 2FA with a security key channel,
    /// type "key" at the 2FA prompt. On Windows (net472), the native WebAuthn dialog appears; touch the key to complete.
    /// </remarks>
    public static class AuthenticateAndGetVault
    {
        private static readonly Lazy<IAuthenticateAndGetVault> Instance =
            new Lazy<IAuthenticateAndGetVault>(() => new AuthenticateAndGetVaultImpl());

        /// <summary>
        /// Gets the default implementation of <see cref="IAuthenticateAndGetVault"/>.
        /// </summary>
        public static IAuthenticateAndGetVault Default => Instance.Value;

        /// <summary>
        /// Returns the authentication object after login. Does not create or sync the vault.
        /// </summary>
        public static async Task<IAuthentication> GetAuthAsync(bool? enablePersistentLogin = null)
            => await Default.GetAuthAsync(enablePersistentLogin);

        /// <summary>
        /// Returns the given vault, or authenticates and gets the vault if null. Returns null if auth fails.
        /// Use as first line in example methods: vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault); if (vault == null) return;
        /// </summary>
        public static async Task<VaultOnline> ResolveVaultAsync(VaultOnline vault)
            => await Default.ResolveVaultAsync(vault);

        /// <summary>
        /// Authenticates and returns a vault (syncs down).
        /// </summary>
        public static async Task<VaultOnline> GetVault(bool? enablePersistentLogin = null)
            => await Default.GetVaultAsync(enablePersistentLogin);

    }

    internal sealed class AuthenticateAndGetVaultImpl : IAuthenticateAndGetVault
    {
        private static readonly IReadOnlyDictionary<string, string> KeeperPublicHosts = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { "US", "keepersecurity.com" },
            { "EU", "keepersecurity.eu" },
            { "AU", "keepersecurity.com.au" },
            { "US Gov", "govcloud.keepersecurity.us" },
            { "JP", "keepersecurity.jp" },
            { "CA", "keepersecurity.ca" },
        };

        private IAuthentication _cachedAuth;
        private VaultOnline _cachedVault;

        public async Task<IAuthentication> GetAuthAsync(bool? enablePersistentLogin = null)
        {
            var auth = await RunLoginAsync(enablePersistentLogin);
            if (auth != null)
                _cachedAuth = auth;
            return auth;
        }

        public async Task<VaultOnline> GetVaultAsync(bool? enablePersistentLogin = null)
        {
            var auth = _cachedAuth ?? await RunLoginAsync(enablePersistentLogin);
            if (auth == null) return null;
            _cachedAuth = auth;

            _cachedVault = new VaultOnline(auth);
            await _cachedVault.SyncDown();
            return _cachedVault;
        }

        public async Task<VaultOnline> ResolveVaultAsync(VaultOnline vault)
        {
            if (vault != null) return vault;
            return await GetVaultAsync();
        }

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
            if (KeeperPublicHosts.TryGetValue(server, out var host))
                server = host;

            configuration.LastServer = server;
            storage.Put(configuration);
        }

        private static async Task<string> PromptUsernameAsync(IInputManager inputManager, string lastLogin)
        {
            Console.Write("Username: ");
            var input = await inputManager.ReadLine(new ReadLineParameters { IsHistory = false, Text = lastLogin ?? "" });
            input = (input ?? "").Trim();
            if (string.IsNullOrEmpty(input) && !string.IsNullOrEmpty(lastLogin))
                input = lastLogin;
            return string.IsNullOrEmpty(input) ? null : input;
        }

        private static async Task<IAuthentication> RunLoginAsync(bool? enablePersistentLogin)
        {
            var configurationStorage = new JsonConfigurationStorage("config.json");
            var configuration = configurationStorage.Get();
            var inputManager = new SimpleInputManager();

            await EnsureServerAsync(configurationStorage, inputManager);

            var username = await PromptUsernameAsync(inputManager, configuration.LastLogin);
            if (string.IsNullOrEmpty(username))
            {
                if (string.IsNullOrEmpty(configuration.LastLogin))
                {
                    Console.WriteLine("No last login found.");
                    return null;
                }

                username = configuration.LastLogin;
            }

            var authFlow = new AuthSync(configurationStorage);
            authFlow.BiometricLoginProvider = null;
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

            if (enablePersistentLogin == true)
                await SetupPersistentLogin(authFlow);
            else if (enablePersistentLogin == false)
                await DisablePersistentLogin(authFlow);

            return authFlow;
        }

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

        private static async Task DisablePersistentLogin(AuthSync auth)
        {
            try
            {
                var accountSummary = await auth.LoadAccountSummary();
                if (accountSummary.Settings.PersistentLogin)
                {
                    await auth.SetSessionParameter("persistent_login", "0");
                    Console.WriteLine("Persistent login disabled.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Could not disable persistent login: {ex.Message}");
            }
        }
    }
}
