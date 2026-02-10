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
using Cli;
using KeeperSecurity.Authentication;
using KeeperSecurity.Authentication.Sync;
using KeeperSecurity.Configuration;
using KeeperSecurity.Vault;

namespace Sample
{
    /// <summary>
    /// Basic authentication example demonstrating:
    /// - Master password authentication
    /// - Two-factor authentication
    /// - Device approval
    /// - Vault synchronization
    /// </summary>
    public class AuthenticateAndGetVault
    {
        public static async Task<VaultOnline> GetVault()
        {
            // Keeper SDK needs a storage to save configuration parameters 
            // such as: last login name, device token, etc
            var configurationStorage = new JsonConfigurationStorage("config.json");
            var configuration = configurationStorage.Get();

            var prompt = "Enter Email Address: ";
            if (!string.IsNullOrEmpty(configuration.LastLogin))
            {
                Console.WriteLine($"Default Email Address: {configuration.LastLogin}");
            }

            Console.Write(prompt);
            var username = Console.ReadLine();
            if (string.IsNullOrEmpty(username))
            {
                if (string.IsNullOrEmpty(configuration.LastLogin))
                {
                    Console.WriteLine("Bye.");
                    return null;
                }

                username = configuration.LastLogin;
            }

            var inputManager = new SimpleInputManager();

            var authFlow = new AuthSync(configurationStorage);
            await KeeperLoginFlow.LoginToKeeper(authFlow, inputManager, username);

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

            await authFlow.SetSessionParameter("persistent_login", "1");

            var vault = new VaultOnline(authFlow);
            await vault.SyncDown();
            return vault;
        }
    }
}

