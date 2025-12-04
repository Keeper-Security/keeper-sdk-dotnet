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
    /// - Device approval
    /// - Vault synchronization
    /// </summary>
    public class AuthenticateAndGetVault
    {
        /// <summary>
        /// Runs the basic authentication example
        /// </summary>
        public static async Task ShowFolders()
        {
            var vault = await GetVault();
            var folders = vault.Folders.Count();
            Console.WriteLine($"Folders: {folders}");
        }

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

            // Use SimpleInputManager from CLI package for handling console input
            var inputManager = new SimpleInputManager();

            // Login to Keeper using AuthSync
            var authFlow = new AuthSync(configurationStorage);
            await Utils.LoginToKeeper(authFlow, inputManager, username);

            // Check for authentication errors
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

            // Sync vault
            var vault = new VaultOnline(authFlow);
            await vault.SyncDown();
            return vault;
        }
    }
}

