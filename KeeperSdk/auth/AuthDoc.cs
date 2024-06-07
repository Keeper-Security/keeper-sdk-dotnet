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

using System.Runtime.CompilerServices;

namespace KeeperSecurity.Authentication
{
    /// <summary>
    ///     Provides base types for establishing connection to Keeper servers.
    /// </summary>
    [CompilerGenerated]
    internal class NamespaceDoc
    {
    }

    namespace Sync
    {
        /// <summary>
        ///     Provides types for connecting to Keeper servers (sync).
        /// </summary>
        /// <example>
        ///   <code>
        ///using System;
        ///using System.Threading.Tasks;
        ///using Cli;
        ///using KeeperSecurity.Authentication;
        ///using KeeperSecurity.Authentication.Sync;
        ///using KeeperSecurity.Configuration;
        ///using KeeperSecurity.Vault;
        ///
        ///namespace Sample
        ///{
        ///    internal static class Program
        ///    {
        ///        private static async Task Main()
        ///        {
        ///            // Keeper SDK needs a storage to save configuration
        ///            // such as: last login name, device token, etc
        ///            var configuration = new JsonConfigurationStorage("config.json");
        ///            var inputManager = new SimpleInputManager();
        ///
        ///            // Login to Keeper
        ///            Console.WriteLine("Logging in...");
        ///            var authFlow = new AuthSync(configuration);
        ///            await Utils.LoginToKeeper(authFlow, inputManager, "username@company.com");
        ///
        ///            if (authFlow.Step is ErrorStep es)
        ///            {
        ///                Console.WriteLine(es.Message);
        ///                return;
        ///            }
        ///            if (!authFlow.IsAuthenticated()) return;
        ///            var auth = authFlow;
        ///            var vault = new VaultOnline(auth);
        ///            await vault.SyncDown();
        ///        }
        ///    }
        ///}
        ///   </code>
        ///</example>
        [CompilerGenerated]
        internal class NamespaceDoc
        {
        }
    }
}
