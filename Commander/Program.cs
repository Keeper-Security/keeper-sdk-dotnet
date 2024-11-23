//  _  __
// | |/ /___ ___ _ __  ___ _ _ ®
// | ' </ -_) -_) '_ \/ -_) '_|
// |_|\_\___\___| .__/\___|_|
//              |_|
//
// Keeper SDK
// Copyright 2022 Keeper Security Inc.
// Contact: ops@keepersecurity.com
//

using System;
using System.Threading.Tasks;
using System.Net;
using KeeperSecurity.Utils;
using KeeperSecurity.Vault;
using Cli;

namespace Commander
{
    internal class Program
    {
        private static readonly InputManager InputManager = new InputManager();
        private static readonly MainLoop MainLoop = new MainLoop();

        public static InputManager GetInputManager()
        {
            return InputManager;
        }

        public static MainLoop GetMainLoop()
        {
            return MainLoop;
        }

        public static IExternalLoader CommanderStorage { get; private set; }

        private static void Main()
        {
            Console.CancelKeyPress += (s, e) => { e.Cancel = true; };
            Utils.Welcome();

            ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
            CommanderStorage = StorageUtils.SetupCommanderStorage();

            if (!CommanderStorage.VerifyDatabase())
            {
                throw new Exception("Database is invalid.");
            }

            MainLoop.StateContext = new NotConnectedCliContext(true);

            _ = MainLoop.Run(GetInputManager());
            InputManager.Run();
        }
    }

    class VaultUi : IVaultUi
    {
        public async Task<bool> Confirmation(string information)
        {
            Console.WriteLine(information);
            Console.WriteLine("Type \"yes\" to confirm, <Enter> to cancel");
            Console.Write("> ");

            var answer = await Program.GetInputManager().ReadLine();
            return string.Compare(answer, "yes", StringComparison.OrdinalIgnoreCase) == 0;
        }
    }
}