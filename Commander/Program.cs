using System;
using System.Threading.Tasks;
using System.Net;
using KeeperSecurity.Vault;
using Cli;
using CommandLine;

namespace Commander
{
    internal static class Program
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

        private static void Main(string[] args)
        {
            Console.CancelKeyPress += (s, e) => { e.Cancel = true; };
            Utils.Welcome();
            ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };

            var configFile = "";
            CommandExtensions.DefaultParser.ParseArguments<CommanderLaunchOptions>(args).WithParsed(x =>
            {
                if (!string.IsNullOrWhiteSpace(x.Config))
                {
                    configFile = x.Config;
                }
            });

            CommanderStorage = StorageUtils.SetupCommanderStorage(configFile);

            _ = MainLoop.Run(GetInputManager());
            InputManager.Run();
        }
    }

    internal class CommanderLaunchOptions
    {
        [Option('c', "config", Required = false, HelpText = "config file name")]
        public string Config { get; set; }
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