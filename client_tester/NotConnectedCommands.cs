using System;
using System.IO;
using System.Threading.Tasks;
using Cli;
using CommandLine;
using KeeperSecurity.Authentication;
using KeeperSecurity.Authentication.Async;
using KeeperSecurity.Configuration;
using KeeperSecurity.Enterprise;

namespace ClientTester
{
    public class NotConnectedCommands : StateCommands
    {
        public NotConnectedCommands()
        {
            if (string.IsNullOrEmpty(Program.Storage.LastServer))
            {
                KeeperServer = KeeperEndpoint.DefaultKeeperServer;
                Console.WriteLine($"Connecting to the default Keeper sever: {KeeperServer}");
            }
            else
            {
                KeeperServer = Program.Storage.LastServer;
            }
            Commands.Add("server",
                new SimpleCommand
                {
                    Order = 10,
                    Description = "Gets or sets Keeper server.",
                    Action = (arguments) =>
                    {
                        if (!string.IsNullOrEmpty(arguments))
                        {
                            KeeperServer = arguments;
                        }
                        Console.WriteLine($"Keeper server: {KeeperServer}");
                        return Task.CompletedTask;
                    },
                });

            Commands.Add("login",
                new ParsableCommand<LoginOptions>
                {
                    Order = 11,
                    Description = "Logins to Keeper server.",
                    Action = Login,
                });

            if (!string.IsNullOrEmpty(Program.Storage.LastLogin))
            {
                Console.WriteLine($"Username: {Program.Storage.LastLogin}");
                Program.EnqueueCommand($"login \"{Program.Storage.LastLogin}\"");
            }
        }

        async Task Login(LoginOptions options)
        {
            var auth = new Auth(new ConsoleAuthUi(Program.GetInputManager()), Program.Storage)
            {
                Endpoint = { DeviceName = "Client Tester", ClientVersion = "c15.0.0" }
            };
            if (!string.IsNullOrEmpty(KeeperServer))
            {
                auth.Endpoint.Server = KeeperServer;
            }

            auth.ResumeSession = true;
            auth.AlternatePassword = options.Sso;
            await auth.Login(options.Username);

            if (auth.IsAuthenticated())
            {
                if (auth.AuthContext.IsEnterpriseAdmin)
                {
                    var enterprise = new EnterpriseData(auth);
                    await enterprise.PopulateEnterprise();
                    NextStateCommands = new EnterpriseCommands(enterprise);
                }
            }
        }

        public string KeeperServer { get; set; }

        public override string GetPrompt()
        {
            return "Not logged in";
        }
    }

    class LoginOptions
    {
        [Option("sso", Required = false, HelpText = "Indicates use of alternate password for SSO account.")]
        public bool Sso { get; set; }

        [Value(0, Required = true, MetaName = "Username", HelpText = "Enterprise administrator email.")]
        public string Username { get; set; }
    }

}
