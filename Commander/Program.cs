using System;
using System.Text;
using System.Threading.Tasks;
using System.Linq;
using KeeperSecurity.Sdk;
using KeeperSecurity.Sdk.UI;
using System.Diagnostics;

namespace Commander
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.CancelKeyPress += (s, e) =>
            {
                Environment.Exit(1);
            };
            Welcome();

            MainLoop().GetAwaiter().GetResult();

            Console.WriteLine("Good Bye");
        }

        private static async Task MainLoop()
        {
            var storage = new JsonConfigurationStorage();
            var api = new KeeperEndpoint(storage);
            var auth = new AuthContext(api, new Ui());

            CliCommands commands = new NotConnectedCliCommands(auth);
            var conf = storage.Get();
            if (!string.IsNullOrEmpty(conf.LastLogin))
            {
                commands.CommandQueue.Enqueue(string.Format("login {0}", conf.LastLogin));
            }

            while (commands != null && !commands.Finished)
            {
                string command = null;
                if (commands.CommandQueue.Count > 0)
                {
                    command = commands.CommandQueue.Dequeue();
                }
                else
                {
                    Console.Write(commands.GetPrompt() + "> ");
                    command = Console.ReadLine();
                }
                if (!string.IsNullOrEmpty(command))
                {
                    command = command.Trim();
                    string parameter = "";
                    int pos = command.IndexOf(' ');
                    if (pos > 1)
                    {
                        parameter = command.Substring(pos + 1).Trim();
                        parameter = parameter.Trim('"');
                        command = command.Substring(0, pos).Trim();
                    }
                    command = command.ToLowerInvariant();
                    if (commands.CommandAliases.TryGetValue(command, out string full_command))
                    {
                        command = full_command;
                    }
                    if (commands.Commands.TryGetValue(command, out ICommand cmd))
                    {
                        try
                        {

                            await cmd.ExecuteCommand(parameter);
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine("Error: " + e.Message);
                        }
                    }
                    else
                    {
                        if (command != "?")
                        {
                            Console.WriteLine(string.Format("Invalid command: {0}", command));
                        }
                        foreach (var c in commands.Commands.OrderBy(x => x.Value.Order))
                        {
                            Console.WriteLine("    " + c.Key.PadRight(16) + c.Value.Description);
                        }
                    }

                    if (commands.Finished)
                    {
                        commands = commands.NewCommands;
                    }
                    Console.WriteLine();
                }
            }
        }


        /*
            var vault = LoadVaultData(auth).Result;
        bool done = false;
        while (!done)
        {
            Console.WriteLine();
            Console.Write("My Vault> ");
            var cmd = Console.ReadLine();
            if (!string.IsNullOrEmpty(cmd))
            {
                cmd = cmd.Trim();
                string parameter = "";
                int pos = cmd.IndexOf(' ');
                if (pos > 1) {
                    parameter = cmd.Substring(pos + 1).Trim();
                    parameter = parameter.Trim('"');
                    cmd = cmd.Substring(0, pos).Trim();
                }
                bool showUsage = false;
                switch (cmd.ToLower())
                {

                    case "?":
                        showUsage = true;
                        break;
                    case "ls":
                    case "list":
                        Console.WriteLine();
                        Console.WriteLine(" Record UID".PadRight(24, ' ') + "    " + " Title");
                        Console.WriteLine("".PadLeft(24, '=') + "    " + "".PadLeft(32, '='));
                        foreach (var record in vault.Records)
                        {
                            Console.WriteLine(record.Uid.PadLeft(24, ' ') + "    " + record.Title);
                        }
                        break;
                    case "g":
                    case "get":
                        if (!string.IsNullOrEmpty(parameter)) {
                            var record = vault.Records.Where(x => x.Uid == parameter || string.Compare(x.Title, parameter, true) == 0).FirstOrDefault();
                            if (record != null)
                            {
                                Console.WriteLine();
                                Console.WriteLine("Record UID: ".PadLeft(24, ' ') + record.Uid);
                                Console.WriteLine("Title: ".PadLeft(24, ' ') + record.Title);
                                Console.WriteLine("Login: ".PadLeft(24, ' ') + record.Login);
                                Console.WriteLine("Password: ".PadLeft(24, ' ') + record.Password);
                                Console.WriteLine("Login URL: ".PadLeft(24, ' ') + record.Link);
                                Console.WriteLine("Notes: ".PadLeft(24, ' ') + record.Notes);
                                if (record.Custom != null && record.Custom.Count > 0) {
                                    Console.WriteLine("Custom Fields:".PadLeft(24, ' '));
                                    foreach (var c in record.Custom) {
                                        Console.WriteLine((c.Name+ ": ").PadLeft(24, ' ') + c.Value);
                                    }
                                }
                            }
                            else
                            {
                                Console.WriteLine(string.Format("Record '{0}' is not found.", parameter));
                            }
                        }
                        break;
                    default:
                        showUsage = true;
                        Console.WriteLine("Invalid command.");
                        break;
                }
                if (showUsage) {
                    Console.WriteLine("Avalable commands:");
                    Console.WriteLine("list".PadRight(12, ' ') + "List all records");
                    Console.WriteLine("get <UID>".PadRight(12, ' ') + "Display record information");
                }
        */

        static void Welcome()
        {
            Console.WriteLine();
            Console.WriteLine(" _  __  ");
            Console.WriteLine("| |/ /___ ___ _ __  ___ _ _ ");
            Console.WriteLine("| ' </ -_) -_) '_ \\/ -_) '_|");
            Console.WriteLine("|_|\\_\\___\\___| .__/\\___|_|");
            Console.WriteLine("             |_|            ");
            Console.WriteLine("password manager & digital vault");
            Console.WriteLine();
            Console.WriteLine();
        }

        class Ui : IAuthUI
        {

            public Task<bool> DisplayDialog(DialogType dialog, string information)
            {
                Console.WriteLine(information);
                if (dialog == DialogType.Confirmation)
                {
                    Console.Write("Type \"yes\" to confirm: ");
                    var answer = Console.ReadLine();
                    return Task.FromResult(string.Compare(answer, "yes", true) == 0);
                }
                return Task.FromResult(true);
            }

            public Task<string> GetNewPassword(PasswordRuleMatcher matcher)
            {
                string password1 = null;
                while (string.IsNullOrEmpty(password1))
                {
                    Console.Write("New Master Password: ");
                    password1 = HelperUtils.ReadLineMasked();

                    if (!string.IsNullOrEmpty(password1) && matcher != null)
                    {
                        var failedRules = matcher.MatchFailedRules(password1);
                        if (failedRules != null && failedRules.Length > 0)
                        {
                            if (!string.IsNullOrEmpty(matcher.RuleIntro))
                            {
                                Console.WriteLine(matcher.RuleIntro);
                            }
                            foreach (var rule in failedRules)
                            {
                                Console.WriteLine(rule);
                            }
                        }
                    }
                }

                string password2 = null;
                while (string.IsNullOrEmpty(password2))
                {
                    Console.Write("Password Again: ");
                    password2 = HelperUtils.ReadLineMasked();
                    if (string.Compare(password1, password2, false) != 0)
                    {
                        Console.WriteLine("Passwords do not match.");
                        password2 = null;
                    }
                }

                return Task.FromResult(password1);
            }

            public Task<string> GetTwoFactorCode()
            {
                Console.Write("Enter Code: ");
                return Task.FromResult(Console.ReadLine());
            }

            public Task<IUserCredentials> GetUserCredentials(IUserCredentials credentials)
            {
                IUserCredentials cred = null;
                string username = credentials?.Username;
                string password = credentials?.Password;
                if (string.IsNullOrEmpty(username))
                {
                    Console.Write("Enter Username: ");
                    username = Console.ReadLine();
                }
                else {
                    Console.WriteLine("Username: " + username);
                }
                if (!string.IsNullOrEmpty(username) && string.IsNullOrEmpty(password)) 
                {
                    Console.Write("Enter Password: ");
                    password = HelperUtils.ReadLineMasked();
                }
                if (!string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(password))
                {
                    cred = new UserCredencials
                    {
                        Username = username,
                        Password = password
                    };
                }

                return Task.FromResult(cred);
            }
        }
    }
}

