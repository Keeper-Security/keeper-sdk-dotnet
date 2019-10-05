using System;
using System.Text;
using System.Threading.Tasks;
using System.Linq;
using KeeperSecurity.Sdk;
using KeeperSecurity.Sdk.UI;
using System.Diagnostics;
using System.Threading;

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
            var ui = new Ui();
            var auth = new Auth(ui, storage);

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

        class Ui : IAuthUI, IDuoTwoFactorUI
        {

            public Task<bool> Confirmation(string information)
            {
                Console.WriteLine(information);
                Console.Write("Type \"yes\" to confirm: ");
                var answer = Console.ReadLine();
                return Task.FromResult(string.Compare(answer, "yes", true) == 0);
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

            public TaskCompletionSource<TwoFactorCode> GetTwoFactorCode(TwoFactorCodeChannel channel)
            {
                TaskCompletionSource<TwoFactorCode> source = new TaskCompletionSource<TwoFactorCode>();
                Task.Run(() =>
                {
                    Console.Write("Enter Code: ");
                    var code = Console.ReadLine();
                    if (!string.IsNullOrEmpty(code) && !source.Task.IsCompleted)
                    {
                        source.SetResult(new TwoFactorCode(code, TwoFactorCodeDuration.Forever));
                    }
                });
                return source;
            }

            public TaskCompletionSource<TwoFactorCode> GetDuoTwoFactorResult(DuoAccount account, Func<DuoAction, Task> onAction)
            {
                TaskCompletionSource<TwoFactorCode> source = new TaskCompletionSource<TwoFactorCode>();
                Task.Run(async () =>
                {
                    string input = null;
                    while (true)
                    {
                        Console.WriteLine("Type:\n\"push\" for DUO push\t\"sms\" for DUO text message\nDUO app code\tKeeper backup code\t<Enter> to Cancel");
                        Console.Write("> ");
                        input = Console.ReadLine();
                        if (source.Task.IsCompleted)
                        {
                            break;
                        }
                        if (string.IsNullOrEmpty(input))
                        {
                            break;
                        }
                        switch (input.ToLowerInvariant())
                        {
                            case "push":
                            case "sms":
                                var action = string.Compare(input, "push", true) == 0 ? DuoAction.DuoPush : DuoAction.TextMessage;
                                input = null;
                                await onAction(action);
                                break;
                            default:
                                break;
                        }
                        if (source.Task.IsCompleted)
                        {
                            break;
                        }
                        if (!string.IsNullOrEmpty(input))
                        {
                            break;
                        }
                    }
                    if (!source.Task.IsCompleted)
                    {
                        if (string.IsNullOrEmpty(input))
                        {
                            source.SetCanceled();
                        }
                        else
                        {
                            source.SetResult(new TwoFactorCode(input, TwoFactorCodeDuration.Forever));
                        }
                    }
                });
                return source;
            }
        }
    }
}

