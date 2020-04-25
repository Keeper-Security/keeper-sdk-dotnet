using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using CommandLine;
using CommandLine.Text;
using KeeperSecurity.Sdk;

namespace Commander
{
    public interface ICommand
    {
        int Order { get; }
        string Description { get; }
        Task ExecuteCommand(string args);
    }

    public class SimpleCommand : ICommand
    {
        public int Order { get; set; }
        public string Description { get; set; }
        public Func<string, Task> Action { get; set; }

        public async Task ExecuteCommand(string args)
        {
            if (Action != null)
            {
                await Action(args);
            }
        }
    }

    public static class CommandExtensions
    {
        public static bool IsWhiteSpace(char ch)
        {
            return char.IsWhiteSpace(ch);
        }

        public static bool IsPathDelimiter(char ch)
        {
            return ch == '/';
        }

        public static IEnumerable<string> TokenizeArguments(this string args)
        {
            return TokenizeArguments(args, IsWhiteSpace);
        }

        public static IEnumerable<string> TokenizeArguments(this string args, Func<char, bool> isDelimiter)
        {
            var sb = new StringBuilder();
            var pos = 0;
            var isQuote = false;
            var isEscape = false;
            while (pos < args.Length)
            {
                var ch = args[pos];

                if (isEscape)
                {
                    isEscape = false;
                    sb.Append(ch);
                }
                else
                {
                    switch (ch)
                    {
                        case '\\':
                            isEscape = true;
                            break;
                        case '"':
                            isQuote = !isQuote;
                            break;
                        default:
                        {
                            if (!isQuote && isDelimiter(ch))
                            {
                                if (sb.Length > 0)
                                {
                                    yield return sb.ToString();
                                    sb.Length = 0;
                                }
                            }
                            else
                            {
                                sb.Append(ch);
                            }

                            break;
                        }
                    }
                }

                pos++;
            }

            if (sb.Length > 0)
            {
                yield return sb.ToString();
            }
        }
    }

    public class ParsableCommand<T> : ICommand where T : class
    {
        public int Order { get; internal set; }
        public string Description { get; set; }
        public Func<T, Task> Action { get; internal set; }

        public async Task ExecuteCommand(string args)
        {
            var res = Parser.Default.ParseArguments<T>(args.TokenizeArguments());
            T options = null;
            res
                .WithParsed(o => { options = o; });
            if (options != null)
            {
                await Action(options);
            }
        }
    }

    public class CliCommands
    {
        public IDictionary<string, ICommand> Commands { get; } = new Dictionary<string, ICommand>();
        public IDictionary<string, string> CommandAliases { get; } = new Dictionary<string, string>();
    }

    public sealed class CliContext: CliCommands
    {
        public CliContext()
        {
            Commands.Add("clear", new SimpleCommand
            {
                Order = 1000,
                Description = "Clear the screen",
                Action = (args) =>
                {
                    Console.Clear();
                    return Task.FromResult(true);
                }
            });

            Commands.Add("quit", new SimpleCommand
            {
                Order = 1001,
                Description = "Quit",
                Action = (args) =>
                {
                    Finished = true;
                    StateContext = null;
                    return Task.FromResult(true);
                }
            });
            CommandAliases.Add("c", "clear");
            CommandAliases.Add("q", "quit");
        }

        public StateContext StateContext { get; set; }
        public bool Finished { get; protected set; }
        public Queue<string> CommandQueue { get; } = new Queue<string>();
    }

    public abstract class StateContext : CliCommands
    {
        public abstract string GetPrompt();
        public StateContext NextStateContext { get; set; }
    }

    public class NotConnectedCliContext : StateContext
    {
        private readonly IAuth _auth;

        private class LoginOptions
        {
            [Option("password", Required = false, HelpText = "master password")]
            public string Password { get; set; }

            [Value(0, Required = true, MetaName = "email", HelpText = "account email")]
            public string Username { get; set; }
        }

        public NotConnectedCliContext(IAuth auth)
        {
            _auth = auth;

            Commands.Add("login", new ParsableCommand<LoginOptions>
            {
                Order = 10,
                Description = "Login to Keeper",
                Action = DoLogin
            });

            Commands.Add("server", new SimpleCommand
            {
                Order = 20,
                Description = "Display or change Keeper Server",
                Action = (args) =>
                {
                    if (!string.IsNullOrEmpty(args))
                    {
                        _auth.Endpoint.Server = args.AdjustServerName();
                    }

                    Console.WriteLine($"Keeper Server: {_auth.Endpoint.Server.AdjustServerName()}");
                    return Task.FromResult(true);
                }
            });
        }

        private async Task DoLogin(LoginOptions options)
        {
            var userConf = new UserConfiguration(options.Username)
            {
                Password = options.Password
            };
            var credentials = await GetUserCredentials(userConf);
            if (credentials != null)
            {
                await _auth.Login(credentials.Username, credentials.Password);
                if (!string.IsNullOrEmpty(_auth.AuthContext.SessionToken))
                {
                    var vault = new Vault(_auth);
                    var connectedCommands = new ConnectedContext(vault);
                    await vault.SyncDown();
                    NextStateContext = connectedCommands;
                }
            }
        }

        public override string GetPrompt()
        {
            return "Not logged in";
        }

        public Task<UserConfiguration> GetUserCredentials(UserConfiguration credentials)
        {
            UserConfiguration cred = null;
            string username = credentials?.Username;
            string password = credentials?.Password;
            if (string.IsNullOrEmpty(username))
            {
                Console.Write("Enter Username: ");
                username = Console.ReadLine();
            }
            else
            {
                Console.WriteLine("Username: " + username);
            }

            if (!string.IsNullOrEmpty(username) && string.IsNullOrEmpty(password))
            {
                Console.Write("Enter Password: ");
                password = HelperUtils.ReadLineMasked();
            }

            if (!string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(password))
            {
                cred = new UserConfiguration(username)
                {
                    Password = password
                };
            }

            return Task.FromResult(cred);
        }
    }
}