using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using CommandLine;
using KeeperSecurity.Authentication;
using KeeperSecurity.Authentication.Async;

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

    public class CliCommands: IDisposable
    {
        public IDictionary<string, ICommand> Commands { get; } = new Dictionary<string, ICommand>();
        public IDictionary<string, string> CommandAliases { get; } = new Dictionary<string, string>();
        public static bool ParseBoolOption(string text, out bool value)
        {
            if (string.Compare(text, "on", StringComparison.InvariantCultureIgnoreCase) == 0)
            {
                value = true;
                return true;
            }
            if (string.Compare(text, "off", StringComparison.InvariantCultureIgnoreCase) == 0)
            {
                value = false;
                return true;
            }

            value = false;
            return false;
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
            }
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
    }

    public sealed class CliContext : CliCommands
    {
        public CliContext()
        {
            Commands.Add("clear", new SimpleCommand
            {
                Order = 1001,
                Description = "Clear the screen",
                Action = (args) =>
                {
                    Console.Clear();
                    return Task.FromResult(true);
                }
            });

            Commands.Add("quit", new SimpleCommand
            {
                Order = 1002,
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
        public bool Finished { get; set; }
        public Queue<string> CommandQueue { get; } = new Queue<string>();
    }

    public abstract class StateContext : CliCommands
    {
        public abstract string GetPrompt();

        public virtual Task<bool> ProcessException(Exception e)
        {
            return Task.FromResult(false);
        }

        public StateContext NextState { get; set; }

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            NextState = null;
        }
    }

    public abstract class BackStateContext : StateContext
    {
        protected BackStateContext()
        {
            Commands.Add("back",
                new SimpleCommand
                {
                    Order = 1000,
                    Description = "Back",
                    Action = _ =>
                    {
                        NextState = BackState;
                        return Task.CompletedTask;
                    },
                });
        }

        protected internal StateContext BackState { get; set; }
        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            BackState = null;
        }
    }

    public class NotConnectedCliContext : StateContext
    {
        private readonly Auth _auth;

        private class LoginOptions
        {
            [Option("password", Required = false, HelpText = "master password")]
            public string Password { get; set; }

            [Option("resume", Required = false, HelpText = "resume last login")]
            public bool Resume { get; set; }

            [Option("sso", Required = false, HelpText = "login using sso provider")]
            public bool IsSsoProvider { get; set; }

            [Option("alt", Required = false, HelpText = "login using sso master password")]
            public bool IsSsoPassword { get; set; }

            [Value(0, Required = true, MetaName = "email", HelpText = "account email")]
            public string Username { get; set; }
        }

        public NotConnectedCliContext(bool autologin)
        {
            var ui = new AuthUi(Program.GetInputManager());
            var storage = Program.CommanderStorage.GetConfigurationStorage(null, new CommanderConfigurationProtection());

            _auth = new Auth(ui, storage)
            {
                Endpoint = {DeviceName = "Commander C#", ClientVersion = "c15.0.0"}
            };

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
                        _auth.Endpoint.Server = args;
                    }

                    Console.WriteLine($"Keeper Server: {_auth.Endpoint.Server}");
                    return Task.FromResult(true);
                }
            });
            if (autologin)
            {
                if (string.IsNullOrEmpty(storage.LastServer))
                {
                    Console.WriteLine($"You are connected to the default Keeper server \"{_auth.Endpoint.Server}\".");
                    Console.WriteLine($"Please use \"server <keeper host name for your region>\" command to choose a different region.");
                }
                else
                {
                    Console.WriteLine($"Connected to \"{_auth.Endpoint.Server}\".");
                }
                Console.WriteLine();

                var lastLogin = storage.LastLogin;
                if (!string.IsNullOrEmpty(lastLogin))
                {
                    Program.EnqueueCommand($"login --resume {lastLogin}");
                }
            }
        }

        private async Task DoLogin(LoginOptions options)
        {
            var username = options.Username;
            var isSsoProvider = options.IsSsoProvider;
            if (isSsoProvider)
            {
                if (string.IsNullOrEmpty(username))
                {
                    Console.Write("Enter SSO Provider: ");
                    username = await Program.GetInputManager().ReadLine();
                }
            }
            else
            {
                if (string.IsNullOrEmpty(username))
                {
                    Console.Write("Enter Username: ");
                    username = await Program.GetInputManager().ReadLine();
                }
                else
                {
                    Console.WriteLine("Username: " + username);
                }
            }

            if (string.IsNullOrEmpty(username)) return;

            try
            {
                if (isSsoProvider)
                {
                    await _auth.LoginSso(username);
                }
                else
                {
                    _auth.ResumeSession = options.Resume;
                    if (options.IsSsoPassword)
                    {
                        _auth.AlternatePassword = true;
                    }
                    var passwords = new List<string>();

                    if (!string.IsNullOrEmpty(options.Password))
                    {
                        passwords.Add(options.Password);
                    }

                    var uc = _auth.Storage.Users.Get(username);
                    if (!string.IsNullOrEmpty(uc?.Password))
                    {
                        passwords.Add(uc.Password);
                    }

                    await _auth.Login(username, passwords.ToArray());
                }

                if (_auth.IsAuthenticated())
                {
                    var connectedCommands = new ConnectedContext(_auth);
                    NextState = connectedCommands;
                }
            }
            catch (KeeperCanceled)
            {
            }
        }

        public override string GetPrompt()
        {
            return "Not logged in";
        }
    }
}