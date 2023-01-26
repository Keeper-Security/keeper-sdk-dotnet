using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using CommandLine;
using CommandLine.Text;
using KeeperSecurity.Utils;

namespace Cli
{
    public class CommandMeta
    {
        public int Order { get; set; }
        public string Description { get; set; }
    }

    public interface ICommand
    {
        Task ExecuteCommand(string args);
    }

    public interface ICancellableCommand
    {
        Task ExecuteCommand(string args, CancellationToken token);
    }

    public class SimpleCommand : CommandMeta, ICommand
    {
        public Func<string, Task> Action { get; set; }

        public async Task ExecuteCommand(string args)
        {
            if (Action != null)
            {
                await Action(args);
            }
        }
    }

    public class SimpleCancellableCommand : CommandMeta, ICancellableCommand
    {
        public Func<string, CancellationToken, Task> Action { get; set; }

        public async Task ExecuteCommand(string args, CancellationToken token)
        {
            if (Action != null)
            {
                await Action(args, token);
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
        public static string GetCommandUsage<T>(int width = 120)
        {
            var parser = new Parser(with => with.HelpWriter = null);
            var result = parser.ParseArguments<T>(new[] { "--help" });
            return HelpText.AutoBuild(result, h =>
            {
                h.AdditionalNewLineAfterOption = false;
                return h;
            }, width);
        }
    }

    public class ParseableCommandMeta<T> : CommandMeta where T : class
    {
        protected T ParseArguments(string args)
        {
            var res = Parser.Default.ParseArguments<T>(args.TokenizeArguments());
            T options = null;
            res.WithParsed(o => { options = o; });
            return options;
        }
    }

    public class ParseableCommand<T> : ParseableCommandMeta<T>, ICommand where T : class
    {
        public Func<T, Task> Action { get; set; }

        public Task ExecuteCommand(string args)
        {
            var options = ParseArguments(args);
            return options != null ? Action?.Invoke(options) : Task.CompletedTask;
        }
    }

    public class ParseableCancellableCommand<T> : ParseableCommandMeta<T>, ICancellableCommand where T : class
    {
        public Func<T, CancellationToken, Task> Action { get; set; }

        public Task ExecuteCommand(string args, CancellationToken token)
        {
            return Action?.Invoke(ParseArguments(args), token);
        }
    }

    public class CliCommands
    {
        public IDictionary<string, CommandMeta> Commands { get; } = new Dictionary<string, CommandMeta>();
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

    }

    public sealed class MainLoop
    {
        private readonly CommandMeta _exitCommand;
        private readonly CommandMeta _clearCommand;
        private readonly CommandMeta _quitCommand;

        public MainLoop()
        {
            _exitCommand = new SimpleCommand
            {
                Order = 1000,
                Description = "Exit",
                Action = (args) =>
                {
                    if (StateContext.BackStateCommands != null)
                    {
                        var oldContext = StateContext;
                        StateContext = oldContext.BackStateCommands;
                        oldContext.Dispose();
                    }

                    return Task.FromResult(true);
                }
            };

            _clearCommand = new SimpleCommand
            {
                Order = 1001,
                Description = "Clears the screen",
                Action = args =>
                {
                    Console.Clear();
                    return Task.FromResult(true);
                }
            };

            _quitCommand = new SimpleCommand
            {
                Order = 1002,
                Description = "Quit",
                Action = (args) =>
                {
                    Finished = true;
                    StateContext = null;
                    Environment.Exit(0);
                    return Task.FromResult(true);
                }
            };
        }

        public StateCommands StateContext { get; set; }
        public bool Finished { get; set; }
        public Queue<string> CommandQueue { get; } = new Queue<string>();

        public async Task Run(InputManager inputManager)
        {
            CommandMeta runningCommand = null;
            CancellationTokenSource tokenSource = null;

            inputManager.CancelKeyPress += (sender, e) =>
            {
                e.Cancel = false;
                if (runningCommand != null)
                {
                    if (runningCommand is ICancellableCommand && tokenSource != null)
                    {
                        tokenSource.Cancel();
                    }
                    else
                    {
                        e.Cancel = true;
                    }
                }
            };
            while (!Finished)
            {
                if (StateContext == null) break;
                if (StateContext.NextStateCommands != null)
                {
                    if (!ReferenceEquals(StateContext, StateContext.NextStateCommands))
                    {
                        var oldContext = StateContext;
                        StateContext = oldContext.NextStateCommands;
                        oldContext.NextStateCommands = null;
                        var contexts = StateContext;
                        while (contexts != null)
                        {
                            if (ReferenceEquals(contexts, oldContext))
                            {
                                break;
                            }

                            contexts = contexts.BackStateCommands;
                        }

                        if (contexts == null)
                        {
                            oldContext.Dispose();
                        }
                    }
                    else
                    {
                        StateContext.NextStateCommands = null;
                    }

                    inputManager.ClearHistory();
                }

                string command;
                if (CommandQueue.Count > 0)
                {
                    command = CommandQueue.Dequeue();
                }
                else
                {
                    Console.Write(StateContext.GetPrompt() + "> ");
                    try
                    {
                        command = await inputManager.ReadLine(new ReadLineParameters
                        {
                            IsHistory = true
                        });
                    }
                    catch (KeyboardInterrupt) 
                    {
                        command = "";
                    }
                }

                if (string.IsNullOrEmpty(command)) continue;

                command = command.Trim();
                var parameter = "";
                var pos = command.IndexOf(' ');
                if (pos > 1)
                {
                    parameter = command.Substring(pos + 1).Trim();
                    command = command.Substring(0, pos).Trim();
                }

                command = command.ToLowerInvariant();
                switch (command)
                {
                    case "exit":
                        runningCommand = _exitCommand;
                        break;
                    case "clear":
                    case "c":
                        runningCommand = _clearCommand;
                        break;
                    case "quit":
                    case "q":
                        runningCommand = _quitCommand;
                        break;
                    default:
                        if (StateContext.CommandAliases.TryGetValue(command, out var fullCommand))
                        {
                            command = fullCommand;
                        }

                        StateContext.Commands.TryGetValue(command, out runningCommand);
                        break;
                }

                if (runningCommand != null)
                {
                    try
                    {
                        if (runningCommand is ICancellableCommand cc)
                        {
                            tokenSource = new CancellationTokenSource();
                            await cc.ExecuteCommand(parameter, tokenSource.Token);
                        }
                        else if (runningCommand is ICommand c)
                        {
                            await c.ExecuteCommand(parameter);
                        }
                        else
                        {
                            Console.WriteLine("Unsupported command type");
                        }
                    }
                    catch (Exception e)
                    {
                        if (!await StateContext.ProcessException(e))
                        {
                            Console.WriteLine("Error: " + e.Message);
                        }
                    }
                    finally
                    {
                        runningCommand = null;
                        tokenSource?.Dispose();
                        tokenSource = null;
                    }
                }
                else
                {
                    if (command != "?")
                    {
                        Console.WriteLine($"Invalid command: {command}");
                    }

                    var tab = new Tabulate(3);
                    tab.AddHeader("Command", "Alias", "Description");
                    foreach (var c in StateContext.Commands
                        .OrderBy(x => x.Value.Order))
                    {
                        var alias = StateContext.CommandAliases
                            .Where(x => x.Value == c.Key)
                            .Select(x => x.Key)
                            .FirstOrDefault();
                        tab.AddRow(c.Key, alias ?? "", c.Value.Description);
                    }

                    if (StateContext.BackStateCommands != null)
                    {
                        tab.AddRow("exit", "", _exitCommand.Description);
                    }

                    tab.AddRow("clear", "c", _clearCommand.Description);
                    tab.AddRow("quit", "q", _quitCommand.Description);

                    tab.DumpRowNo = false;
                    tab.LeftPadding = 1;
                    tab.MaxColumnWidth = 60;
                    tab.Dump();
                }

                Console.WriteLine();
            }
        }

    }

    public abstract class StateCommands : CliCommands, IDisposable
    {
        public abstract string GetPrompt();

        public virtual Task<bool> ProcessException(Exception e)
        {
            return Task.FromResult(false);
        }

        public StateCommands NextStateCommands { get; set; }

        public StateCommands BackStateCommands { get; set; }

        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                NextStateCommands = null;
                BackStateCommands = null;
            }
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
    }
}
