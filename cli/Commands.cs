using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using CommandLine;
using KeeperSecurity.Utils;

namespace Cli
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
        public int Order { get; set; }
        public string Description { get; set; }
        public Func<T, Task> Action { get; set; }

        public async Task ExecuteCommand(string args)
        {
            var res = Parser.Default.ParseArguments<T>(args.TokenizeArguments());
            T options = null;
            res.WithParsed(o => { options = o; });
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

    public sealed class MainLoop : CliCommands
    {
        public MainLoop()
        {
            Commands.Add("clear",
                new SimpleCommand
                {
                    Order = 1000,
                    Description = "Clears the screen",
                    Action = (args) =>
                    {
                        Console.Clear();
                        return Task.FromResult(true);
                    }
                });

            Commands.Add("quit",
                new SimpleCommand
                {
                    Order = 1001,
                    Description = "Quit",
                    Action = (args) =>
                    {
                        Finished = true;
                        StateContext = null;
                        Environment.Exit(0);
                        return Task.FromResult(true);
                    }
                });
            CommandAliases.Add("c", "clear");
            CommandAliases.Add("q", "quit");
        }

        public StateCommands StateContext { get; set; }
        public bool Finished { get; set; }
        public Queue<string> CommandQueue { get; } = new Queue<string>();

        public async Task Run(InputManager inputManager)
        {
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
                        oldContext.Dispose();
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
                    command = await inputManager.ReadLine(new ReadLineParameters
                    {
                        IsHistory = true
                    });
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
                if (CommandAliases.TryGetValue(command, out var fullCommand))
                {
                    command = fullCommand;
                }
                else if (StateContext.CommandAliases.TryGetValue(command, out fullCommand))
                {
                    command = fullCommand;
                }

                if (!Commands.TryGetValue(command, out var cmd))
                {
                    StateContext.Commands.TryGetValue(command, out cmd);
                }

                if (cmd != null)
                {
                    try
                    {
                        await cmd.ExecuteCommand(parameter);
                    }
                    catch (Exception e)
                    {
                        if (!await StateContext.ProcessException(e))
                        {
                            Console.WriteLine("Error: " + e.Message);
                        }
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
                    foreach (var c in (Commands.Concat(StateContext.Commands))
                        .OrderBy(x => x.Value.Order))
                    {
                        var alias = CommandAliases
                            .Where(x => x.Value == c.Key)
                            .Select(x => x.Key)
                            .FirstOrDefault();
                        if (alias == null)
                        {
                            alias = StateContext.CommandAliases
                                .Where(x => x.Value == c.Key)
                                .Select(x => x.Key)
                                .FirstOrDefault();
                        }
                        tab.AddRow(c.Key, alias ?? "", c.Value.Description);
                    }
                    tab.DumpRowNo = false;
                    tab.LeftPadding = 1;
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

        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                NextStateCommands = null;
            }
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
    }
}
