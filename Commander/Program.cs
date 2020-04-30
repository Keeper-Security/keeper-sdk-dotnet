using System;
using System.Threading.Tasks;
using System.Linq;
using KeeperSecurity.Sdk;
using KeeperSecurity.Sdk.UI;
using System.Net.WebSockets;
using System.Threading;
using System.Diagnostics;

namespace Commander
{
    internal class Program
    {
        private static void Main()
        {
            Console.CancelKeyPress += (s, e) => { Environment.Exit(1); };
            Welcome();

            MainLoop().GetAwaiter().GetResult();

            Console.WriteLine("Good Bye");
        }

        private static CliContext cliContext;

        private static async Task MainLoop()
        {
            {
                var storage = new JsonConfigurationStorage();
                var ui = new Ui();
                var auth = new Auth(ui, storage);
                var notConnected = new NotConnectedCliContext(auth);
                cliContext = new CliContext
                {
                    StateContext = notConnected
                };
                IUserStorage us = storage;
                if (!string.IsNullOrEmpty(us.LastLogin))
                {
                    cliContext.CommandQueue.Enqueue($"login {us.LastLogin}");
                }
            }

            while (!cliContext.Finished)
            {
                if (cliContext.StateContext == null) break;
                if (cliContext.StateContext.NextStateContext != null)
                {
                    cliContext.StateContext = cliContext.StateContext.NextStateContext;
                    cliContext.StateContext.NextStateContext = null;
                }

                string command;
                if (cliContext.CommandQueue.Count > 0)
                {
                    command = cliContext.CommandQueue.Dequeue();
                }
                else
                {
                    Console.Write(cliContext.StateContext.GetPrompt() + "> ");
                    command = Console.ReadLine();
                }

                if (string.IsNullOrEmpty(command)) continue;

                command = command.Trim();
                var parameter = "";
                var pos = command.IndexOf(' ');
                if (pos > 1)
                {
                    parameter = command.Substring(pos + 1).Trim();
                    parameter = parameter.Trim('"');
                    command = command.Substring(0, pos).Trim();
                }

                command = command.ToLowerInvariant();
                if (cliContext.CommandAliases.TryGetValue(command, out var fullCommand))
                {
                    command = fullCommand;
                }
                else if (cliContext.StateContext.CommandAliases.TryGetValue(command, out fullCommand))
                {
                    command = fullCommand;
                }

                if (!cliContext.Commands.TryGetValue(command, out var cmd))
                {
                    cliContext.StateContext.Commands.TryGetValue(command, out cmd);
                }

                if (cmd != null)
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
                        Console.WriteLine($"Invalid command: {command}");
                    }

                    foreach (var c in (cliContext.Commands.Concat(cliContext.StateContext.Commands))
                        .OrderBy(x => x.Value.Order))
                    {
                        Console.WriteLine("    " + c.Key.PadRight(16) + c.Value.Description);
                    }
                }

                Console.WriteLine();
            }
        }

        static void Welcome()
        {
            Console.WriteLine();
            Console.WriteLine(@" _  __  ");
            Console.WriteLine(@"| |/ /___ ___ _ __  ___ _ _ ");
            Console.WriteLine(@"| ' </ -_) -_) '_ \/ -_) '_|");
            Console.WriteLine(@"|_|\_\___\___| .__/\___|_|  ");
            Console.WriteLine(@"             |_|            ");
            Console.WriteLine(@"password manager & digital vault");
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
                return Task.FromResult(string.Compare(answer, "yes", StringComparison.OrdinalIgnoreCase) == 0);
            }

            public Task<string> GetNewPassword(PasswordRuleMatcher matcher)
            {
                string password1 = null;
                while (string.IsNullOrEmpty(password1))
                {
                    Console.Write("New Master Password: ");

                    password1 = HelperUtils.ReadLineMasked();
                    if (string.IsNullOrEmpty(password1)) continue;

                    if (matcher == null) continue;

                    var failedRules = matcher.MatchFailedRules(password1);
                    if (!(failedRules?.Length > 0)) continue;

                    password1 = null;
                    if (!string.IsNullOrEmpty(matcher.RuleIntro))
                    {
                        Console.WriteLine(matcher.RuleIntro);
                    }

                    foreach (var rule in failedRules)
                    {
                        Console.WriteLine(rule);
                    }
                }

                string password2 = null;
                while (string.IsNullOrEmpty(password2))
                {
                    Console.Write("Password Again: ");
                    password2 = HelperUtils.ReadLineMasked();
                    if (string.CompareOrdinal(password1, password2) == 0) continue;

                    Console.WriteLine("Passwords do not match.");
                    password2 = null;
                }

                return Task.FromResult(password1);
            }

            public Task<TwoFactorCode> GetTwoFactorCode(TwoFactorCodeChannel channel)
            {
                return Task.Run(() =>
                {
                    Console.Write("Enter Code: ");
                    var code = Console.ReadLine();
                    return new TwoFactorCode(code, TwoFactorCodeDuration.Forever);
                });
            }

            string DuoPasscode { get; set; }

            public Task<TwoFactorCode> GetDuoTwoFactorResult(DuoAccount account, CancellationToken token)
            {
                return Task.Run(() =>
                {
                    if (!string.IsNullOrEmpty(account.PushNotificationUrl))
                    {
                        DuoPasscode = null;
                        _ = Task.Run(async () =>
                        {
                            var ws = new ClientWebSocket();
                            try
                            {
                                await ws.ConnectAsync(new Uri(account.PushNotificationUrl), token);
                                var buffer = new byte[1024];
                                var segment = new ArraySegment<byte>(buffer);
                                while (ws.State == WebSocketState.Open)
                                {
                                    var rs = await ws.ReceiveAsync(segment, token);
                                    if (rs == null) break;
                                    if (rs.Count <= 0) continue;

                                    var notification = new byte[rs.Count];
                                    Array.Copy(buffer, notification, rs.Count);
                                    var passcode = account.ParseDuoPasscodeNotification(notification);
                                    if (string.IsNullOrEmpty(passcode)) continue;
                                    DuoPasscode = passcode;
                                    Console.WriteLine("Press Enter to continue");
                                }
                            }
                            catch (OperationCanceledException)
                            {
                            }
                            catch (Exception e)
                            {
                                Debug.WriteLine(e);
                            }
                            finally
                            {
                                if (ws.State == WebSocketState.Open)
                                {
                                    await ws.CloseAsync(WebSocketCloseStatus.NormalClosure, "", CancellationToken.None);
                                }

                                ws.Dispose();
                            }
                        }, token);
                    }

                    string input;
                    while (true)
                    {
                        Console.WriteLine(
                            "Type:\n\"push\" for DUO push\t\"sms\" for DUO text message\nDUO app code\tKeeper backup code\t<Enter> to Cancel");
                        Console.Write("> ");
                        input = Console.ReadLine();
                        if (!string.IsNullOrEmpty(DuoPasscode))
                        {
                            input = DuoPasscode;
                            DuoPasscode = null;
                            break;
                        }

                        if (!string.IsNullOrEmpty(input))
                        {
                            break;
                        }
                    }

                    return new TwoFactorCode(input, TwoFactorCodeDuration.Forever);
                }, token);
            }

            public void DuoRequireEnrollment(string enrollmentUrl)
            {
                Console.WriteLine($"Complete Duo Enrollment by visiting: {enrollmentUrl}");
            }
        }
    }
}