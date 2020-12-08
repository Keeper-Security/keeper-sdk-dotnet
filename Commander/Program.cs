﻿using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using KeeperSecurity.Utils;
using KeeperSecurity.Vault;
using KeeperSecurity.Authentication;

namespace Commander
{
    internal class Program
    {
        private static readonly InputManager InputManager = new InputManager();

        public static InputManager GetInputManager()
        {
            return InputManager;
        }



        public static IExternalLoader CommanderStorage { get; private set; }

        private static void Main()
        {
            Console.CancelKeyPress += (s, e) => { e.Cancel = true; };
            Welcome();

            _ = Task.Run(async () =>
            {
                try
                {
                    await MainLoop();
                }
                catch (Exception e)
                {
                    Console.WriteLine(e.Message);
                }

                Console.WriteLine("Good Bye");
                Environment.Exit(0);
            });

            InputManager.Run();
        }

        internal static void EnqueueCommand(string command)
        {
            _cliContext?.CommandQueue.Enqueue(command);
        }

        private static CliContext _cliContext;

        private static async Task MainLoop()
        {
            ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
            CommanderStorage = StorageUtils.SetupCommanderStorage();
            if (!CommanderStorage.VerifyDatabase())
            {
                throw new Exception("Database is invalid.");
            }

            var ui = new AuthUi(InputManager);
            var storage = CommanderStorage.GetConfigurationStorage(null, new CommanderConfigurationProtection());

            var auth = new Auth(ui, storage);
            auth.Endpoint.DeviceName = "Commander C#";
            auth.Endpoint.ClientVersion = "c15.0.0";
            if (string.IsNullOrEmpty(storage.LastServer))
            {
                Console.WriteLine($"You are connected to the default Keeper server \"{auth.Endpoint.Server}\".");
                Console.WriteLine($"Please use \"server <keeper host name for your region>\" command to choose a different region.");
            }
            else
            {
                Console.WriteLine($"Connected to \"{auth.Endpoint.Server}\".");
            }

            Console.WriteLine();

            var notConnected = new NotConnectedCliContext(auth);
            _cliContext = new CliContext
            {
                StateContext = notConnected
            };
            var lastLogin = storage.LastLogin;
            if (!string.IsNullOrEmpty(lastLogin))
            {
                EnqueueCommand($"login --resume {lastLogin}");
            }

            while (!_cliContext.Finished)
            {
                if (_cliContext.StateContext == null) break;
                if (_cliContext.StateContext.NextStateContext != null)
                {
                    if (!ReferenceEquals(_cliContext.StateContext, _cliContext.StateContext.NextStateContext))
                    {
                        var oldContext = _cliContext.StateContext;
                        _cliContext.StateContext = oldContext.NextStateContext;
                        oldContext.NextStateContext = null;
                        oldContext.Dispose();
                    }
                    else
                    {
                        _cliContext.StateContext.NextStateContext = null;
                    }

                    InputManager.ClearHistory();
                }

                string command;
                if (_cliContext.CommandQueue.Count > 0)
                {
                    command = _cliContext.CommandQueue.Dequeue();
                }
                else
                {
                    if (Console.CursorLeft != 0)
                    {
                        Console.WriteLine();
                    }

                    Console.Write(_cliContext.StateContext.GetPrompt() + "> ");
                    command = await InputManager.ReadLine(new ReadLineParameters
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
                if (_cliContext.CommandAliases.TryGetValue(command, out var fullCommand))
                {
                    command = fullCommand;
                }
                else if (_cliContext.StateContext.CommandAliases.TryGetValue(command, out fullCommand))
                {
                    command = fullCommand;
                }

                if (!_cliContext.Commands.TryGetValue(command, out var cmd))
                {
                    _cliContext.StateContext.Commands.TryGetValue(command, out cmd);
                }

                if (cmd != null)
                {
                    try
                    {
                        await cmd.ExecuteCommand(parameter);
                    }
                    catch (Exception e)
                    {
                        if (!await _cliContext.StateContext.ProcessException(e))
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

                    foreach (var c in (_cliContext.Commands.Concat(_cliContext.StateContext.Commands))
                        .OrderBy(x => x.Value.Order))
                    {
                        Console.WriteLine("    " + c.Key.PadRight(24) + c.Value.Description);
                    }
                }

                Console.WriteLine();
            }
        }

        static void Welcome()
        {
            Console.WriteLine();
            Console.WriteLine(@" _  __                      ");
            Console.WriteLine(@"| |/ /___ ___ _ __  ___ _ _ ");
            Console.WriteLine(@"| ' </ -_) -_) '_ \/ -_) '_|");
            Console.WriteLine(@"|_|\_\___\___| .__/\___|_|  ");
            Console.WriteLine(@"             |_|            ");
            Console.WriteLine(@"password manager & digital vault");
            Console.WriteLine();
            Console.WriteLine();
        }

    }

    class AuthUi : ConsoleAuthUi, IAuthUI, IAuthInfoUI, IPostLoginTaskUI, IAuthSsoUI, IAuthSecurityKeyUI, IUsePassword, IHttpProxyCredentialUi
    {
        public AuthUi(InputManager inputManager): base(inputManager)
        {
        }

        public Func<string, string> UsePassword { get; set; }

        public override async Task<bool> WaitForUserPassword(IPasswordInfo info, CancellationToken token)
        {
            string password = null;
            if (UsePassword != null)
            {
                password = UsePassword(info.Username);
            }

            if (!string.IsNullOrEmpty(password))
            {
                try
                {
                    await info.InvokePasswordActionDelegate(password);
                }
                catch (KeeperAuthFailed)
                {
                }
            }

            return await base.WaitForUserPassword(info, token);
        }

        public async Task<bool> Confirmation(string information)
        {
            Console.WriteLine(information);
            Console.Write("Type \"yes\" to confirm, <Enter> to cancel");

            var answer = await Program.GetInputManager().ReadLine();
            return string.Compare(answer, "yes", StringComparison.OrdinalIgnoreCase) == 0;
        }

        public async Task<string> GetNewPassword(PasswordRuleMatcher matcher)
        {
            string password1 = null;
            while (string.IsNullOrEmpty(password1))
            {
                Console.Write("New Master Password: ");

                password1 = await InputManager.ReadLine(new ReadLineParameters
                {
                    IsSecured = true
                });
                if (string.IsNullOrEmpty(password1)) continue;

                if (matcher == null) continue;

                var failedRules = matcher.MatchFailedRules(password1);
                if (!(failedRules?.Length > 0)) continue;

                password1 = null;

                foreach (var rule in failedRules)
                {
                    Console.WriteLine(rule);
                }
            }

            string password2 = null;
            while (string.IsNullOrEmpty(password2))
            {
                Console.Write("Password Again: ");
                password2 = await InputManager.ReadLine(new ReadLineParameters
                {
                    IsSecured = true
                });
                if (string.CompareOrdinal(password1, password2) == 0) continue;

                Console.WriteLine("Passwords do not match.");
                password2 = null;
            }

            return password1;
        }

        public Task<bool> WaitForSsoToken(ISsoTokenActionInfo actionInfo, CancellationToken token)
        {
            Console.WriteLine($"Complete {(actionInfo.IsCloudSso ? "Cloud" : "OnSite")} SSO login");
            Console.WriteLine($"\nLogin Url:\n\n{actionInfo.SsoLoginUrl}\n");
            var ts = new TaskCompletionSource<bool>();
            _ = Task.Run(async () =>
            {
                Task<string> readTask = null;
                var registration = token.Register(() =>
                {
                    ts.SetCanceled();
                    Program.GetInputManager().InterruptReadTask(readTask);
                });
                try
                {
                    while (!ts.Task.IsCompleted)
                    {
                        Console.WriteLine("Type \"clipboard\" to get token from the clipboard or \"cancel\"");
                        Console.Write("> ");
                        readTask = Program.GetInputManager().ReadLine();
                        var answer = await readTask;
                        switch (answer.ToLowerInvariant())
                        {
                            case "clipboard":
                                var ssoToken = "";
                                var thread = new Thread(() => { ssoToken = Clipboard.GetText(); });
                                thread.SetApartmentState(ApartmentState.STA);
                                thread.Start();
                                thread.Join();
                                if (string.IsNullOrEmpty(ssoToken))
                                {
                                    Console.WriteLine("Clipboard is empty");
                                }
                                else
                                {
                                    Console.WriteLine($"Token:\n{ssoToken}\n\nType \"yes\" to accept this token <Enter> to discard");
                                    Console.Write("> ");
                                    answer = await Program.GetInputManager().ReadLine();
                                    if (answer == "yes")
                                    {
                                        await actionInfo.InvokeSsoTokenAction(ssoToken);
                                    }
                                }

                                break;
                            case "cancel":
                                ts.TrySetResult(false);
                                break;
                        }
                    }
                }
                finally
                {
                    registration.Dispose();
                }
            });
            return ts.Task;
        }

        public void SsoLogoutUrl(string url)
        {
            Console.WriteLine($"\nSSO Logout Url:\n\n{url}\n");
        }

        public Task<bool> WaitForDataKey(IDataKeyChannelInfo[] channels, CancellationToken token)
        {
            var taskSource = new TaskCompletionSource<bool>();

            _ = Task.Run(async () =>
            {
                var actions = channels
                    .Select(x => x.Channel.TryGetDataKeyShareChannelText(out var text) ? text : null)
                    .Where(x => !string.IsNullOrEmpty(x))
                    .ToArray();

                Console.WriteLine("\nRequest Data Key\n");
                Console.WriteLine($"{string.Join("\n", actions.Select(x => $"\"{x}\""))}");
                Console.WriteLine("\"cancel\" to stop waiting.");
                while (true)
                {
                    Console.Write("> ");
                    var answer = await Program.GetInputManager().ReadLine();
                    if (token.IsCancellationRequested) break;
                    if (string.IsNullOrEmpty(answer))
                    {
                        continue;
                    }

                    if (string.Compare("cancel", answer, StringComparison.InvariantCultureIgnoreCase) == 0)
                    {
                        taskSource.TrySetResult(false);
                        break;
                    }

                    if (token.IsCancellationRequested)
                    {
                        break;
                    }

                    var action = channels
                        .Where(x =>
                        {
                            if (x.Channel.TryGetDataKeyShareChannelText(out var text))
                            {
                                return text == answer;
                            }

                            return false;
                        })
                        .FirstOrDefault();
                    if (action != null)
                    {
                        await action.InvokeGetDataKeyAction.Invoke();
                    }
                    else
                    {
                        Console.WriteLine($"Unsupported command {answer}");
                    }
                }
            });

            return taskSource.Task;
        }

        private bool _testedSystemProxy;

        public override Task<bool> WaitForHttpProxyCredentials(IHttpProxyInfo proxyInfo)
        {
            if (!_testedSystemProxy)
            {
                _testedSystemProxy = true;
                if (CredentialManager.GetCredentials(proxyInfo.ProxyUri.DnsSafeHost, out var username, out var password))
                {
                    proxyInfo.InvokeHttpProxyCredentialsDelegate.Invoke(username, password);
                    return Task.FromResult(true);
                }
            }

            return base.WaitForHttpProxyCredentials(proxyInfo);
        }

        public async Task<string> AuthenticateRequests(SecurityKeyAuthenticateRequest[] requests)
        {
            if (requests == null || requests.Length == 0) throw new KeeperCanceled();
            var cancellationSource = new CancellationTokenSource();
            var clientData = new SecurityKeyClientData
            {
                dataType = SecurityKeyClientData.U2F_SIGN,
                challenge = requests[0].challenge,
                origin = requests[0].appId,
            };
            var keyHandles = new List<byte[]>
                {
                    requests[0].keyHandle.Base64UrlDecode()
                };

            foreach (var rq in requests.Skip(1))
            {
                if (rq.challenge == clientData.challenge && rq.appId == clientData.origin)
                {
                    keyHandles.Add(rq.keyHandle.Base64UrlDecode());
                }
            }

            var u2fSignature = await WinWebAuthn.Authenticate.GetAssertion(WinWebAuthn.Authenticate.GetConsoleWindow(), clientData, keyHandles, cancellationSource.Token);
            var signature = new SecurityKeySignature
            {
                clientData = u2fSignature.clientData.Base64UrlEncode(),
                signatureData = u2fSignature.signatureData.Base64UrlEncode(),
                keyHandle = u2fSignature.keyHandle.Base64UrlEncode()
            };
            return Encoding.UTF8.GetString(JsonUtils.DumpJson(signature));
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

    public interface IUsePassword
    {
        Func<string, string> UsePassword { get; set; }
    }
}