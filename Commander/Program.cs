using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using KeeperSecurity;
using KeeperSecurity.Configuration;
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

        private static void Main()
        {
            Console.CancelKeyPress += (s, e) => { e.Cancel = true; };
            Welcome();

            _ = Task.Run(async () =>
            {
                await MainLoop();
                Console.WriteLine("Good Bye");
                Environment.Exit(0);
            });

            InputManager.Run();
        }

        private static CliContext _cliContext;

        private static async Task MainLoop()
        {
            ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
            {
                var storage = new JsonConfigurationStorage();
                storage.Cache.ConfigurationProtection = new CommanderConfigurationProtection();
                var ui = new AuthUi();
                var auth = new Auth(ui, storage);
                auth.Endpoint.DeviceName = "Commander C#";
                auth.Endpoint.ClientVersion = "c15.0.0";
                var notConnected = new NotConnectedCliContext(auth);
                _cliContext = new CliContext
                {
                    StateContext = notConnected
                };
                var lastLogin = storage.LastLogin;
                if (!string.IsNullOrEmpty(lastLogin))
                {
                    _cliContext.CommandQueue.Enqueue($"login --resume {lastLogin}");
                }
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

    class AuthUi : IAuthUI, IAuthInfoUI, IPostLoginTaskUI, IAuthSsoUI, IAuthSecurityKeyUI, IUsePassword, IHttpProxyCredentialUI
    {
        public Func<string, string> UsePassword { get; set; }

        public async Task<bool> WaitForUserPassword(IPasswordInfo info, CancellationToken token)
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

            while (true)
            {
                Console.Write("\nEnter Master Password: ");
                password = await Program.GetInputManager().ReadLine(new ReadLineParameters
                {
                    IsSecured = true
                });
                if (string.IsNullOrEmpty(password)) return false;
                try
                {
                    await info.InvokePasswordActionDelegate(password);
                    break;
                }
                catch (KeeperAuthFailed)
                {
                    Console.WriteLine($"Invalid password");
                }
                catch (Exception e)
                {
                    Console.WriteLine(e.Message);
                }
            }
            return true;
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

                password1 = await Program.GetInputManager().ReadLine(new ReadLineParameters
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
                password2 = await Program.GetInputManager().ReadLine(new ReadLineParameters
                {
                    IsSecured = true
                });
                if (string.CompareOrdinal(password1, password2) == 0) continue;

                Console.WriteLine("Passwords do not match.");
                password2 = null;
            }

            return password1;
        }

        private static string DurationToText(TwoFactorDuration duration)
        {
            switch (duration) {
                case TwoFactorDuration.EveryLogin:
                    return "never";
                case TwoFactorDuration.Forever:
                    return "forever";
                default:
                    return $"{(int) duration} days";
            }
        }

        private static bool TryParseTextToDuration(string text, out TwoFactorDuration duration)
        {
            text = text.Trim().ToLowerInvariant();
            switch (text)
            {
                case "never":
                    duration = TwoFactorDuration.EveryLogin;
                    return true;
                case "forever":
                    duration = TwoFactorDuration.Forever;
                    return true;
                default:
                    var idx = text.IndexOf(' ');
                    if (idx > 0)
                    {
                        text = text.Substring(0, idx);
                    }

                    if (int.TryParse(text, out var days))
                    {
                        foreach (var d in Enum.GetValues(typeof(TwoFactorDuration)).OfType<TwoFactorDuration>())
                        {
                            if ((int) d == days)
                            {
                                duration = d;
                                return true;
                            }
                        }
                    }

                    break;
            }

            duration = TwoFactorDuration.EveryLogin;
            return false;
        }

        public Task<bool> WaitForTwoFactorCode(ITwoFactorChannelInfo[] channels, CancellationToken token)
        {
            var twoFactorTask = new TaskCompletionSource<bool>();
            Task.Run(async () =>
            {
                var cancelCallback = token.Register(() =>
                {
                    twoFactorTask.SetResult(true);
                });
                var pushChannelInfo = new Dictionary<TwoFactorPushAction, ITwoFactorPushInfo>();
                var codeChannelInfo = new Dictionary<TwoFactorChannel, ITwoFactorAppCodeInfo>();
                ITwoFactorAppCodeInfo codeChannel = null;
                {
                    foreach (var ch in channels)
                    {
                        if (ch is ITwoFactorPushInfo pi)
                        {
                            if (pi.SupportedActions == null) continue;
                            foreach (var a in pi.SupportedActions)
                            {
                                if (pushChannelInfo.ContainsKey(a)) continue;
                                pushChannelInfo.Add(a, pi);
                            }
                        }

                        if (ch is ITwoFactorAppCodeInfo aci)
                        {
                            if (codeChannel == null)
                            {
                                codeChannel = aci;
                            }

                            aci.Duration = TwoFactorDuration.Every30Days;

                            if (codeChannelInfo.ContainsKey(ch.Channel)) continue;
                            codeChannelInfo.Add(ch.Channel, aci);
                        }
                    }
                }

                var info = pushChannelInfo.Keys
                    .Select(x => x.TryGetPushActionText(out var text) ? text : null)
                    .Where(x => !string.IsNullOrEmpty(x))
                    .Select(x => $"\"{x}\"")
                    .ToList();
                if (codeChannelInfo.Count > 1)
                {
                    var codes = string.Join(", ", codeChannelInfo.Values.Select(x => x.ChannelName));
                    info.Add($"To switch between app code channels: code=<channel> where channels are {codes}");
                }

                Console.WriteLine("To change default 2FA token persistence use command 2fa=<duration>");
                var dur = Enum
                    .GetValues(typeof(TwoFactorDuration))
                    .OfType<TwoFactorDuration>()
                    .Select(x => $"\"{DurationToText(x)}\"")
                    .ToArray();
                Console.WriteLine("Available durations are: " + string.Join(", ", dur));

                info.Add("<Enter> to Cancel");

                Console.WriteLine("\nTwo Factor Authentication");
                Console.WriteLine(string.Join("\n", info));
                string code;
                while (true)
                {
                    if (codeChannel != null)
                    {
                        Console.Write($"[{codeChannel.ChannelName ?? ""}] ({DurationToText(codeChannel.Duration)})");
                    }
                    Console.Write(" > ");

                    code = await Program.GetInputManager().ReadLine();

                    if (twoFactorTask.Task.IsCompleted) break;
                    if (string.IsNullOrEmpty(code))
                    {
                        twoFactorTask.TrySetResult(false);
                        break;
                    }

                    if (code.StartsWith("code="))
                    {
                        var ch = code.Substring(5);
                        var cha = codeChannelInfo.Values
                            .FirstOrDefault(x => x.ChannelName == ch.ToLowerInvariant());
                        if (cha != null)
                        {
                            codeChannel = cha;
                        }
                        else
                        {
                            Console.WriteLine($"Invalid 2FA code channel: {ch}");
                        }

                        continue;
                    }


                    if (code.StartsWith("2fa="))
                    {
                        if (TryParseTextToDuration(code.Substring(4), out var duration))
                        {
                            if (codeChannel != null)
                            {
                                codeChannel.Duration = duration;
                            }
                        }
                        continue;
                    }

                    if (AuthUIExtensions.TryParsePushAction(code, out var action))
                    {
                        if (pushChannelInfo.ContainsKey(action))
                        {

                            await pushChannelInfo[action].InvokeTwoFactorPushAction(action);
                        }
                        else
                        {
                            Console.WriteLine($"Unsupported 2fa push action: {code}");
                        }

                        continue;
                    }

                    if (codeChannel != null)
                    {
                        try
                        {
                            await codeChannel.InvokeTwoFactorCodeAction(code);
                        }
                        catch (KeeperAuthFailed)
                        {
                            Console.WriteLine("Code is invalid");
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine(e.Message);
                        }
                    }
                }

                cancelCallback.Dispose();
            });
            return twoFactorTask.Task;
        }

        public Task<bool> WaitForDeviceApproval(IDeviceApprovalChannelInfo[] channels, CancellationToken token)
        {
            var deviceApprovalTask = new TaskCompletionSource<bool>();

            Task.Run(async () =>
            {
                var tokenReg = token.Register(() =>
                {
                    deviceApprovalTask.SetResult(false);
                });

                Console.WriteLine("\nDevice Approval\n");
                foreach (var ch in channels)
                {
                    switch (ch.Channel)
                    {
                        case DeviceApprovalChannel.Email:
                            if (ch is IDeviceApprovalPushInfo)
                            {
                                Console.WriteLine("\"email_send\" to resend email");
                            }

                            if (ch is IDeviceApprovalOtpInfo)
                            {
                                Console.WriteLine("\"email_code=<code>\" to validate verification code sent in email");
                            }

                            break;
                        case DeviceApprovalChannel.KeeperPush:
                            Console.WriteLine("\"keeper_push\" to send Keeper Push notification");
                            break;
                        case DeviceApprovalChannel.TwoFactorAuth:
                            if (ch is IDeviceApprovalPushInfo)
                            {
                                Console.WriteLine("\"2fa_send\" to send 2FA code");
                            }

                            if (ch is IDeviceApprovalOtpInfo)
                            {
                                Console.WriteLine("\"2fa_code=<code>\" to validate a code provided by 2FA application");
                            }

                            break;
                    }
                }

                const string twoFactorDurationPrefix = "2fa_duration";
                Console.Write($"\"{twoFactorDurationPrefix}=<duration>\" to change 2FA token persistence. ");
                var dur = Enum
                    .GetValues(typeof(TwoFactorDuration))
                    .OfType<TwoFactorDuration>()
                    .Select(x => $"\"{DurationToText(x)}\"")
                    .ToArray();
                Console.WriteLine("Available durations are: " + string.Join(", ", dur));

                Console.WriteLine("<Enter> to resume\n\"cancel\" to cancel\n");

                var duration = TwoFactorDuration.EveryLogin;

                while (true)
                {
                    Console.Write($"({DurationToText(duration)}) > ");
                    var answer = await Program.GetInputManager().ReadLine();
                    if (string.IsNullOrEmpty(answer))
                    {
                        deviceApprovalTask.SetResult(true);
                        break;
                    }

                    if (string.Compare(answer, "cancel", StringComparison.InvariantCultureIgnoreCase) == 0)
                    {
                        deviceApprovalTask.SetResult(false);
                        return;
                    }

                    Task action = null;
                    if (answer.StartsWith($"{twoFactorDurationPrefix}=", StringComparison.CurrentCultureIgnoreCase))
                    {
                        TryParseTextToDuration(answer.Substring(twoFactorDurationPrefix.Length + 1), out duration);
                    }
                    else if (answer.StartsWith("email_", StringComparison.InvariantCultureIgnoreCase))
                    {
                        var emailAction = channels
                            .FirstOrDefault((x) => x.Channel == DeviceApprovalChannel.Email);
                        if (emailAction != null)
                        {
                            if (answer.StartsWith("email_code=", StringComparison.InvariantCultureIgnoreCase))
                            {
                                if (emailAction is IDeviceApprovalOtpInfo otp)
                                {
                                    var code = answer.Substring("email_code=".Length);
                                    action = otp.InvokeDeviceApprovalOtpAction.Invoke(code);
                                }
                            }
                            else if (string.Compare(answer, "email_send", StringComparison.CurrentCultureIgnoreCase) == 0)
                            {
                                if (emailAction is IDeviceApprovalPushInfo push)
                                {
                                    action = push.InvokeDeviceApprovalPushAction.Invoke();
                                }
                            }
                        }
                    }
                    else if (string.Compare(answer, "keeper_push", StringComparison.InvariantCultureIgnoreCase) == 0)
                    {
                        var keeperPushAction = channels
                            .FirstOrDefault((x) => x.Channel == DeviceApprovalChannel.KeeperPush);
                        if (keeperPushAction != null)
                        {
                            if (keeperPushAction is IDeviceApprovalPushInfo push)
                            {
                                await push.InvokeDeviceApprovalPushAction.Invoke();
                            }
                        }
                    }
                    else if (answer.StartsWith("2fa_", StringComparison.InvariantCultureIgnoreCase))
                    {
                        var tfaAction = channels
                            .FirstOrDefault((x) => x.Channel == DeviceApprovalChannel.TwoFactorAuth);
                        if (tfaAction != null)
                        {
                            if (tfaAction is ITwoFactorDurationInfo dura)
                            {
                                dura.Duration = duration;
                            }

                            if (answer.StartsWith("2fa_code=", StringComparison.InvariantCultureIgnoreCase))
                            {
                                if (tfaAction is IDeviceApprovalOtpInfo otp)
                                {
                                    var code = answer.Substring("2fa_code=".Length);
                                    action = otp.InvokeDeviceApprovalOtpAction.Invoke(code);
                                }
                            }
                            else if (string.Compare(answer, "2fa_send", StringComparison.CurrentCultureIgnoreCase) == 0)
                            {
                                if (tfaAction is IDeviceApprovalPushInfo push)
                                {
                                    action = push.InvokeDeviceApprovalPushAction.Invoke();
                                }
                            }
                        }
                    }
                    else
                    {
                        Console.WriteLine($"Unsupported command: {answer}");
                    }

                    if (action == null) continue;

                    try
                    {
                        await action;
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine(e.Message);
                    }
                }

                tokenReg.Dispose();
            });

            return deviceApprovalTask.Task;
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

        private static IEnumerable<string> ParseProxyAuthentication(string authentication)
        {
            if (!string.IsNullOrEmpty(authentication))
            {
                var pos = authentication.IndexOf(' ');
                if (pos > 0)
                {
                    var methods = authentication.Substring(0, pos).Trim();
                    if (!string.IsNullOrEmpty(methods))
                    {
                        return methods.Split(',').Select(x => x.Trim());
                    }
                }
            }

            return new[] { "Basic" };
        }


        private bool _testedSystemProxy;

        public Task<IWebProxy> GetHttpProxyCredentials(Uri proxyUri, string proxyAuthenticate)
        {
            string username;
            string password;
            var methods = ParseProxyAuthentication(proxyAuthenticate);
            if (!_testedSystemProxy)
            {
                _testedSystemProxy = true;
                if (CredentialManager.GetCredentials(proxyUri.DnsSafeHost, out username, out password))
                {
                    var cred = new NetworkCredential(username, password);
                    var myCache = new CredentialCache();
                    foreach (var method in methods)
                    {
                        myCache.Add(proxyUri, method.TrimEnd(), cred);
                    }

                    return Task.FromResult<IWebProxy>(new WebProxy(proxyUri.DnsSafeHost, proxyUri.Port)
                    {
                        UseDefaultCredentials = false,
                        Credentials = myCache
                    });
                }
            }

            var proxyTask = new TaskCompletionSource<IWebProxy>();
            Task.Run(async () =>
            {
                Console.WriteLine("\nProxy Authentication\n");
                Console.Write("Proxy Username: ");
                username = await Program.GetInputManager().ReadLine();
                if (string.IsNullOrEmpty(username)) proxyTask.TrySetCanceled();

                Console.Write("Proxy Password: ");
                password = await Program.GetInputManager().ReadLine(new ReadLineParameters
                {
                    IsSecured = true
                });
                if (string.IsNullOrEmpty(username)) proxyTask.TrySetCanceled();
                var cred = new NetworkCredential(username, password);
                var myCache = new CredentialCache();
                foreach (var method in methods)
                {
                    myCache.Add(proxyUri, method.TrimEnd(), cred);
                }

                proxyTask.TrySetResult(new WebProxy(proxyUri.DnsSafeHost, proxyUri.Port)
                {
                    UseDefaultCredentials = false,
                    Credentials = myCache
                });
            });

            return proxyTask.Task;
        }

        public void RegionChanged(string newRegion)
        {
            Console.WriteLine();
            Console.WriteLine($"You are being redirected to the data center at: {newRegion}");
            Console.WriteLine();
        }

        public void SelectedDevice(string deviceToken)
        {
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