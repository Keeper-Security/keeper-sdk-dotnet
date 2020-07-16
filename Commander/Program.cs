using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Linq;
using KeeperSecurity.Sdk;
using KeeperSecurity.Sdk.UI;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading;
using System.Windows.Forms;

namespace Commander
{
    internal class Program
    {
        [DllImport("user32.dll")]
        static extern IntPtr GetForegroundWindow();

        [DllImport("user32.dll")]
        private static extern bool PostMessage(IntPtr hWnd, uint msg, int wParam, int lParam);

        const int VK_RETURN = 0x0D;
        const int WM_KEYDOWN = 0x100;

        private static IntPtr ConsoleHwnd;

        private static void Main()
        {
            Console.CancelKeyPress += (s, e) => { Environment.Exit(1); };
            Welcome();
            ConsoleHwnd = GetForegroundWindow();

            MainLoop().GetAwaiter().GetResult();

            Console.WriteLine("Good Bye");
        }

        private static CliContext cliContext;

        private static async Task MainLoop()
        {

            {
                var storage = new JsonConfigurationStorage();
                storage.Cache.StorageProtection = new CommanderStorageProtection();
                var ui = new Ui();
                var auth = new Auth(ui, storage);
                auth.Endpoint.DeviceName = "Commander C#";
                var version = System.Diagnostics.FileVersionInfo.GetVersionInfo(Assembly.GetExecutingAssembly().Location);
                auth.Endpoint.ClientVersion = "c15.0.0";
                var notConnected = new NotConnectedCliContext(auth);
                cliContext = new CliContext
                {
                    StateContext = notConnected
                };
                var lastLogin = storage.LastLogin;
                if (!string.IsNullOrEmpty(lastLogin))
                {
                    cliContext.CommandQueue.Enqueue($"login --resume {lastLogin}");
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
                        if (!await cliContext.StateContext.ProcessException(e))
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
            Console.WriteLine(@" _  __                      ");
            Console.WriteLine(@"| |/ /___ ___ _ __  ___ _ _ ");
            Console.WriteLine(@"| ' </ -_) -_) '_ \/ -_) '_|");
            Console.WriteLine(@"|_|\_\___\___| .__/\___|_|  ");
            Console.WriteLine(@"             |_|            ");
            Console.WriteLine(@"password manager & digital vault");
            Console.WriteLine();
            Console.WriteLine();
        }

        internal static void CompleteReadLine()
        {
            PostMessage(ConsoleHwnd, WM_KEYDOWN, VK_RETURN, 0);
        }

        class Ui : IAuthUI, IPostLoginTaskUI, IAuthSsoUI, IUsePassword, IHttpProxyCredentialUI
        {
            public Func<string, string> UsePassword { get; set; }

            public Task<string> GetMasterPassword(string username)
            {
                string password = null;
                if (UsePassword != null)
                {
                    password = UsePassword(username);
                }

                if (string.IsNullOrEmpty(password))
                {
                    Console.Write("\nEnter Master Password: ");
                    password = HelperUtils.ReadLineMasked();
                }

                return Task.FromResult(password);
            }

            public Task<bool> Confirmation(string information)
            {
                Console.WriteLine(information);
                Console.Write("Type \"yes\" to confirm, <Enter> to cancel");

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

            private static string DurationToText(TwoFactorDuration duration)
            {
                switch (duration)
                {
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

            public Task<TwoFactorCode> GetTwoFactorCode(TwoFactorChannel channel, ITwoFactorChannelInfo[] channels, CancellationToken token)
            {
                var twoFactorTask = new TaskCompletionSource<TwoFactorCode>();
                Task.Run(async () =>
                {
                    var cancelCallback = token.Register(() =>
                    {
                        twoFactorTask.SetResult(null);
                        CompleteReadLine();
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

                    var duration = TwoFactorDuration.Every30Days;
                    Console.WriteLine("\nTwo Factor Authentication");
                    Console.WriteLine(string.Join("\n", info));
                    string code;
                    while (true)
                    {
                        Console.Write($"[{codeChannel?.ChannelName ?? ""}] ({DurationToText(duration)}) > ");
                        code = Console.ReadLine();

                        if (twoFactorTask.Task.IsCompleted) break;
                        if (string.IsNullOrEmpty(code))
                        {
                            twoFactorTask.TrySetException(new KeeperCanceled());
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
                            TryParseTextToDuration(code.Substring(4), out duration);
                            continue;
                        }

                        if (AuthUIExtensions.TryParsePushAction(code, out var action))
                        {
                            if (pushChannelInfo.ContainsKey(action))
                            {
                                await pushChannelInfo[action].InvokeTwoFactorPushAction(action, duration);
                            }
                            else
                            {
                                Console.WriteLine($"Unsupported 2fa push action: {code}");
                            }

                            continue;
                        }

                        break;
                    }

                    if (!twoFactorTask.Task.IsCompleted)
                    {
                        twoFactorTask.SetResult(new TwoFactorCode(codeChannel?.Channel ?? TwoFactorChannel.Other, code, duration));
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
                        CompleteReadLine();
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

                    Console.WriteLine("To change default 2FA token persistence use command 2fa=<duration>");
                    var dur = Enum
                        .GetValues(typeof(TwoFactorDuration))
                        .OfType<TwoFactorDuration>()
                        .Select(x => $"\"{DurationToText(x)}\"")
                        .ToArray();
                    Console.WriteLine("Available durations are: " + string.Join(", ", dur));

                    Console.WriteLine("<Enter> to resume\n\"q\" to cancel\n");

                    var duration = TwoFactorDuration.EveryLogin;

                    while (true)
                    {
                        Console.Write($"({DurationToText(duration)}) > ");
                        var answer = Console.ReadLine();
                        if (string.IsNullOrEmpty(answer))
                        {
                            deviceApprovalTask.SetResult(true);
                            break;
                        }
                        
                        if (string.Compare(answer, "q", StringComparison.InvariantCultureIgnoreCase) == 0)
                        {
                            deviceApprovalTask.SetResult(false);
                            return;
                        }

                        if (answer.StartsWith("2fa=", StringComparison.CurrentCultureIgnoreCase))
                        {
                            TryParseTextToDuration(answer.Substring(4), out duration);
                            continue;
                        }

                        if (answer.StartsWith("email_", StringComparison.InvariantCultureIgnoreCase))
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
                                        await otp.InvokeDeviceApprovalOtpAction.Invoke(code, duration);
                                    }
                                }
                                else if (string.Compare(answer, "email_send", StringComparison.CurrentCultureIgnoreCase) == 0)
                                {
                                    if (emailAction is IDeviceApprovalPushInfo push)
                                    {
                                        await push.InvokeDeviceApprovalPushAction(duration);
                                    }
                                }
                            }
                            continue;
                        }

                        if (string.Compare(answer, "keeper_push", StringComparison.InvariantCultureIgnoreCase) == 0)
                        {
                            var keeperPushAction = channels
                                .FirstOrDefault((x) => x.Channel == DeviceApprovalChannel.KeeperPush);
                            if (keeperPushAction != null)
                            {
                                if (keeperPushAction is IDeviceApprovalPushInfo push)
                                {
                                    await push.InvokeDeviceApprovalPushAction(duration);
                                }
                            }
                            continue;
                        }

                        if (answer.StartsWith("2fa_", StringComparison.InvariantCultureIgnoreCase))
                        {
                            var tfaAction = channels
                                .FirstOrDefault((x) => x.Channel == DeviceApprovalChannel.TwoFactorAuth);
                            if (tfaAction != null)
                            {
                                if (answer.StartsWith("2fa_code=", StringComparison.InvariantCultureIgnoreCase))
                                {
                                    if (tfaAction is IDeviceApprovalOtpInfo otp)
                                    {
                                        var code = answer.Substring("2fa_code=".Length);
                                        await otp.InvokeDeviceApprovalOtpAction.Invoke(code, duration);
                                    }
                                }
                                else if (string.Compare(answer, "2fa_send", StringComparison.CurrentCultureIgnoreCase) == 0)
                                {
                                    if (tfaAction is IDeviceApprovalPushInfo push)
                                    {
                                        await push.InvokeDeviceApprovalPushAction(duration);
                                    }
                                }
                            }
                            continue;
                        }

                        Console.WriteLine($"Unsupported command: {answer}");
                    }

                    tokenReg.Dispose();
                });

                return deviceApprovalTask.Task;
            }

            public Task<string> GetSsoToken(string url, bool isCloudSso)
            {
                Console.WriteLine($"Complete {(isCloudSso ? "Cloud" : "OnSite")} SSO login");
                Console.WriteLine($"\nLogin Url:\n\n{url}\n");
                var ts = new TaskCompletionSource<string>();
                _ = Task.Run(() =>
                {
                    while (!ts.Task.IsCompleted)
                    {
                        Console.WriteLine("Type \"clipboard\" to get token from the clipboard or \"cancel\"");
                        Console.Write("> ");
                        var answer = Console.ReadLine();
                        switch (answer.ToLowerInvariant())
                        {
                            case "clipboard":
                                var token = "";
                                var thread = new Thread(() => { token = Clipboard.GetText(); });
                                thread.SetApartmentState(ApartmentState.STA);
                                thread.Start();
                                thread.Join();
                                if (string.IsNullOrEmpty(token))
                                {
                                    Console.WriteLine("Clipboard is empty");
                                }
                                else
                                {
                                    Console.WriteLine($"Token:\n{token}\n\nType \"yes\" to accept this token <Enter> to discard");
                                    Console.Write("> ");
                                    answer = Console.ReadLine();
                                    if (answer == "yes")
                                    {
                                        ts.TrySetResult(token);
                                    }
                                }

                                break;
                            case "cancel":
                                ts.TrySetException(new KeeperCanceled());
                                break;
                        }
                    }
                });
                return ts.Task;
            }

            public Task<bool> WaitForDataKey(IGetDataKeyChannelInfo[] channels, CancellationToken token)
            {
                var taskSource = new TaskCompletionSource<bool>();

                _ = Task.Run(async () =>
                {
                    var actions = channels
                        .OfType<IGetDataKeyActionInfo>()
                        .Select(x => x.Channel.TryGetDataKeyShareChannelText(out var text) ? text : null)
                        .Where(x => !string.IsNullOrEmpty(x))
                        .ToArray();

                    Console.WriteLine($"Type {string.Join(", ", actions.Select(x => $"\"{x}\""))} to request data key");
                    Console.WriteLine("or \"cancel\" to stop waiting.");
                    var reg = token.Register(CompleteReadLine);
                    while (true)
                    {
                        Console.Write("> ");
                        var answer = Console.ReadLine();
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
                            .OfType<IGetDataKeyActionInfo>()
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

                    reg.Dispose();
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

                return new[] {"Basic"};
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
                Task.Run(() =>
                {
                    Console.WriteLine("\nProxy Authentication\n");
                    Console.Write("Proxy Username: ");
                    username = Console.ReadLine();
                    if (string.IsNullOrEmpty(username)) proxyTask.TrySetCanceled();

                    Console.Write("Proxy Password: ");
                    password = HelperUtils.ReadLineMasked();
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
        }
    }

    public interface IUsePassword
    {
        Func<string, string> UsePassword { get; set; }
    }
}