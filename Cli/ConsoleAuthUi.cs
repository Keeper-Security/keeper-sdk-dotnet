using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using KeeperSecurity.Authentication;
using KeeperSecurity.Authentication.Async;
using KeeperSecurity.Utils;

#if NET472_OR_GREATER
using System.Windows;
using System.Text;
#endif

namespace Cli.Async
{
    /// <exclude/>
    public class ConsoleAuthUi : IAuthUI, IAuthInfoUI, IAuthSsoUI
    {
        protected InputManager InputManager { get; }

        public static string BiometricKeyTag = "bio";
        protected byte[] BiometricKey { get; set; }
        protected byte[] DeviceToken { get; private set; }

        public ConsoleAuthUi(InputManager inputManager)
        {
            InputManager = inputManager;
        }

        public void SelectedDevice(string deviceToken)
        {
            BiometricKey = null;
            DeviceToken = deviceToken.Base64UrlDecode();
        }

        public virtual async Task<bool> WaitForUserPassword(IPasswordInfo info, CancellationToken token)
        {
            while (true)
            {
                Console.Write("\nEnter Master Password: ");
                var password = await InputManager.ReadLine(new ReadLineParameters
                {
                    IsSecured = true
                });
                if (string.IsNullOrEmpty(password)) return false;
                try
                {
                    if (BiometricKey != null && string.CompareOrdinal(BiometricKeyTag, password) == 0)
                    {
                        await info.InvokeBiometricsActionDelegate(BiometricKey);
                    }
                    else
                    {
                        await info.InvokePasswordActionDelegate(password);
                    }

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

        public virtual Task<bool> WaitForTwoFactorCode(ITwoFactorChannelInfo[] channels, CancellationToken token)
        {
            var twoFactorTask = new TaskCompletionSource<bool>();
            Task.Run(async () =>
            {
                var cancelCallback = token.Register(() => { twoFactorTask.SetResult(true); });
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
                    .Select(x => x.GetPushActionText())
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
                    .Select(x => $"\"{AuthUIExtensions.DurationToText(x)}\"")
                    .ToArray();
                Console.WriteLine("Available durations are: " + string.Join(", ", dur));

                info.Add("<Enter> to Cancel");

                Console.WriteLine("\nTwo Factor Authentication");
                Console.WriteLine(string.Join("\n", info));
                while (true)
                {
                    if (codeChannel != null)
                    {
                        Console.Write($"[{codeChannel.ChannelName ?? ""}] ({AuthUIExtensions.DurationToText(codeChannel.Duration)})");
                    }

                    Console.Write(" > ");

                    var code = await InputManager.ReadLine();

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
                        if (AuthUIExtensions.TryParseTextToDuration(code.Substring(4), out var duration))
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
                            try
                            {
                                await pushChannelInfo[action].InvokeTwoFactorPushAction(action);
                            }
                            catch (Exception e)
                            {
                                Console.WriteLine(e.Message);
                            }
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
            },
                token);
            return twoFactorTask.Task;
        }

        public virtual Task<bool> WaitForDeviceApproval(IDeviceApprovalChannelInfo[] channels, CancellationToken token)
        {
            var deviceApprovalTask = new TaskCompletionSource<bool>();

            Task.Run(async () =>
            {
                var tokenReg = token.Register(() => { deviceApprovalTask.SetResult(false); });

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
                    .Select(x => $"\"{AuthUIExtensions.DurationToText(x)}\"")
                    .ToArray();
                Console.WriteLine("Available durations are: " + string.Join(", ", dur));

                Console.WriteLine("<Enter> to resume\n\"cancel\" to cancel\n");

                var duration = TwoFactorDuration.EveryLogin;

                while (true)
                {
                    Console.Write($"({AuthUIExtensions.DurationToText(duration)}) > ");
                    var answer = await InputManager.ReadLine();
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
                        AuthUIExtensions.TryParseTextToDuration(answer.Substring(twoFactorDurationPrefix.Length + 1), out duration);
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
            },
                token);

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
                    InputManager.InterruptReadTask(readTask);
                });
                try
                {
                    while (!ts.Task.IsCompleted)
                    {
#if NET472_OR_GREATER
                        Console.WriteLine("Type \"clipboard\" to get token from the clipboard or \"cancel\"");
#else
                        Console.WriteLine("Paste SSO token or \"cancel\"");
#endif
                        Console.Write("> ");
                        readTask = InputManager.ReadLine();
                        var answer = await readTask;
                        switch (answer.ToLowerInvariant())
                        {
#if NET472_OR_GREATER
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
                                    answer = await InputManager.ReadLine();
                                    if (answer == "yes")
                                    {
                                        await actionInfo.InvokeSsoTokenAction(ssoToken);
                                    }
                                }
                                break;
#endif
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
                    .Select(x => x.Channel.SsoDataKeyShareChannelText())
                    .Where(x => !string.IsNullOrEmpty(x))
                    .ToArray();

                Console.WriteLine("\nRequest Data Key\n");
                Console.WriteLine($"{string.Join("\n", actions.Select(x => $"\"{x}\""))}");
                Console.WriteLine("\"cancel\" to stop waiting.");
                while (true)
                {
                    Console.Write("> ");
                    var answer = await InputManager.ReadLine();
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
                        .FirstOrDefault(x => x.Channel.SsoDataKeyShareChannelText() == answer);
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

        public void RegionChanged(string newRegion)
        {
            Console.WriteLine();
            Console.WriteLine($"You are being redirected to the data center at: {newRegion}");
            Console.WriteLine();
        }
    }

#if NET472_OR_GREATER
    class WinAuthUi : ConsoleAuthUi, IAuthSecurityKeyUI
    {
        public WinAuthUi(InputManager inputManager) : base(inputManager)
        {
        }

        public async Task<string> AuthenticatePublicKeyRequest(PublicKeyCredentialRequestOptions request)
        {
            if (request == null || string.IsNullOrEmpty(request.challenge))
            {
                throw new Exception("Security key challenge is empty. Try another 2FA method.");
            }
            var cancellationSource = new CancellationTokenSource();


            var webAuthnSignature = await WinWebAuthn.Authenticate.GetAssertion(WinWebAuthn.Authenticate.GetConsoleWindow(), request, cancellationSource.Token);
            var signature = new KeeperWebAuthnSignature
            {
                id = webAuthnSignature.credentialId.Base64UrlEncode(),
                rawId = webAuthnSignature.credentialId.Base64UrlEncode(),
                response = new SignatureResponse
                {
                    authenticatorData = webAuthnSignature.authenticatorData.Base64UrlEncode(),
                    clientDataJSON = webAuthnSignature.clientData.Base64UrlEncode(),
                    signature = webAuthnSignature.signatureData.Base64UrlEncode(),
                },
                type = "public-key",
                clientExtensionResults = new ClientExtensionResults(),
            };
            return Encoding.UTF8.GetString(JsonUtils.DumpJson(signature, false));
        }
    }
#endif

}
