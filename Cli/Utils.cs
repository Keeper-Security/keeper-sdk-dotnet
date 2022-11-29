using KeeperSecurity.Authentication;
using KeeperSecurity.Authentication.Sync;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;

#if NET472_OR_GREATER
using System.Text;
using System.Threading;
using KeeperSecurity.Utils;
#endif

namespace Cli
{
    public static class Utils
    {
        public static void Welcome()
        {
            string version = null;
            string product = null;
            try
            {
                var ver = FileVersionInfo.GetVersionInfo(Process.GetCurrentProcess().MainModule.FileName);
                if (ver != null && ver.ProductMajorPart > 0)
                {
                    version = $"{ver.ProductMajorPart}.{ver.ProductMinorPart}.{ver.ProductBuildPart}";
                    product = ver.ProductName;
                }
            }
            catch { }

            if (string.IsNullOrEmpty(version)) {
                try
                {
                    version = Assembly.GetEntryAssembly()?.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
                    product = Assembly.GetEntryAssembly()?.GetCustomAttribute<AssemblyProductAttribute>()?.Product;
                }
                catch { }
            }
            if (!string.IsNullOrEmpty(version))
            {
                version = "v" + version;
            }

            // https://stackoverflow.com/questions/30418886/how-and-why-does-quickedit-mode-in-command-prompt-freeze-applications
            // https://stackoverflow.com/questions/13656846/how-to-programmatic-disable-c-sharp-console-applications-quick-edit-mode
            // Application freezes on start up eventually.
            Console.WriteLine();
            Console.WriteLine(@" _  __                      ");
            Console.WriteLine(@"| |/ /___ ___ _ __  ___ _ _ ");
            Console.WriteLine(@"| ' </ -_) -_) '_ \/ -_) '_|");
            Console.WriteLine(@"|_|\_\___\___| .__/\___|_|  ");
            Console.WriteLine(@"             |_|            ");
            Console.WriteLine(@"password manager & digital vault");
            Console.WriteLine($"{product ?? ""} {version ?? ""}");
            Console.WriteLine();
            Console.WriteLine("Type \"?\" for command help");
            Console.WriteLine();
        }

        public static async Task LoginToKeeper(AuthSync auth, InputManager inputManager, string username = null, string[] passwords = null)
        {
            auth.Cancel();
            var email = username;
            if (string.IsNullOrEmpty(username))
            {
                email = auth.Storage.LastLogin;
                Console.Write("User name: ");
                email = await inputManager.ReadLine(new ReadLineParameters
                {
                    IsHistory = false,
                    Text = email ?? ""
                });
                if (string.IsNullOrEmpty(email))
                {
                    return;
                }
            }
            else
            {
                Console.WriteLine($"Username: {email}");
            }

            var passwds = new List<string>();
            if (passwords != null)
            {
                passwds.AddRange(passwords);
            }

            var uc = auth.Storage.Users.Get(email);
            if (!string.IsNullOrEmpty(uc?.Password))
            {
                if (!passwds.Contains(uc.Password))
                {
                    passwds.Add(uc.Password);
                }
            }

            await auth.Login(email, passwds.ToArray());

            await LoginFlow(auth, inputManager);
        }

        public static async Task LoginToSsoProvider(AuthSync auth, InputManager inputManager, string providerName = null)
        {
            auth.Cancel();
            var provider = providerName;
            if (string.IsNullOrEmpty(provider))
            {
                Console.Write("SSO provider: ");
                provider = await inputManager.ReadLine(new ReadLineParameters
                {
                    IsHistory = false
                });
                if (string.IsNullOrEmpty(provider))
                {
                    return;
                }
            }

            await auth.LoginSso(provider);

            await LoginFlow(auth, inputManager);
        }

        private static async Task LoginFlow(AuthSync auth, InputManager inputManager)
        {
            Task<string> readTask = null;
            string answer = null;
#if NET472_OR_GREATER
            auth.UiCallback = new WindowsAuthSyncCallback(() =>
            {
                if (readTask != null && !readTask.IsCompleted)
                {
                    Console.WriteLine();
                    inputManager.InterruptReadTask(readTask);
                }
            });
#else
            auth.UiCallback = new AuthSyncCallback(() =>
            {
                if (readTask != null && !readTask.IsCompleted)
                {
                    Console.WriteLine();
                    inputManager.InterruptReadTask(readTask);
                }
            });
#endif

            while (!auth.IsCompleted)
            {
                switch (auth.Step)
                {
                    case DeviceApprovalStep das:
                        Console.WriteLine("\nDevice Approval\n");
                        Console.WriteLine("\"email_send\" to resend email");
                        Console.WriteLine("\"email_code=<code>\" to validate verification code sent in email");
                        Console.WriteLine("\"keeper_push\" to send Keeper Push notification");
                        Console.WriteLine("\"2fa_send\" to send 2FA code");
                        Console.WriteLine("\"2fa_code=<code>\" to validate a code provided by 2FA application");
                        Console.WriteLine("\"resume\" to resume\n\"cancel\" to cancel\n");

                        while (true)
                        {
                            Console.Write("Device Approval > ");
                            readTask = inputManager.ReadLine();
                            try
                            {
                                answer = await readTask;
                            }
                            catch (TaskCanceledException)
                            {
                                break;
                            }
                            if (string.Compare(answer, "cancel", StringComparison.InvariantCultureIgnoreCase) == 0)
                            {
                                auth.Cancel();
                                return;
                            }
                            if (string.Compare(answer, "resume", StringComparison.InvariantCultureIgnoreCase) == 0)
                            {
                                await das.Resume();
                                break;
                            }
                            try
                            {
                                if (answer == "email_send")
                                {
                                    await das.SendPush(DeviceApprovalChannel.Email);
                                }
                                else if (answer == "keeper_push")
                                {
                                    await das.SendPush(DeviceApprovalChannel.KeeperPush);
                                }
                                else if (answer == "2fa_send")
                                {
                                    await das.SendPush(DeviceApprovalChannel.TwoFactorAuth);
                                }
                                else if (answer.StartsWith("email_code="))
                                {
                                    var code = answer.Substring("email_code=".Length);
                                    await das.SendCode(DeviceApprovalChannel.Email, code);
                                    break;
                                }
                                else if (answer.StartsWith("2fa_code="))
                                {
                                    var code = answer.Substring("2fa_code=".Length);
                                    await das.SendCode(DeviceApprovalChannel.TwoFactorAuth, code);
                                    break;
                                }
                            }
                            catch (KeeperAuthFailed)
                            {
                                Console.WriteLine("\nCode is invalid or expired.");
                            }
                            catch (Exception e)
                            {
                                Console.WriteLine(e.Message);
                            }
                        }
                        break;

                    case TwoFactorStep tfs:
                        const string twoFactorDurationPrefix = "2fa";
                        Console.WriteLine($"\nTo change default 2FA token persistence use command {twoFactorDurationPrefix}=<duration>");
                        var dur = Enum
                            .GetValues(typeof(TwoFactorDuration))
                            .OfType<TwoFactorDuration>()
                            .Select(x => $"{AuthUIExtensions.DurationToText(x)}")
                            .ToArray();
                        Console.WriteLine("Available durations are: " + string.Join(", ", dur.Select(x => $"\"{x}\"")));
                        if (tfs.Channels.Length > 1)
                        {
                            Console.WriteLine("'NO' or \"channel=NO\" to change 2FA channel");
                        }
                        Console.WriteLine("\"resume\" to Resume\n\"cancel\" to Cancel");


                        Console.WriteLine("\nTwo Factor Authentication");
                        for (var i = 0; i < tfs.Channels.Length; i++)
                        {
                            var phoneNumber = tfs.GetPhoneNumber(tfs.Channels[i]);
                            if (!string.IsNullOrEmpty(phoneNumber))
                            {
                                phoneNumber = $"({phoneNumber})";
                            }
                            var name = "";
                            Console.WriteLine($"   {i + 1}. [{AuthUIExtensions.GetTwoFactorChannelText(tfs.Channels[i])}]: {name} {phoneNumber}");
                            var pushes = tfs.GetChannelPushActions(tfs.Channels[i]);
                            if (pushes.Length > 0)
                            {
                                var push_text = pushes.Select(x => $"\"{AuthUIExtensions.GetPushActionText(x)}\"").ToArray();

                                Console.WriteLine($"      {string.Join(", ", push_text)}");
                            }
                        }

                        while (true)
                        {
                            var pushActions = tfs.GetChannelPushActions(tfs.DefaultChannel).Select(x => AuthUIExtensions.GetPushActionText(x)).ToArray();
                            Console.Write($"[{AuthUIExtensions.GetTwoFactorChannelText(tfs.DefaultChannel)}] ({AuthUIExtensions.DurationToText(tfs.Duration)})");
                            Console.Write("> ");
                            readTask = inputManager.ReadLine();
                            try
                            {
                                answer = await readTask;
                            }
                            catch (TaskCanceledException)
                            {
                                break;
                            }
                            if (string.IsNullOrEmpty(answer))
                            {
                                continue;
                            }
                            if (string.Compare(answer, "cancel", StringComparison.InvariantCultureIgnoreCase) == 0)
                            {
                                auth.Cancel();
                                return;
                            }
                            if (string.Compare(answer, "resume", StringComparison.InvariantCultureIgnoreCase) == 0)
                            {
                                await tfs.Resume();
                                break;
                            }

                            try
                            {
                                if (int.TryParse(answer, out var channelNo))
                                {
                                    if (channelNo > 0 && channelNo <= tfs.Channels.Length)
                                    {
                                        answer = $"channel={channelNo}";
                                    }
                                }
                                else if (dur.Any(x => answer == x))
                                {
                                    answer = $"{twoFactorDurationPrefix}={answer}";
                                }
                                if (answer.StartsWith("channel="))
                                {
                                    var no = answer.Substring("channel=".Length);
                                    if (int.TryParse(no, out var n))
                                    {
                                        if (n > 0 && n <= tfs.Channels.Length)
                                        {
                                            tfs.DefaultChannel = tfs.Channels[n - 1];
                                        }
                                        else
                                        {
                                            Console.WriteLine($"Incorrect 2FA channel index: {n}. Valid: 1-{tfs.Channels.Length}");
                                        }
                                    }
                                    else
                                    {
                                        Console.WriteLine($"2FA channel index {no}. Valid: 1-{tfs.Channels.Length}");
                                    }
                                }
                                else if (answer.StartsWith($"{twoFactorDurationPrefix}="))
                                {
                                    var text = answer.Substring(twoFactorDurationPrefix.Length + 1);
                                    if (AuthUIExtensions.TryParseTextToDuration(text, out var duration))
                                    {
                                        tfs.Duration = duration;
                                    }
                                    else
                                    {
                                        Console.WriteLine($"Invalid 2FA token duration: {text}");
                                    }
                                }
                                else if (pushActions.Any(x => x == answer))
                                {
                                    if (AuthUIExtensions.TryParsePushAction(answer, out var push))
                                    {
                                        await tfs.SendPush(push);
                                        break;
                                    }
                                }
                                else
                                {
                                    await tfs.SendCode(tfs.DefaultChannel, answer);
                                    break;
                                }
                            }
                            catch (KeeperAuthFailed)
                            {
                                Console.WriteLine("\nCode is invalid or expired.");
                            }
                            catch (Exception e)
                            {
                                Console.WriteLine(e.Message);
                            }
                        }
                        break;

                    case PasswordStep ps:
                        while (true)
                        {
                            readTask = null;
                            Console.Write("Enter Master Password: ");
                            var password = await inputManager.ReadLine(new ReadLineParameters
                            {
                                IsSecured = true
                            });
                            if (string.IsNullOrEmpty(password))
                            {
                                auth.Cancel();
                                return;
                            }
                            try
                            {
                                await ps.VerifyPassword(password);
                                break;
                            }
                            catch (KeeperAuthFailed)
                            {
                                Console.WriteLine("\nInvalid password.");
                            }
                            catch (Exception e)
                            {
                                Console.WriteLine(e.Message);
                            }
                        }
                        break;

                    case SsoTokenStep sts:
                        Console.WriteLine($"Complete {(sts.IsCloudSso ? "Cloud" : "OnSite")} SSO login");
                        Console.WriteLine($"\nSSO Login Url:\n{sts.SsoLoginUrl}\n");
                        Console.WriteLine("Navigate to SSO Login URL with your browser and complete login.");
                        Console.WriteLine("Copy a returned SSO token into clipboard.");
                        Console.WriteLine("Paste that token into the application");
                        Console.WriteLine("NOTE: To copy SSO Token please click \"Copy login token\" button on \"SSO Connect\" page.");
                        Console.WriteLine();
                        Console.WriteLine("'a' or \"password\" to login with master password");
#if NET472_OR_GREATER
                        Console.WriteLine("'o' or \"open\" to default browser");
                        Console.WriteLine("'c' or \"copy\" SSO Login URL to clipboard");
                        Console.WriteLine("'p' or \"paste\" SSO Token from clipboard");
#endif

                        Console.WriteLine("\"cancel\" to cancel login");

                        while (true)
                        {
                            Console.Write("SSO login > ");
                            readTask = inputManager.ReadLine();
                            try
                            {
                                answer = await readTask;
                            }
                            catch (TaskCanceledException)
                            {
                                break;
                            }
                            if (string.Compare(answer, "cancel", StringComparison.InvariantCultureIgnoreCase) == 0)
                            {
                                auth.Cancel();
                                return;
                            }
                            if (answer == "a")
                            {
                                answer = "password";
                            }
                            if (string.Compare(answer, "password", StringComparison.InvariantCultureIgnoreCase) == 0)
                            {
                                await sts.LoginWithPassword();
                                break;
                            }
#if NET472_OR_GREATER
                            if (answer == "o")
                            {
                                answer = "open";
                            }
                            if (answer == "p")
                            {
                                answer = "paste";
                            }
                            if (answer == "c")
                            {
                                answer = "copy";
                            }

                            if (string.Compare(answer, "open", StringComparison.InvariantCultureIgnoreCase) == 0)
                            {
                                try
                                {
                                    Process.Start(sts.SsoLoginUrl);
                                }
                                catch (Exception e)
                                {
                                    Console.WriteLine(e.Message);
                                }
                                continue;
                            }
                            if (string.Compare(answer, "copy", StringComparison.InvariantCultureIgnoreCase) == 0)
                            {
                                var thread = new Thread(() => { System.Windows.Clipboard.SetText(sts.SsoLoginUrl); });
                                thread.SetApartmentState(ApartmentState.STA);
                                thread.Start();
                                thread.Join();
                                continue;
                            }
                            if (string.Compare(answer, "paste", StringComparison.InvariantCultureIgnoreCase) == 0)
                            {
                                var thread = new Thread(() => { answer = System.Windows.Clipboard.GetText(); });
                                thread.SetApartmentState(ApartmentState.STA);
                                thread.Start();
                                thread.Join();
                            }
#endif
                            try
                            {
                                await sts.SetSsoToken(answer);
                                break;
                            }
                            catch (Exception e)
                            {
                                Console.WriteLine(e.Message);
                            }
                        }
                        break;

                    case SsoDataKeyStep sdks:
                        var actions = sdks.Channels
                            .Select(x => x.SsoDataKeyShareChannelText())
                            .Where(x => !string.IsNullOrEmpty(x))
                            .ToArray();

                        Console.WriteLine("\nRequest Data Key\n");
                        Console.WriteLine($"{string.Join("\n", actions.Select(x => $"\"{x}\""))}");
                        Console.WriteLine("\"resume\" to resume\n\"cancel\" to cancel login.");
                        while (true)
                        {
                            Console.Write("SSO Data Key > ");
                            readTask = inputManager.ReadLine();
                            try
                            {
                                answer = await readTask;
                            }
                            catch (TaskCanceledException)
                            {
                                break;
                            }
                            if (string.Compare(answer, "cancel", StringComparison.InvariantCultureIgnoreCase) == 0)
                            {
                                auth.Cancel();
                                return;
                            }
                            if (string.Compare(answer, "resume", StringComparison.InvariantCultureIgnoreCase) == 0)
                            {
                                await sdks.Resume();
                                break;
                            }
                            if (actions.Any(x => x == answer))
                            {
                                if (AuthUIExtensions.TryParseDataKeyShareChannel(answer, out var channel))
                                {
                                    try
                                    {
                                        await sdks.RequestDataKey(channel);
                                    }
                                    catch (Exception e)
                                    {
                                        Console.WriteLine(e.Message);
                                    }
                                }
                                else
                                {
                                    Console.WriteLine($"Unsupported approval channel: {answer}");
                                }
                            }
                            else
                            {
                                Console.WriteLine($"Unsupported command: {answer}");
                            }
                        }
                        break;
                }
            }
            auth.UiCallback = null;
        }
    }

    public class AuthSyncCallback : IAuthSyncCallback
    {
        private readonly Action _onNextStep;
        public AuthSyncCallback(Action onNextStep) {
            _onNextStep = onNextStep;
        }
        public void OnNextStep()
        {
            _onNextStep?.Invoke();
        }
    }

#if NET472_OR_GREATER
    internal class WindowsAuthSyncCallback : AuthSyncCallback, IAuthSecurityKeyUI
    {
        public WindowsAuthSyncCallback(Action onNextStep) : base(onNextStep)
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
