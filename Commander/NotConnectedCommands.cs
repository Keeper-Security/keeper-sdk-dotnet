using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Authentication;
using Cli;
using CommandLine;
using Google.Protobuf;
using KeeperSecurity.Authentication;
using KeeperSecurity.Authentication.Sync;
using KeeperSecurity.Configuration;
using KeeperSecurity.Utils;

namespace Commander
{
    public class NotConnectedCliContext : StateCommands
    {
        private readonly AuthSync _auth;

        private class CreateOptions
        {
            [Value(0, Required = true, MetaName = "email", HelpText = "account email")]
            public string Username { get; set; }
        }

        private class ProxyOptions
        {
            [Option("user", Required = false, HelpText = "proxy user")]
            public string User { get; set; }

            [Option("password", Required = false, HelpText = "proxy password")]
            public string Password { get; set; }
        }
        private class ServerOptions
        {
            [Option("key-id", Required = false, HelpText = "self hosted server key ID")]
            public int? KeyId { get; set; }

            [Option("public-key", Required = false, HelpText = "self hosted server EC public key. Base64 URL encoded")]
            public string PublicKey { get; set; }

            [Option("ignore-certificate-errors", Required = false,
                HelpText = "true | false. Accept any TLS certificate presented by this server. The server is not authenticated")]
            public bool? IgnoreCertificateErrors { get; set; }

            [Value(0, Required = false, MetaName = "server", HelpText = "Keeper region or self hosted host name")]
            public string Server { get; set; }
        }

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

            [Option("keep-alive", Required = false, HelpText = "enable automatic session keep-alive")]
            public bool KeepAlive { get; set; }

            [Option("push-notifications", Required = false, HelpText = "enable push notifications")]
            public bool PushNotifications { get; set; }

            [Value(0, Required = true, MetaName = "email", HelpText = "account email")]
            public string Username { get; set; }
        }

        public NotConnectedCliContext(bool autologin)
        {
            var loader = Program.CommanderStorage.GetConfigurationLoader();
            var storage = new JsonConfigurationStorage(loader);

            _auth = new AuthSync(storage)
            {
                Endpoint = { DeviceName = "Commander C#", ClientVersion = "c18.0.0" }
            };

#if NET472_OR_GREATER
            _auth.BiometricLoginProvider = new KeeperBiometrics.BiometricLoginProviderAdapter();
#endif
            Commands.Add("proxy", new ParseableCommand<ProxyOptions>
            {
                Order = 9,
                Description = "Detect and setup proxy",
                Action = DoProxy
            });

            Commands.Add("login", new ParseableCommand<LoginOptions>
            {
                Order = 10,
                Description = "Login to Keeper",
                Action = DoLogin
            });

            Commands.Add("create", new ParseableCommand<CreateOptions>
            {
                Order = 11,
                Description = "Create Keeper account",
                Action = DoCreateAccount
            });

            Commands.Add("server", new ValidatingParseableCommand<ServerOptions>
            {
                Order = 20,
                Description = "Display or change Keeper Server",
                // "--ignore-certificate-errors" without a value parses as "no change". Ask for the value.
                Validate = tokens =>
                {
                    for (var i = 0; i < tokens.Count; i++)
                    {
                        if (!string.Equals(tokens[i], "--ignore-certificate-errors",
                                StringComparison.OrdinalIgnoreCase)) continue;
                        if (i == tokens.Count - 1 || tokens[i + 1].StartsWith("-"))
                        {
                            return "\"--ignore-certificate-errors\" option requires a value: true or false.";
                        }
                    }

                    return null;
                },
                Action = options =>
                {
                    var server = options.Server?.Trim() ?? "";
                    if (string.IsNullOrEmpty(server))
                    {
                        server = _auth.Endpoint.Server;
                    }
                    else
                    {
                        var resolved = KeeperRegions.ResolveServer(server);
                        if (resolved == null && !server.Contains("."))
                        {
                            Console.WriteLine($"Invalid region: {server}");
                            Console.WriteLine($"Valid regions: {string.Join(", ", KeeperRegions.Servers.Keys.OrderBy(k => k, StringComparer.OrdinalIgnoreCase))}");
                            Console.WriteLine("Self hosted instances are set by their host name.");
                            return Task.CompletedTask;
                        }

                        // Not a known region: a self hosted Keeper instance.
                        server = (resolved ?? server).ToLowerInvariant();
                    }

                    try
                    {
                        if (options.IgnoreCertificateErrors.HasValue)
                        {
                            _auth.Storage.SetIgnoreCertificateErrors(server, options.IgnoreCertificateErrors.Value);
                        }

                        if (!string.IsNullOrEmpty(options.PublicKey))
                        {
                            if (!options.KeyId.HasValue)
                            {
                                Console.WriteLine("\"--key-id\" option is required with \"--public-key\".");
                                return Task.CompletedTask;
                            }

                            _auth.Storage.SetServerPublicKey(server, options.KeyId.Value, options.PublicKey);
                        }
                        else if (options.KeyId.HasValue)
                        {
                            _auth.Storage.SetServerKeyId(server, options.KeyId.Value);
                        }
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine(e.Message);
                        return Task.CompletedTask;
                    }

                    // Reloads the server key and TLS configuration.
                    _auth.Endpoint.Server = server;

                    var sc = _auth.Storage.Get().Servers.Get(_auth.Endpoint.Server);
                    Console.WriteLine($"Keeper Server: {_auth.Endpoint.Server}");
                    Console.WriteLine($"Server Key ID: {_auth.Endpoint.ServerKeyId}");
                    Console.WriteLine(
                        $"TLS Verification: {(sc?.IgnoreCertificateErrors == true ? "OFF. The server is not authenticated" : "ON")}");
                    return Task.CompletedTask;
                }
            });

            Commands.Add("version", new SimpleCommand
            {
                Order = 21,
                Action = args =>
                {
                    if (!string.IsNullOrEmpty(args))
                    {
                        _auth.Endpoint.ClientVersion = args;
                    }

                    Console.WriteLine($"Keeper Client Version: {_auth.Endpoint.ClientVersion}");
                    return Task.FromResult(true);
                }
            });

            if (autologin)
            {
                var configuration = storage.Get();
                if (string.IsNullOrEmpty(configuration.LastServer))
                {
                    Console.WriteLine($"You are connected to the default Keeper server \"{_auth.Endpoint.Server}\".");
                    Console.WriteLine($"Please use \"server <keeper host name for your region>\" command to choose a different region.");
                }
                else
                {
                    Console.WriteLine($"Connected to \"{_auth.Endpoint.Server}\".");
                }
                Console.WriteLine();

                var lastLogin = configuration.LastLogin;
                if (!string.IsNullOrEmpty(lastLogin))
                {
                    Program.GetMainLoop().CommandQueue.Enqueue($"login --resume {lastLogin}");
                }
            }
        }

        private async Task DoCreateAccount(CreateOptions options)
        {
            var username = options.Username.ToLowerInvariant();
            Console.WriteLine($"Create {username} account in {_auth.Endpoint.Server} region.");

            var rulesRs = await _auth.Endpoint.GetNewUserParams(username);
            var matcher = PasswordRuleMatcher.FromNewUserParams(rulesRs);
            string password;
            while (true)
            {
                Console.Write("\nEnter Master Password: ");
                password = await Program.GetInputManager().ReadLine(new ReadLineParameters { IsSecured = true });
                var failedRules = matcher.MatchFailedRules(password);
                if (failedRules == null) break;
                if (failedRules.Length == 0) break;
                Console.WriteLine(string.Join("\n", failedRules));
            }

            try
            {
                var context = new LoginContext();
                await _auth.EnsureDeviceTokenIsRegistered(context, username);

                await _auth.RequestCreateUser(context, password);

                Task<string> verificationCodeTask = null;
                _auth.PushNotifications.RegisterCallback(evt =>
                {
                    if (evt.Command == "user_created" && evt.Username == username)
                    {
                        if (verificationCodeTask != null)
                        {
                            Program.GetInputManager().InterruptReadTask(verificationCodeTask);
                        }

                        return true;
                    }

                    return false;
                });
                while (true)
                {
                    Console.Write("\nEnter Verification Code: ");
                    try
                    {
                        verificationCodeTask = Program.GetInputManager().ReadLine();
                        var code = await verificationCodeTask;
                        verificationCodeTask = null;
                        if (string.IsNullOrEmpty(code)) break;
                        var verRq = new ValidateCreateUserVerificationCodeRequest
                        {
                            ClientVersion = _auth.Endpoint.ClientVersion,
                            Username = username,
                            VerificationCode = code,
                        };

                        var payload = new ApiRequestPayload
                        {
                            Payload = ByteString.CopyFrom(verRq.ToByteArray())
                        };
                        await _auth.Endpoint.ExecuteRest("authentication/validate_create_user_verification_code", payload);

                        break;
                    }
                    catch (TaskCanceledException)
                    {
                        break;
                    }
                    catch (KeeperApiException kae)
                    {
                        if (kae.Code == "link_or_code_expired")
                        {
                            Console.WriteLine(kae.Message);
                        }
                        else
                        {
                            throw;
                        }
                    }
                }
            }
            finally
            {
                _auth.PushNotifications?.Dispose();
                _auth.SetPushNotifications(null);
            }

            await DoLogin(new LoginOptions
            {
                Username = username,
                Password = password
            });
        }

        private async Task DoProxy(ProxyOptions options)
        {
            Uri proxyUri = null;
            string[] proxyMethods = null;
            var hasProxy = await _auth.DetectProxy((uri, methods) =>
            {
                proxyUri = uri;
                proxyMethods = methods;
            });
            if (proxyUri == null || proxyMethods == null)
            {
                return;
            }
            var proxyUser = options.User;
            if (string.IsNullOrEmpty(proxyUser))
            {
                Console.Write("Enter Proxy username: ");
                proxyUser = await Program.GetInputManager().ReadLine();
            }
            if (string.IsNullOrEmpty(proxyUser))
            {
                return;
            }
            var proxyPassword = options.Password;
            if (string.IsNullOrEmpty(proxyPassword))
            {
                Console.Write("Enter Proxy password: ");
                proxyPassword = await Program.GetInputManager().ReadLine(new ReadLineParameters
                {
                    IsSecured = true,
                });
            }
            if (string.IsNullOrEmpty(proxyPassword))
            {
                return;
            }

            _auth.Endpoint.WebProxy = AuthUIExtensions.GetWebProxyForCredentials(proxyUri, proxyMethods, proxyUser, proxyPassword);
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
            }

            if (string.IsNullOrEmpty(username)) return;

            _auth.AutoKeepAlive = options.KeepAlive;
            _auth.UsePushNotifications = options.PushNotifications;

            try
            {
                if (isSsoProvider)
                {
                    await KeeperLoginFlow.LoginToSsoProvider(_auth, Program.GetInputManager(), username);
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

                    var configuration = _auth.Storage.Get();
                    var uc = configuration.Users.Get(username);
                    if (!string.IsNullOrEmpty(uc?.Password))
                    {
                        passwords.Add(uc.Password);
                    }

                    await KeeperLoginFlow.LoginToKeeper(_auth, Program.GetInputManager(), username, passwords.ToArray());
                }

                if (_auth.IsAuthenticated())
                {
                    var connectedCommands = new ConnectedContext(_auth);
                    NextStateCommands = connectedCommands;
                }
            }
            catch (KeeperCanceled)
            {
            }
            catch (KeyboardInterrupt)
            {
            }
        }

        public override string GetPrompt()
        {
            return "Not logged in";
        }
    }
}