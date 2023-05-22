using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Authentication;
using Cli;
using CommandLine;
using Google.Protobuf;
using KeeperSecurity.Authentication;
using KeeperSecurity.Authentication.Sync;
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
            var storage = Program.CommanderStorage.GetConfigurationStorage(null, new CommanderConfigurationProtection());
            _auth = new AuthSync(storage)
            {
                Endpoint = {DeviceName = "Commander C#", ClientVersion = "c16.5.0"}
            };

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

            Commands.Add("server", new Cli.SimpleCommand
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

            Commands.Add("version", new Cli.SimpleCommand
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
                password = await Program.GetInputManager().ReadLine(new ReadLineParameters {IsSecured = true});
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

            try
            {
                if (isSsoProvider)
                {
                    await Utils.LoginToSsoProvider(_auth, Program.GetInputManager(), username);
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

                    await Utils.LoginToKeeper(_auth, Program.GetInputManager(), username, passwords.ToArray());
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