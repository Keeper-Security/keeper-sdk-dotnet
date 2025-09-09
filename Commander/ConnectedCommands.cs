using System;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using AccountSummary;
using Authentication;
using BreachWatch;
using Cli;
using CommandLine;
using Enterprise;
using Google.Protobuf;
using KeeperSecurity.Authentication;
using KeeperSecurity.Utils;
using KeeperSecurity.Vault;

namespace Commander
{
    public partial class ConnectedContext : StateCommands
    {
        private readonly VaultContext _vaultContext;
        private readonly AuthCommon _auth;

        private AccountSummaryElements _accountSummary;

        public ConnectedContext(AuthCommon auth)
        {
            _auth = auth;
            var storage = Program.CommanderStorage.GetKeeperStorage(auth.AuthContext.AccountUid.Base64UrlEncode());
            var vault = new VaultOnline(_auth, storage)
            {
                VaultUi = new VaultUi(),
                AutoSync = true
            };
            _vaultContext = new VaultContext(vault);

            SubscribeToNotifications();
            CheckIfEnterpriseAdmin();
            lock (Commands)
            {
                _vaultContext.AppendVaultCommands(this);
                Commands.Add("devices",
                    new ParseableCommand<OtherDevicesOptions>
                    {
                        Order = 50,
                        Description = "Devices (other than current) commands",
                        Action = DeviceCommand,
                    });

                Commands.Add("this-device",
                    new ParseableCommand<ThisDeviceOptions>
                    {
                        Order = 51,
                        Description = "Current device command",
                        Action = ThisDeviceCommand,
                    });

                if (_auth.AuthContext.Settings?.ShareDatakeyWithEnterprise == true)
                {
                    Commands.Add("share-datakey",
                        new SimpleCommand
                        {
                            Order = 52,
                            Description = "Share data key with enterprise",
                            Action = ShareDatakeyCommand,
                        });
                }

                Commands.Add("logout",
                    new ParseableCommand<LogoutOptions>
                    {
                        Order = 200,
                        Description = "Logout",
                        Action = LogoutCommand,
                    });

                Commands.Add("whoami",
                    new SimpleCommand
                    {
                        Order = 201,
                        Description = "Display information about the currently logged in user",
                        Action = WhoamiCommand,
                    });
            }

            Program.GetMainLoop().CommandQueue.Enqueue("sync-down");
        }

        private bool DeviceApprovalRequestCallback(NotificationEvent evt)
        {
            if (string.Compare(evt.Event, "device_approval_request", StringComparison.InvariantCultureIgnoreCase) !=
                0) return false;
            _accountSummary = null;
            var deviceToken = evt.EncryptedDeviceToken.Base64UrlDecode();
            Console.WriteLine(!string.IsNullOrEmpty(evt.EncryptedDeviceToken)
                ? $"New notification arrived for Device ID: {deviceToken.TokenToString()}"
                : "New notification arrived.");

            return false;
        }

        private void SubscribeToNotifications()
        {
            _auth.PushNotifications?.RegisterCallback(DeviceApprovalRequestCallback);
        }

        private void UnsubscribeFromNotifications()
        {
            _auth.PushNotifications?.RemoveCallback(DeviceApprovalRequestCallback);
            _auth.PushNotifications?.RemoveCallback(EnterpriseNotificationCallback);
        }

        private async Task LogoutCommand(LogoutOptions options)
        {
            UnsubscribeFromNotifications();
            if (!options.Resume)
            {
                await _auth.Logout();
            }

            NextStateCommands = new NotConnectedCliContext(false);
        }

        private async Task ThisDeviceCommand(ThisDeviceOptions arguments)
        {
            if (_accountSummary == null)
            {
                _accountSummary = await _auth.LoadAccountSummary();
            }

            var device = _accountSummary?.Devices
                .FirstOrDefault(x => x.EncryptedDeviceToken.ToByteArray().SequenceEqual(_auth.DeviceToken));
            if (device == null)
            {
                Console.WriteLine("???????????????");
                return;
            }

            var availableVerbs = new[]
                {"rename", "register", "persistent_login", "ip_disable_auto_approve", "timeout", "bio"};

            var deviceToken = device.EncryptedDeviceToken.ToByteArray();
            var bioTarget = _auth.Username.BiometricCredentialTarget(deviceToken);
            var hasBio = CredentialManager.GetCredentials(bioTarget, out _, out _);
            var persistentLoginDisabled = false;
            if (_auth.AuthContext.Enforcements.ContainsKey("restrict_persistent_login"))
            {
                var pl = _auth.AuthContext.Enforcements["restrict_persistent_login"];
                if (pl is bool b)
                {
                    persistentLoginDisabled = b;
                }
                else if (pl is IConvertible conv)
                {
                    persistentLoginDisabled = conv.ToBoolean(CultureInfo.InvariantCulture);
                }
                else
                {
                    persistentLoginDisabled = true;
                }
            }

            switch (arguments.Command)
            {
                case null:
                {
                    Console.WriteLine();
                    Console.WriteLine("{0, 20}: {1}", "Device Name", device.DeviceName);
                    Console.WriteLine("{0, 20}: {1}", "Client Version", device.ClientVersion);
                    Console.WriteLine("{0, 20}: {1}", "Data Key Present", device.EncryptedDataKeyPresent);
                    Console.WriteLine("{0, 20}: {1}", "IP Auto Approve",
                        !_accountSummary.Settings.IpDisableAutoApprove);
                    Console.WriteLine("{0, 20}: {1}", "Persistent Login",
                        !persistentLoginDisabled && _accountSummary.Settings.PersistentLogin);
                    if (_accountSummary.Settings.LogoutTimer > 0)
                    {
                        if (_accountSummary.Settings.LogoutTimer >= TimeSpan.FromDays(1).TotalMilliseconds)
                        {
                            Console.WriteLine("{0, 20}: {1} day(s)", "Logout Timeout",
                                TimeSpan.FromMilliseconds(_accountSummary.Settings.LogoutTimer).TotalDays);
                        }
                        else if (_accountSummary.Settings.LogoutTimer >= TimeSpan.FromHours(1).TotalMilliseconds)
                        {
                            Console.WriteLine("{0, 20}: {1} hour(s)", "Logout Timeout",
                                TimeSpan.FromMilliseconds(_accountSummary.Settings.LogoutTimer).TotalHours);
                        }
                        else if (_accountSummary.Settings.LogoutTimer >= TimeSpan.FromSeconds(1).TotalMilliseconds)
                        {
                            Console.WriteLine("{0, 20}: {1} minute(s)", "Logout Timeout",
                                TimeSpan.FromMilliseconds(_accountSummary.Settings.LogoutTimer).TotalMinutes);
                        }
                        else
                        {
                            Console.WriteLine("{0, 20}: {1} second(s)", "Logout Timeout",
                                TimeSpan.FromMilliseconds(_accountSummary.Settings.LogoutTimer).TotalSeconds);
                        }
                    }

                    Console.WriteLine("{0, 20}: {1}", "Biometric Login", hasBio);

                    Console.WriteLine();
                    Console.WriteLine($"Available sub-commands: {string.Join(", ", availableVerbs)}");
                }
                break;

                case "rename":
                    if (string.IsNullOrEmpty(arguments.Parameter))
                    {
                        Console.WriteLine($"{arguments.Command} command requires new device name parameter.");
                    }
                    else
                    {
                        var request = new DeviceUpdateRequest
                        {
                            ClientVersion = _auth.Endpoint.ClientVersion,
                            DeviceStatus = DeviceStatus.DeviceOk,
                            DeviceName = arguments.Parameter,
                            EncryptedDeviceToken = device.EncryptedDeviceToken,
                        };
                        await _auth.ExecuteAuthRest("authentication/update_device", request);
                    }

                    break;

                case "register":
                {
                    if (!device.EncryptedDataKeyPresent)
                    {
                        await _auth.RegisterDataKeyForDevice(device);
                    }
                    else
                    {
                        Console.WriteLine("Device already registered.");
                    }

                }
                break;

                case "ip_disable_auto_approve":
                case "persistent_login":
                {
                    bool? enabled;
                    if (string.Compare(arguments.Parameter, "on", StringComparison.InvariantCultureIgnoreCase) == 0)
                    {
                        enabled = true;
                    }
                    else if (string.Compare(arguments.Parameter, "off", StringComparison.InvariantCultureIgnoreCase) ==
                             0)
                    {
                        enabled = false;
                    }
                    else
                    {
                        Console.WriteLine($"\"{arguments.Command}\" accepts the following parameters: on, off");
                        return;
                    }

                    if (arguments.Command == "persistent_login" && persistentLoginDisabled)
                    {
                        Console.WriteLine("\"Stay Logged In\" feature is restricted by Keeper Administrator");
                        return;
                    }

                    await _auth.SetSessionParameter(arguments.Command, enabled.Value ? "1" : "0");
                }
                break;

                case "timeout":
                {
                    if (string.IsNullOrEmpty(arguments.Parameter))
                    {
                        Console.WriteLine($"\"{arguments.Command}\" requires timeout in minutes parameter.");
                    }
                    else
                    {
                        if (int.TryParse(arguments.Parameter, out var timeout))
                        {
                            await _auth.SetSessionInactivityTimeout(timeout);
                            _accountSummary = null;
                        }
                        else
                        {
                            Console.WriteLine(
                                $"{arguments.Command}: invalid timeout in minutes parameter: {arguments.Parameter}");
                        }
                    }
                }
                break;

                case "bio":
                {
                    bool enabled;
                    if (string.Compare(arguments.Parameter, "on", StringComparison.InvariantCultureIgnoreCase) == 0)
                    {
                        enabled = true;
                    }
                    else if (string.Compare(arguments.Parameter, "off", StringComparison.InvariantCultureIgnoreCase) ==
                             0)
                    {
                        enabled = false;
                    }
                    else
                    {
                        Console.WriteLine($"\"{arguments.Command}\" accepts the following parameters: on, off");
                        return;
                    }

                    var deviceTokenName = deviceToken.TokenToString();
                    if (enabled)
                    {
                        var bioKey = CryptoUtils.GenerateEncryptionKey();
                        var authHash = CryptoUtils.CreateBioAuthHash(bioKey);
                        var encryptedDataKey = CryptoUtils.EncryptAesV2(_auth.AuthContext.DataKey, bioKey);
                        var request = new UserAuthRequest
                        {
                            LoginType = LoginType.Bio,
                            Name = deviceTokenName,
                            AuthHash = ByteString.CopyFrom(authHash),
                            EncryptedDataKey = ByteString.CopyFrom(encryptedDataKey)
                        };

                        await _auth.ExecuteAuthRest("authentication/set_v2_alternate_password", request);
                        CredentialManager.PutCredentials(bioTarget, _auth.Username, bioKey.Base64UrlEncode());
                    }
                    else
                    {
                        if (hasBio)
                        {
                            CredentialManager.DeleteCredentials(bioTarget);
                        }
                    }
                }
                break;

                default:
                {
                    Console.WriteLine($"Available sub-commands: {string.Join(", ", availableVerbs)}");
                }
                break;
            }
        }

        private async Task ShareDatakeyCommand(string _)
        {
            /*
            if (_auth.AuthContext.Settings?.ShareDatakeyWithEnterprise != true) 
            {
                Console.WriteLine("Data key sharing is not requested.");
                return;
            }
            */
            Console.Write(
                "Enterprise administrator requested data key to be shared. Proceed with sharing? (Yes/No) : ");
            var answer = await Program.GetInputManager().ReadLine();
            if (string.Compare("y", answer, StringComparison.InvariantCultureIgnoreCase) == 0)
            {
                answer = "yes";
            }

            if (string.Compare(answer, "yes", StringComparison.InvariantCultureIgnoreCase) != 0) return;

            var rs = (EnterprisePublicKeyResponse) await _auth.ExecuteAuthRest("enterprise/get_enterprise_public_key",
                null, typeof(EnterprisePublicKeyResponse));
            if (rs.EnterpriseECCPublicKey?.Length == 65)
            {
                var publicKey = CryptoUtils.LoadEcPublicKey(rs.EnterpriseECCPublicKey.ToByteArray());
                var encryptedDataKey = CryptoUtils.EncryptEc(_auth.AuthContext.DataKey, publicKey);
                var rq = new EnterpriseUserDataKey
                {
                    UserEncryptedDataKey = ByteString.CopyFrom(encryptedDataKey)
                };
                await _auth.ExecuteAuthRest("enterprise/set_enterprise_user_data_key", rq);
                Commands.Remove("share-datakey");
            }
            else
            {
                Console.Write("Your enterprise does not have EC key pair created.");
            }
        }

        private async Task DeviceCommand(OtherDevicesOptions arguments)
        {
            if (arguments.Force)
            {
                _accountSummary = null;
            }

            if (_accountSummary == null)
            {
                _accountSummary = await _auth.LoadAccountSummary();
            }

            if (_accountSummary == null)
            {
                Console.WriteLine("No devices available");
                return;
            }

            var devices = _accountSummary.Devices
                .Where(x => !x.EncryptedDeviceToken.SequenceEqual(_auth.DeviceToken))
                .OrderBy(x => (int) x.DeviceStatus)
                .ToArray();

            if (devices.Length == 0)
            {
                Console.WriteLine("No devices available");
                return;
            }

            if (string.IsNullOrEmpty(arguments.Command) || arguments.Command == "list")
            {
                var tab = new Tabulate(5)
                {
                    DumpRowNo = true
                };
                tab.AddHeader(new[] { "Device Name", "Client", "ID", "Status", "Data Key" });
                foreach (var device in devices)
                {
                    var deviceToken = device.EncryptedDeviceToken.ToByteArray();
                    tab.AddRow(
                        device.DeviceName,
                        device.ClientVersion,
                        deviceToken.TokenToString(),
                        device.DeviceStatus.DeviceStatusToString(),
                        device.EncryptedDataKeyPresent ? "Yes" : "No"
                    );
                }

                Console.WriteLine();
                tab.Dump();
                return;
            }

            if (arguments.Command == "approve" || arguments.Command == "decline")
            {
                if (string.IsNullOrEmpty(arguments.DeviceId))
                {
                    Console.WriteLine("No device Id");
                    return;
                }

                var isDecline = arguments.Command == "decline";
                var toApprove = devices
                    .Where(x => ((x.DeviceStatus == DeviceStatus.DeviceNeedsApproval) ||
                                 (arguments.Link && x.DeviceStatus == DeviceStatus.DeviceOk)))
                    .Where(x =>
                    {
                        if (arguments.DeviceId == "all")
                        {
                            return true;
                        }

                        var deviceToken = x.EncryptedDeviceToken.ToByteArray();
                        var token = deviceToken.TokenToString();
                        return token.StartsWith(arguments.DeviceId);
                    })
                    .ToArray();

                if (toApprove.Length == 0)
                {
                    Console.WriteLine($"No device approval for criteria \"{arguments.DeviceId}\"");
                    return;
                }

                foreach (var device in toApprove)
                {
                    var deviceApprove = new ApproveDeviceRequest
                    {
                        EncryptedDeviceToken = device.EncryptedDeviceToken,
                        DenyApproval = isDecline,

                    };
                    if ((_accountSummary.Settings.SsoUser || arguments.Link) && !isDecline)
                    {
                        var publicKeyBytes = device.DevicePublicKey.ToByteArray();
                        var publicKey = CryptoUtils.LoadEcPublicKey(publicKeyBytes);
                        var encryptedDataKey = CryptoUtils.EncryptEc(_auth.AuthContext.DataKey, publicKey);
                        deviceApprove.EncryptedDeviceDataKey = ByteString.CopyFrom(encryptedDataKey);
                        deviceApprove.LinkDevice = arguments.Link;
                    }

                    await _auth.ExecuteAuthRest("authentication/approve_device", deviceApprove);
                }

                _accountSummary = null;
                return;
            }

            Console.WriteLine($"Unsupported device command {arguments.Command}");
        }

        public override async Task<bool> ProcessException(Exception e)
        {
            if (!(e is KeeperAuthFailed)) return await base.ProcessException(e);

            Console.WriteLine("Session is expired. Disconnecting...");
            await LogoutCommand(new LogoutOptions { Resume = true });
            return true;
        }

        public override string GetPrompt()
        {
            if (!_auth.IsAuthenticated())
            {
                _ = LogoutCommand(new LogoutOptions { Resume = true });
                return "";
            }

            if (!string.IsNullOrEmpty(_vaultContext.CurrentFolder))
            {
                var folder = _vaultContext.CurrentFolder;
                var sb = new StringBuilder();
                while (_vaultContext.Vault.TryGetFolder(folder, out var node))
                {
                    if (sb.Length > 0)
                    {
                        sb.Insert(0, '/');
                    }

                    sb.Insert(0, node.Name);
                    folder = node.ParentUid;
                    if (!string.IsNullOrEmpty(folder)) continue;

                    sb.Insert(0, _vaultContext.Vault.RootFolder.Name + "/");
                    if (sb.Length <= 40) return sb.ToString();

                    sb.Remove(0, sb.Length - 37);
                    sb.Insert(0, "...");
                    return sb.ToString();
                }
            }

            return _vaultContext.Vault.RootFolder.Name;
        }

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            _vaultContext.Vault.Dispose();
            _auth.Dispose();
        }

        private Task WhoamiCommand(string _)
        {
            var tab = new Tabulate(2);
            tab.SetColumnRightAlign(0, true);
            var enterpriseTier = EnterpriseData.EnterpriseLicense.Tier;

            tab.AddRow("User:", _auth.Username);
            tab.AddRow("Server:", _auth.Endpoint.Server);
            tab.AddRow("Admin:", _auth.AuthContext.IsEnterpriseAdmin ? "Yes" : "No");
            tab.AddRow("Account Type:", _auth.AuthContext.License.AccountType);
            tab.AddRow("Renewal Date:", _auth.AuthContext.License.ExpirationDate);
            tab.AddRow("Storage Capacity:", _auth.AuthContext.License.BytesTotal/(1024*1024*1024) + "GB");
            tab.AddRow("Storage Usage:", _auth.AuthContext.License.BytesUsed/(1024*1024*1024) + "GB");
            tab.AddRow("Storage Expires:", _auth.AuthContext.License.StorageExpirationDate);
            tab.AddRow("License Type:", _auth.AuthContext.License.ProductTypeName);
            tab.AddRow("License Expires:", _auth.AuthContext.License.ExpirationDate);
            tab.AddRow("Base Plan:", enterpriseTier == 1 ? "Enterprise" : "Business");
            
            tab.Dump();
            return Task.FromResult(true);
        }
    }

    class LogoutOptions
    {
        [Option("resume", Required = false, HelpText = "resume last login")]
        public bool Resume { get; set; }
    }

    class OtherDevicesOptions
    {
        [Option('f', "force", Required = false, Default = false, HelpText = "reload device list")]
        public bool Force { get; set; }

        [Value(0, Required = false, HelpText = "device command: \"approve\", \"decline\", \"list\"")]
        public string Command { get; set; }

        [Value(1, Required = false, HelpText = "device id or \"all\" or \"clear\"")]
        public string DeviceId { get; set; }

        [Option('l', "link", Required = false, Default = false, HelpText = "link device")]
        public bool Link { get; set; }
    }

    class ThisDeviceOptions
    {
        [Value(0, Required = false, HelpText = "this-device command: \"register\", \"rename\", \"timeout\", \"bio\"")]
        public string Command { get; set; }

        [Value(1, Required = false, HelpText = "sub-command parameter")]
        public string Parameter { get; set; }
    }

}