using System;
using System.Collections.Generic;
using System.Diagnostics;
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
using KeeperSecurity.BreachWatch;
using KeeperSecurity.Utils;
using KeeperSecurity.Vault;

namespace Commander
{
    public partial class ConnectedContext : StateCommands
    {
        internal readonly VaultContext _vaultContext;
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
            _vaultContext.EnterpriseContext = this;
            _vaultContext.EnterpriseData = EnterpriseData;
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

                Commands.Add("device-list",
                    new ParseableCommand<DeviceListOptions>
                    {
                        Order = 53,
                        Description = "List devices registered to the current user",
                        Action = DeviceListCommand,
                    });

                Commands.Add("device-action",
                    new ParseableCommand<DeviceActionOptions>
                    {
                        Order = 54,
                        Description = "Perform an action on one or more devices (logout, remove, lock, unlock, account-lock, account-unlock, link, unlink)",
                        Action = DeviceActionCommand,
                    });

                Commands.Add("device-rename",
                    new ParseableCommand<DeviceRenameOptions>
                    {
                        Order = 55,
                        Description = "Rename a device",
                        Action = DeviceRenameCommand,
                    });

                Commands.Add("biometric",
                    new ParseableCommand<BiometricOptions>
                    {
                        Order = 52,
                        Description = "Manage Windows Hello biometric authentication",
                        Action = BiometricCommand,
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
                    Console.WriteLine("{0, 20}: {1}", "Data Key Present", device.EncryptedDataKeyPresent);
                    Console.WriteLine("{0, 20}: {1}", "IP Auto Approve",
                        !_accountSummary.Settings.IpDisableAutoApprove);
                    Console.WriteLine("{0, 20}: {1}", "Persistent Login",
                        !persistentLoginDisabled && _accountSummary.Settings.PersistentLogin);

                    var deviceTimeout = TimeSpan.FromMilliseconds(_accountSummary.Settings.LogoutTimer);
                    if (deviceTimeout > TimeSpan.Zero)
                    {
                        Console.WriteLine("{0, 20}: {1}", "Device Timeout", deviceTimeout.ToNaturalString());
                    }
                    if (_auth.AuthContext.Enforcements.TryGetValue("logout_timer_desktop", out var lt))
                    {
                        if (lt is IConvertible convertible)
                        {
                            try
                            {
                                var minutes = convertible.ToInt32(null);
                                if (minutes > 0)
                                {
                                    var enterpriseTimeout = TimeSpan.FromMinutes(minutes);
                                    Console.WriteLine("{0, 20}: {1}", "Company Timeout", enterpriseTimeout.ToNaturalString());
                                }
                            }
                            catch
                            {
                                // ignored
                            }
                        }
                    }
                    Console.WriteLine("{0, 20}: {1}", "Effective Timeout", _auth.LogoutTimeout.ToNaturalString());
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

        private async Task<DeviceManagement.Device[]> GetSortedUserDevices()
        {
            var devices = await _auth.GetUserDevices();
            return devices.OrderByDescending(x => x.LastModifiedTime).ToArray();
        }

        // Device identifiers are 1-based, matching the row numbers displayed by "device-list"
        // (and Python Commander's DeviceResolver), which sorts devices the same way.
        private static DeviceManagement.Device[] ResolveUserDevices(DeviceManagement.Device[] devices, string identifier)
        {
            if (string.IsNullOrEmpty(identifier) || identifier == "all")
            {
                return devices;
            }

            if (int.TryParse(identifier, out var index) && index >= 1 && index <= devices.Length)
            {
                return new[] { devices[index - 1] };
            }

            var matches = devices
                .Where(x => x.EncryptedDeviceToken.ToByteArray().TokenToString().StartsWith(identifier) ||
                            (!string.IsNullOrEmpty(x.DeviceName) && x.DeviceName.IndexOf(identifier, StringComparison.OrdinalIgnoreCase) >= 0))
                .ToArray();
            return matches;
        }

        private static readonly IDictionary<string, DeviceManagement.DeviceActionType> DeviceActionNames =
            new Dictionary<string, DeviceManagement.DeviceActionType>(StringComparer.OrdinalIgnoreCase)
            {
                ["logout"] = DeviceManagement.DeviceActionType.DaLogout,
                ["remove"] = DeviceManagement.DeviceActionType.DaRemove,
                ["lock"] = DeviceManagement.DeviceActionType.DaLock,
                ["unlock"] = DeviceManagement.DeviceActionType.DaUnlock,
                ["account-lock"] = DeviceManagement.DeviceActionType.DaDeviceAccountLock,
                ["account-unlock"] = DeviceManagement.DeviceActionType.DaDeviceAccountUnlock,
                ["link"] = DeviceManagement.DeviceActionType.DaLink,
                ["unlink"] = DeviceManagement.DeviceActionType.DaUnlink,
            };

        private static string GetDeviceClientCategory(DeviceManagement.Device device)
        {
            switch (device.ClientTypeCategory)
            {
                case DeviceManagement.ClientTypeCategory.CatExtension:
                    return "Browser Extension";
                case DeviceManagement.ClientTypeCategory.CatDesktop:
                    return "Desktop";
                case DeviceManagement.ClientTypeCategory.CatWebVault:
                    return "Web Vault";
                case DeviceManagement.ClientTypeCategory.CatAdmin:
                    return "Admin Console";
                case DeviceManagement.ClientTypeCategory.CatSecretsManager:
                    return "Secrets Manager";
                case DeviceManagement.ClientTypeCategory.CatChatDesktop:
                    return "Chat Desktop";
                case DeviceManagement.ClientTypeCategory.CatChatMobile:
                    return "Chat Mobile";
                case DeviceManagement.ClientTypeCategory.CatMobile:
                    switch (device.ClientFormFactor)
                    {
                        case ClientFormFactor.FfTablet:
                            return "Tablet App";
                        case ClientFormFactor.FfWatch:
                            return "Wear OS App";
                        default:
                            switch (device.ClientType)
                            {
                                case DeviceManagement.ClientType.Ios:
                                    return "iOS App";
                                case DeviceManagement.ClientType.Android:
                                    return "Android App";
                                default:
                                    return "Mobile App";
                            }
                    }
                default:
                    switch (device.ClientType)
                    {
                        case DeviceManagement.ClientType.Commander:
                            return "Commander CLI";
                        case DeviceManagement.ClientType.Server:
                            return "Server";
                        case DeviceManagement.ClientType.None:
                        case DeviceManagement.ClientType.Unknown:
                            return "Unknown";
                        default:
                            return device.ClientType.ToString();
                    }
            }
        }

        private async Task DeviceListCommand(DeviceListOptions arguments)
        {
            var devices = await GetSortedUserDevices();
            if (devices.Length == 0)
            {
                Console.WriteLine("No devices found");
                return;
            }

            var format = (arguments.Format ?? "table").ToLowerInvariant();
            var headerRow = new[] { "Device Name", "Client", "ID", "Status", "Login State", "Last Accessed" };
            var rows = devices.Select(device =>
            {
                var deviceToken = device.EncryptedDeviceToken.ToByteArray();
                var lastAccessed = device.LastModifiedTime > 0
                    ? DateTimeOffset.FromUnixTimeMilliseconds(device.LastModifiedTime).LocalDateTime.ToString("yyyy-MM-dd HH:mm:ss")
                    : "";
                return new object[]
                {
                    device.DeviceName,
                    GetDeviceClientCategory(device),
                    deviceToken.TokenToString(),
                    device.DeviceStatus.DeviceStatusToString(),
                    device.LoginState.ToString(),
                    lastAccessed
                };
            }).ToList();

            var jsonData = format == "json"
                ? rows.Select(row => headerRow.Zip(row, (col, val) => new { col, val }).ToDictionary(x => x.col, x => x.val)).ToList()
                : null;

            if (!string.IsNullOrEmpty(arguments.Output) && format == "table")
            {
                Console.WriteLine("Output file is ignored for table format. Use json.");
            }

            if (!string.IsNullOrEmpty(arguments.Output) && format != "table")
            {
                using var writer = new System.IO.StreamWriter(arguments.Output);
                EnterpriseExtensions.WriteFormattedOutput(writer, format, headerRow, rows, jsonData);
                Console.WriteLine($"Output written to {arguments.Output}");
                return;
            }

            if (format == "table")
            {
                Console.WriteLine();
            }
            EnterpriseExtensions.WriteFormattedOutput(Console.Out, format, headerRow, rows, jsonData);
        }

        private async Task DeviceActionCommand(DeviceActionOptions arguments)
        {
            if (string.IsNullOrEmpty(arguments.Action) || !DeviceActionNames.TryGetValue(arguments.Action, out var actionType))
            {
                Console.WriteLine($"Unsupported device action \"{arguments.Action}\". Valid actions: {string.Join(", ", DeviceActionNames.Keys)}");
                return;
            }

            if (string.IsNullOrEmpty(arguments.Devices))
            {
                Console.WriteLine("At least one device must be specified");
                return;
            }

            var devices = await GetSortedUserDevices();
            var identifiers = arguments.Devices.Split(',').Select(x => x.Trim()).Where(x => x.Length > 0).ToArray();
            var toAct = new List<DeviceManagement.Device>();
            foreach (var identifier in identifiers)
            {
                var matches = ResolveUserDevices(devices, identifier);
                if (matches.Length == 0)
                {
                    Console.WriteLine($"No device found for \"{identifier}\"");
                    continue;
                }

                toAct.AddRange(matches);
            }

            toAct = toAct.GroupBy(x => x.EncryptedDeviceToken).Select(x => x.First()).ToList();

            if (toAct.Count == 0)
            {
                Console.WriteLine("No devices to act on");
                return;
            }

            if ((actionType == DeviceManagement.DeviceActionType.DaLink || actionType == DeviceManagement.DeviceActionType.DaUnlink) && toAct.Count < 2)
            {
                Console.WriteLine($"Action \"{arguments.Action}\" requires at least 2 devices");
                return;
            }

            var results = await _auth.ExecuteDeviceAction(actionType, toAct.Select(x => x.EncryptedDeviceToken));
            foreach (var result in results)
            {
                foreach (var token in result.EncryptedDeviceToken)
                {
                    Console.WriteLine($"Device {token.ToByteArray().TokenToString()}: {result.DeviceActionStatus}");
                }
            }
        }

        private async Task DeviceRenameCommand(DeviceRenameOptions arguments)
        {
            if (string.IsNullOrEmpty(arguments.Device) || string.IsNullOrEmpty(arguments.NewName))
            {
                Console.WriteLine("Usage: device-rename <device> <new_name>");
                return;
            }

            var devices = await GetSortedUserDevices();
            var matches = ResolveUserDevices(devices, arguments.Device);
            if (matches.Length == 0)
            {
                Console.WriteLine($"No device found for \"{arguments.Device}\"");
                return;
            }

            if (matches.Length > 1)
            {
                Console.WriteLine($"Multiple devices match \"{arguments.Device}\". Please be more specific.");
                return;
            }

            var result = await _auth.RenameUserDevice(matches[0].EncryptedDeviceToken, arguments.NewName);
            if (result == null)
            {
                Console.WriteLine("Device rename failed: no response from server");
                return;
            }

            if (result.DeviceActionStatus == DeviceManagement.DeviceActionStatus.Success)
            {
                Console.WriteLine($"Device renamed to \"{result.DeviceNewName}\"");
                await DeviceListCommand(new DeviceListOptions());
            }
            else
            {
                Console.WriteLine($"Device rename failed: {result.DeviceActionStatus}");
            }
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
            if (disposing)
            {
                this.ReleaseEnterprisePlugins();
                if (_vaultContext != null)
                {
                    _vaultContext.EnterpriseContext = null;
                    _vaultContext.EnterpriseData = null;
                }
            }

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
            tab.AddRow("Data Center:", get_data_center(_auth.Endpoint.Server));
            if (get_environment(_auth.Endpoint.Server) != string.Empty) {
                tab.AddRow("Environment:", get_environment(_auth.Endpoint.Server));
            }
            tab.AddRow("Admin:", _auth.AuthContext.IsEnterpriseAdmin ? "Yes" : "No");
            tab.AddRow("Account Type:", _auth.AuthContext.License.AccountType);
            tab.AddRow("Renewal Date:", _auth.AuthContext.License.ExpirationDate);
            tab.AddRow("Storage Capacity:", _auth.AuthContext.License.BytesTotal/(1024*1024*1024) + "GB");
            tab.AddRow("Storage Usage:", _auth.AuthContext.License.BytesUsed/(1024*1024*1024) + "GB");
            tab.AddRow("Storage Expires:", _auth.AuthContext.License.StorageExpirationDate);
            tab.AddRow("License Type:", _auth.AuthContext.License.ProductTypeName);
            tab.AddRow("License Expires:", _auth.AuthContext.License.ExpirationDate);
            tab.AddRow("Base Plan:", enterpriseTier == 1 ? "Enterprise" : "Business");
            tab.AddRow("BreachWatch:", _vaultContext.Vault.Auth.IsBreachWatchEnabled() ? "Yes" : "No");
            tab.Dump();
            return Task.FromResult(true);
        }
    
        private string get_data_center(string hostname) {
            if (hostname.EndsWith(".com")) {
                return "US";
            } else if (hostname.EndsWith("eu")) {
                return "EU";
            } else if (hostname.EndsWith("govcloud.keepersecurity.us")) {
                return "US GOV";
            } else if (hostname.EndsWith(".au")) {
                return "AU";
            } else {
                return hostname;
            }
        }
        
        private string get_environment(string hostname) {
            if (hostname.StartsWith("dev.")) {
                return "DEV";
            } else if (hostname.StartsWith("qa.")) {
                return "QA";
            } else if (hostname.EndsWith("local")) {
                return "LOCAL";
            }
            return string.Empty;
        }

        private async Task BiometricCommand(BiometricOptions options)
        {
#if NET472_OR_GREATER
            if (!KeeperBiometrics.PasskeyManager.IsAvailable())
            {
                Console.WriteLine("Windows Hello is not available on this system.");
                Console.WriteLine("Please ensure Windows Hello is set up in Windows Settings.");
                return;
            }

            switch (options.Action?.ToLower())
            {
                case BiometricActions.Register:
                    Console.WriteLine("Registering Windows Hello biometric credential...");
                    try
                    {
                        var regResult = await KeeperBiometrics.PasskeyManager.RegisterPasskeyAsync(
                            _auth, 
                            options.FriendlyName, 
                            options.Force);
                        
                        if (regResult.Success)
                        {
                            Console.WriteLine($"{regResult.Message}");
                            Debug.WriteLine($"Biometric registration successful for user");
                            if (!string.IsNullOrEmpty(regResult.Provider))
                            {
                                Console.WriteLine($"Provider: {regResult.Provider}");
                            }
                            Console.WriteLine("\nYou can now use Windows Hello to log in to Keeper.");
                        }
                        else
                        {
                            Console.WriteLine($"Registration failed: {regResult.ErrorMessage}");
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Error during registration: {ex.Message}");
                    }
                    break;

                case BiometricActions.List:
                    Console.WriteLine("Listing Windows Hello biometric credentials...\n");
                    try
                    {
                        var credentials = await KeeperBiometrics.PasskeyManager.ListPasskeysAsync(_auth, options.IncludeDisabled);
                        
                        if (credentials.Count == 0)
                        {
                            Console.WriteLine("No biometric credentials found.");
                        }
                        else
                        {
                            var tab = new Tabulate(5)
                            {
                                DumpRowNo = true,
                                LeftPadding = 2
                            };
                            tab.AddHeader("Friendly Name", "Provider", "Created", "Last Used", "Status");
                            
                            foreach (var cred in credentials)
                            {
                                var created = cred.CreatedAt != DateTime.MinValue 
                                    ? cred.CreatedAt.ToLocalTime().ToString("yyyy-MM-dd HH:mm") 
                                    : "Unknown";
                                var lastUsed = cred.LastUsed != DateTime.MinValue 
                                    ? cred.LastUsed.ToLocalTime().ToString("yyyy-MM-dd HH:mm") 
                                    : "Never";
                                var status = cred.IsDisabled ? "Disabled" : "Active";
                                var provider = cred.Provider ?? "Unknown";
                                
                                tab.AddRow(
                                    cred.FriendlyName ?? "Windows Hello",
                                    provider,
                                    created,
                                    lastUsed,
                                    status
                                );
                            }
                            
                            Console.WriteLine();
                            tab.Dump();
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Error listing biometric credentials: {ex.Message}");
                    }
                    break;

                case BiometricActions.Remove:
                    var removeUsername = _auth.Username;

                    if (string.IsNullOrEmpty(removeUsername))
                    {
                        Console.WriteLine("Note: Uses logged-in username by default.");
                        return;
                    }
                    
                    Console.Write($"Are you sure you want to remove Windows Hello biometric credential for '{removeUsername}'? (y/N): ");
                    var confirmation = await Program.GetInputManager().ReadLine();
                    
                    if (confirmation?.ToLower() != "y")
                    {
                        Console.WriteLine("Cancelled.");
                        return;
                    }
                    
                    try
                    {
                        var removed = await KeeperBiometrics.PasskeyManager.RemovePasskeyAsync(_auth, removeUsername);
                        
                        if (removed)
                        {
                            Console.WriteLine($"Biometric credential removed for user: {removeUsername}");
                        }
                        else
                        {
                            Console.WriteLine($"Failed to remove biometric credential or none found for: {removeUsername}");
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Error removing biometric credential: {ex.Message}");
                    }
                    break;

                case BiometricActions.Verify:
                    var verifyUsername = _auth.Username;
                    
                    if (string.IsNullOrEmpty(verifyUsername))
                    {
                        Console.WriteLine("Note: Uses logged-in username by default.");
                        return;
                    }

                    var purpose = options.Purpose?.ToLower() ?? PasskeyPurposes.Vault;
                    if (purpose != PasskeyPurposes.Login && purpose != PasskeyPurposes.Vault)
                    {
                        Console.WriteLine($"Invalid purpose: {options.Purpose}. Must be '{PasskeyPurposes.Login}' or '{PasskeyPurposes.Vault}'.");
                        return;
                    }
                    
                    Console.WriteLine($"Verifying Windows Hello authentication for '{verifyUsername}' (purpose: {purpose})...");
                    try
                    {
                        var authResult = await KeeperBiometrics.PasskeyManager.AuthenticatePasskeyAsync(
                            _auth, 
                            verifyUsername, 
                            purpose);
                        
                        if (authResult.Success && authResult.IsValid)
                        {
                            Console.WriteLine("Windows Hello verification successful.");
                        }
                        else
                        {
                            Console.WriteLine($"Verification failed: {authResult.ErrorMessage ?? "Unknown error"}");
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Error during verification: {ex.Message}");
                    }
                    break;

                default:
                    Console.WriteLine("Windows Hello Biometric Authentication Management");
                    Console.WriteLine("=================================================\n");
                    Console.WriteLine("Available commands:");
                    Console.WriteLine("  biometric register");
                    Console.WriteLine("    Register a new Windows Hello credential");
                    Console.WriteLine();
                    Console.WriteLine("  biometric list");
                    Console.WriteLine("    List all registered biometric credentials");
                    Console.WriteLine();
                    Console.WriteLine("  biometric remove");
                    Console.WriteLine("    Remove a biometric credential (uses logged-in username by default)");
                    Console.WriteLine();
                    Console.WriteLine("  biometric verify [--purpose <login|vault>]");
                    Console.WriteLine("    Test Windows Hello authentication (defaults to 'vault' purpose)");
                    break;
            }
#else
            Console.WriteLine("Windows Hello biometric support is only available on Windows with .NET Framework 4.7.2+");
            await Task.CompletedTask;
#endif
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
        [Value(0, Required = false, HelpText = "this-device command: \"register\", \"rename\", \"timeout\", \"bio\", \"ip_disable_auto_approve\", \"persistent_login\"")]
        public string Command { get; set; }

        [Value(1, Required = false, HelpText = "sub-command parameter")]
        public string Parameter { get; set; }
    }

    class DeviceListOptions
    {
        [Option("format", Required = false, Default = "table", HelpText = "output format: table, json")]
        public string Format { get; set; }

        [Option('o', "output", Required = false, HelpText = "output file name (ignored for table format)")]
        public string Output { get; set; }
    }

    class DeviceActionOptions
    {
        [Value(0, Required = true, HelpText = "device action: \"logout\", \"remove\", \"lock\", \"unlock\", \"account-lock\", \"account-unlock\", \"link\", \"unlink\"")]
        public string Action { get; set; }

        [Value(1, Required = true, HelpText = "comma separated list of device number(s) (as shown in device-list), name(s), or \"all\"")]
        public string Devices { get; set; }
    }

    class DeviceRenameOptions
    {
        [Value(0, Required = true, HelpText = "device number (as shown in device-list) or name")]
        public string Device { get; set; }

        [Value(1, Required = true, HelpText = "new device name")]
        public string NewName { get; set; }
    }

    class BiometricOptions
    {
        [Value(0, Required = false, HelpText = "Biometric command: \"register\", \"list\", \"remove\", \"verify\"")]
        public string Action { get; set; }

        [Option("friendly-name", Required = false, HelpText = "Friendly name for the biometric credential (for register)")]
        public string FriendlyName { get; set; }

        [Option("force", Required = false, Default = false, HelpText = "Force registration even if credential exists")]
        public bool Force { get; set; }

        [Option("include-disabled", Required = false, Default = false, HelpText = "Include disabled biometric credentials in list")]
        public bool IncludeDisabled { get; set; }

        [Option("purpose", Required = false, Default = "vault", HelpText = "Authentication purpose: 'login' or 'vault' (for verify command)")]
        public string Purpose { get; set; }
    }
    public static class BiometricActions
        {
            public const string Register = "register";
            public const string List = "list";
            public const string Remove = "remove";
            public const string Verify = "verify";
        }
        
    public static class PasskeyPurposes
        {
            public const string Login = "login";
            public const string Vault = "vault";
        }
}
}