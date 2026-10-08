using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using AccountSummary;
using Authentication;
using BreachWatch;
using Cli;
using CommandLine;
using DeviceManagement;
using Enterprise;
using Google.Protobuf;
using KeeperSecurity.Authentication;
using KeeperSecurity.BreachWatch;
using KeeperSecurity.Utils;
using KeeperSecurity.Vault;
using ZeroDep;
using UserDevice = DeviceManagement.Device;

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

                Commands.Add("biometric",
                    new ParseableCommand<BiometricOptions>
                    {
                        Order = 52,
                        Description = "Manage Windows Hello biometric authentication",
                        Action = BiometricCommand,
                    });

                Commands.Add("device-list",
                    new ParseableCommand<DeviceListOptions>
                    {
                        Order = 53,
                        Description = "List devices registered to the current account",
                        Action = DeviceListCommand,
                    });

                Commands.Add("device-action",
                    new ParseableCommand<DeviceActionOptions>
                    {
                        Order = 54,
                        Description = "Perform an action on devices registered to the current account",
                        Action = DeviceActionCommand,
                    });

                Commands.Add("device-rename",
                    new ParseableCommand<DeviceRenameOptions>
                    {
                        Order = 55,
                        Description = "Rename a device registered to the current account",
                        Action = DeviceRenameCommand,
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

        private async Task DeviceListCommand(DeviceListOptions options)
        {
            var format = (options.Format ?? "table").ToLowerInvariant();
            if (format != "table" && format != "json")
            {
                Console.WriteLine("Unsupported output format. Valid formats: table, json");
                return;
            }

            UserDevice[] devices;
            try
            {
                devices = (await _auth.GetUserDevices()).OrderByDescending(x => x.LastModifiedTime).ToArray();
            }
            catch (Exception e)
            {
                Console.Error.WriteLine($"Failed to retrieve devices: {e.Message}");
                return;
            }

            if (format == "json")
            {
                var jsonDevices = new List<Dictionary<string, object>>();
                for (var i = 0; i < devices.Length; i++)
                {
                    var device = devices[i];
                    jsonDevices.Add(new Dictionary<string, object>
                    {
                        ["id"] = i + 1,
                        ["deviceName"] = device.DeviceName,
                        ["clientType"] = device.ClientType.ToString().ToUpperInvariant(),
                        ["loginStatus"] = GetDeviceLoginStatus(device.LoginState),
                        ["lastAccessedTimestamp"] = GetDeviceTimestamp(device.LastModifiedTime),
                    });
                }

                var json = Json.Serialize(new Dictionary<string, object> { ["devices"] = jsonDevices });
                if (!string.IsNullOrEmpty(options.Output))
                {
                    try
                    {
                        File.WriteAllText(options.Output, json, Encoding.UTF8);
                        Console.WriteLine($"Results saved to {options.Output}");
                    }
                    catch (Exception e)
                    {
                        Console.Error.WriteLine($"Failed to save results to {options.Output}: {e.Message}");
                    }
                }
                else
                {
                    Console.WriteLine(json);
                }
                return;
            }

            if (devices.Length == 0)
            {
                Console.WriteLine("No devices found");
                return;
            }

            Console.WriteLine($"User Devices ({devices.Length} found)");
            var table = new Tabulate(5);
            table.AddHeader("ID", "Device Name", "Client Type", "Login Status", "Last Accessed");
            for (var i = 0; i < devices.Length; i++)
            {
                var device = devices[i];
                table.AddRow(i + 1, device.DeviceName, device.ClientType.ToString().ToUpperInvariant(),
                    GetDeviceLoginStatus(device.LoginState), GetDeviceTimestamp(device.LastModifiedTime));
            }
            table.Dump();
        }

        private async Task DeviceActionCommand(DeviceActionOptions options)
        {
            if (!DeviceManagementExtensions.TryParseDeviceAction(options.Action, out var actionType))
            {
                Console.Error.WriteLine($"Unsupported device action \"{options.Action}\"");
                return;
            }

            UserDevice[] devices;
            try
            {
                devices = (await _auth.GetUserDevices()).OrderByDescending(x => x.LastModifiedTime).ToArray();
            }
            catch (Exception e)
            {
                Console.Error.WriteLine($"Failed to retrieve devices: {e.Message}");
                return;
            }

            if (devices.Length == 0)
            {
                Console.Error.WriteLine("No devices found");
                return;
            }

            var selected = new List<UserDevice>();
            var resolutionErrors = new List<string>();
            foreach (var identifier in options.Devices.SelectMany(x => x.Split(',')))
            {
                var text = identifier.Trim();
                if (text.Length == 0) continue;

                var matches = ResolveUserDevices(devices, text);
                if (matches.Length == 0)
                    resolutionErrors.Add($"No device found for \"{text}\"");
                else if (matches.Length > 1)
                    resolutionErrors.Add($"Multiple devices match \"{text}\". Use a row number or a more specific device token.");
                else if (!selected.Any(x => x.EncryptedDeviceToken.Equals(matches[0].EncryptedDeviceToken)))
                    selected.Add(matches[0]);
            }

            if (resolutionErrors.Count > 0)
            {
                foreach (var error in resolutionErrors) Console.Error.WriteLine(error);
                return;
            }
            if (selected.Count == 0)
            {
                Console.Error.WriteLine("At least one device identifier must be specified");
                return;
            }
            if ((actionType == DeviceActionType.DaLink || actionType == DeviceActionType.DaUnlink) && selected.Count < 2)
            {
                Console.Error.WriteLine($"Action \"{options.Action}\" requires at least 2 devices");
                return;
            }

            IEnumerable<DeviceActionResult> results;
            try
            {
                results = await _auth.ExecuteDeviceAction(actionType, selected.Select(x => x.EncryptedDeviceToken));
            }
            catch (Exception e)
            {
                Console.Error.WriteLine($"Device action \"{options.Action}\" failed: {e.Message}");
                return;
            }

            var deviceNames = selected.ToDictionary(x => x.EncryptedDeviceToken.ToByteArray().Base64UrlEncode(),
                x => x.DeviceName ?? "Unknown Device");
            var returnedTokens = new HashSet<string>(StringComparer.Ordinal);
            var succeeded = 0;
            var failed = 0;
            foreach (var result in results ?? Enumerable.Empty<DeviceActionResult>())
            {
                foreach (var token in result.EncryptedDeviceToken)
                {
                    var tokenText = token.ToByteArray().Base64UrlEncode();
                    if (!deviceNames.ContainsKey(tokenText) || !returnedTokens.Add(tokenText)) continue;

                    var deviceName = deviceNames.TryGetValue(tokenText, out var name) ? name : "Unknown Device";
                    if (result.DeviceActionStatus == DeviceActionStatus.Success)
                    {
                        Console.WriteLine($"✓ Device '{deviceName}' successfully {GetDeviceActionVerb(options.Action)}");
                        succeeded++;
                    }
                    else if (result.DeviceActionStatus == DeviceActionStatus.NotAllowed)
                    {
                        Console.Error.WriteLine($"Device '{deviceName}': Operation not allowed");
                        failed++;
                    }
                    else
                    {
                        Console.Error.WriteLine($"Device '{deviceName}': Action failed ({result.DeviceActionStatus.ToString().ToUpperInvariant()})");
                        failed++;
                    }
                }
            }

            var missing = deviceNames.Keys.Where(x => !returnedTokens.Contains(x)).ToArray();
            foreach (var token in missing)
            {
                Console.Error.WriteLine($"Device '{deviceNames[token]}': Action result was not returned by the server");
            }
            if (failed > 0 || missing.Length > 0)
            {
                Console.Error.WriteLine($"Device action \"{options.Action}\" completed with partial failure: {succeeded} succeeded, {failed + missing.Length} failed or missing.");
            }

            if (succeeded > 0)
            {
                Console.WriteLine();
                Console.WriteLine("Updated device list:");
                await DeviceListCommand(new DeviceListOptions());
            }
        }

        private async Task DeviceRenameCommand(DeviceRenameOptions options)
        {
            string newName;
            try
            {
                newName = DeviceManagementExtensions.NormalizeDeviceName(options.NewName);
            }
            catch (ArgumentException e)
            {
                Console.Error.WriteLine(e.Message);
                return;
            }

            UserDevice[] devices;
            try
            {
                devices = (await _auth.GetUserDevices()).OrderByDescending(x => x.LastModifiedTime).ToArray();
            }
            catch (Exception e)
            {
                Console.Error.WriteLine($"Failed to retrieve devices: {e.Message}");
                return;
            }
            if (devices.Length == 0)
            {
                Console.Error.WriteLine("No devices found");
                return;
            }

            var matches = ResolveUserDevices(devices, options.Device);
            if (matches.Length == 0)
            {
                Console.Error.WriteLine($"No device found for \"{options.Device}\"");
                return;
            }
            if (matches.Length > 1)
            {
                Console.Error.WriteLine($"Multiple devices match \"{options.Device}\". Use a row number or a more specific device token.");
                return;
            }

            var device = matches[0];
            if (HasNormalizedDeviceName(devices, device, newName))
            {
                Console.Error.WriteLine($"Another device already uses the name '{newName}'");
                return;
            }
            DeviceRenameResult result;
            try
            {
                result = await _auth.RenameUserDevice(device.EncryptedDeviceToken, newName);
            }
            catch (Exception e)
            {
                Console.Error.WriteLine($"Device rename failed: {e.Message}");
                return;
            }
            if (result == null)
            {
                Console.Error.WriteLine("Device rename failed: no response from server");
                return;
            }
            if (result.DeviceActionStatus == DeviceActionStatus.NotAllowed)
            {
                Console.Error.WriteLine($"Device '{device.DeviceName}': Operation not allowed");
                return;
            }
            if (result.DeviceActionStatus != DeviceActionStatus.Success)
            {
                Console.Error.WriteLine($"Device '{device.DeviceName}': Rename failed ({result.DeviceActionStatus.ToString().ToUpperInvariant()})");
                return;
            }

            Console.WriteLine($"✓ Device name updated from '{device.DeviceName}' to '{result.DeviceNewName}'");
            Console.WriteLine();
            Console.WriteLine("Updated device list:");
            await DeviceListCommand(new DeviceListOptions());
        }

        private static UserDevice[] ResolveUserDevices(IReadOnlyList<UserDevice> devices, string identifier)
        {
            if (string.IsNullOrWhiteSpace(identifier)) return Array.Empty<UserDevice>();

            identifier = identifier.Trim();
            if (int.TryParse(identifier, out var rowNumber))
                return rowNumber >= 1 && rowNumber <= devices.Count ? new[] { devices[rowNumber - 1] } : Array.Empty<UserDevice>();

            var matches = devices.Where(x => x.EncryptedDeviceToken.ToByteArray().Base64UrlEncode()
                .Equals(identifier, StringComparison.OrdinalIgnoreCase)).ToArray();
            if (matches.Length == 0)
                matches = devices.Where(x => x.EncryptedDeviceToken.ToByteArray().Base64UrlEncode()
                    .StartsWith(identifier, StringComparison.OrdinalIgnoreCase)).ToArray();
            if (matches.Length == 0)
                matches = devices.Where(x => !string.IsNullOrEmpty(x.DeviceName) && x.DeviceName
                    .Equals(identifier, StringComparison.OrdinalIgnoreCase)).ToArray();
            return matches;
        }

        private static bool HasNormalizedDeviceName(IEnumerable<UserDevice> devices, UserDevice target, string normalizedName)
        {
            foreach (var device in devices)
            {
                if (device.EncryptedDeviceToken.Equals(target.EncryptedDeviceToken)) continue;
                try
                {
                    if (DeviceManagementExtensions.DeviceNamesEqual(device.DeviceName, normalizedName)) return true;
                }
                catch (ArgumentException)
                {
                    // Existing legacy names may not pass current validation and cannot be compared safely.
                }
            }
            return false;
        }

        private static string GetDeviceLoginStatus(LoginState loginState)
        {
            return loginState switch
            {
                LoginState.LoggedIn => "LOGGED_IN",
                LoginState.LoggedOut => "LOGGED_OUT",
                LoginState.DeviceLocked => "DEVICE_LOCKED",
                LoginState.DeviceAccountLocked => "DEVICE_ACCOUNT_LOCKED",
                LoginState.AccountLocked => "ACCOUNT_LOCKED",
                LoginState.LicenseExpired => "LICENSE_EXPIRED",
                _ => loginState.ToString().ToUpperInvariant(),
            };
        }

        private static string GetDeviceTimestamp(long timestamp)
        {
            if (timestamp <= 0) return "N/A";
            try
            {
                return (timestamp > 10000000000 ? DateTimeOffset.FromUnixTimeMilliseconds(timestamp) : DateTimeOffset.FromUnixTimeSeconds(timestamp))
                    .LocalDateTime.ToString("yyyy-MM-dd HH:mm:ss");
            }
            catch (ArgumentOutOfRangeException)
            {
                return $"Invalid timestamp: {timestamp}";
            }
        }

        private static string GetDeviceActionVerb(string action)
        {
            return action.ToLowerInvariant() switch
            {
                "logout" => "logged out", "remove" => "removed", "lock" => "locked", "unlock" => "unlocked",
                "account-lock" => "account locked", "account-unlock" => "account unlocked", "link" => "linked", "unlink" => "unlinked",
                _ => action,
            };
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

    class DeviceListOptions
    {
        [Option("format", Required = false, Default = "table", HelpText = "output format: table or json")]
        public string Format { get; set; }

        [Option("output", Required = false, HelpText = "JSON output file; ignored for table format")]
        public string Output { get; set; }
    }

    class DeviceActionOptions
    {
        [Value(0, Required = true, HelpText = "device action: logout, remove, lock, unlock, account-lock, account-unlock, link, unlink")]
        public string Action { get; set; }

        [Value(1, Required = true, Min = 1, HelpText = "device row ID, device token, or device name")]
        public IEnumerable<string> Devices { get; set; }
    }

    class DeviceRenameOptions
    {
        [Value(0, Required = true, HelpText = "device row ID, device token, or device name")]
        public string Device { get; set; }

        [Value(1, Required = true, HelpText = "new device name")]
        public string NewName { get; set; }
    }

    class ThisDeviceOptions
    {
        [Value(0, Required = false, HelpText = "this-device command: \"register\", \"rename\", \"timeout\", \"bio\", \"ip_disable_auto_approve\", \"persistent_login\"")]
        public string Command { get; set; }

        [Value(1, Required = false, HelpText = "sub-command parameter")]
        public string Parameter { get; set; }
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
