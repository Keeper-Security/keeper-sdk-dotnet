using System;
using System.Collections.Generic;
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

                Commands.Add("get",
                    new ParseableCommand<GetObjectOptions>
                    {
                        Order = 25,
                        Description = "Get information about any Keeper object (record, folder, team, etc.)",
                        Action = async options => await GetCommand(options),
                    });

                Commands.Add("logout",
                    new ParseableCommand<LogoutOptions>
                    {
                        Order = 200,
                        Description = "Logout",
                        Action = LogoutCommand,
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

        // Helper methods for resolving names to UIDs
        private KeeperRecord TryResolveRecord(string identifier)
        {
            // First try as UID
            if (_vaultContext.Vault.TryGetKeeperRecord(identifier, out var record))
            {
                return record;
            }
            
            // Then try by title/name
            foreach (var r in _vaultContext.Vault.KeeperRecords)
            {
                if (string.Equals(r.Title, identifier, StringComparison.OrdinalIgnoreCase))
                {
                    return r;
                }
            }
            
            return null;
        }

        private FolderNode TryResolveFolder(string identifier)
        {
            // First try as UID
            if (_vaultContext.Vault.TryGetFolder(identifier, out var folder))
            {
                return folder;
            }
            
            // Then try by name
            foreach (var f in _vaultContext.Vault.Folders)
            {
                if (string.Equals(f.Name, identifier, StringComparison.OrdinalIgnoreCase))
                {
                    return f;
                }
            }
            
            return null;
        }

        private SharedFolder TryResolveSharedFolder(string identifier)
        {
            // First try as UID
            if (_vaultContext.Vault.TryGetSharedFolder(identifier, out var sharedFolder))
            {
                return sharedFolder;
            }
            
            // Then try by name
            foreach (var sf in _vaultContext.Vault.SharedFolders)
            {
                if (string.Equals(sf.Name, identifier, StringComparison.OrdinalIgnoreCase))
                {
                    return sf;
                }
            }
            
            return null;
        }

        private async Task<(KeeperSecurity.Vault.Team vaultTeam, string resolvedUid)> TryResolveTeam(string identifier)
        {
            // First try as UID
            if (_vaultContext.Vault.TryGetTeam(identifier, out var team))
            {
                return (team, identifier);
            }
            
            // Then try by name in vault teams
            foreach (var t in _vaultContext.Vault.Teams)
            {
                if (string.Equals(t.Name, identifier, StringComparison.OrdinalIgnoreCase))
                {
                    return (t, t.TeamUid);
                }
            }
            
            // Try available teams by name
            try
            {
                var availableTeams = await _vaultContext.GetAvailableTeams();
                foreach (var at in availableTeams)
                {
                    if (string.Equals(at.Name, identifier, StringComparison.OrdinalIgnoreCase))
                    {
                        return (null, at.TeamUid); // Return UID for further processing
                    }
                }
            }
            catch
            {
                // Ignore errors getting available teams
            }
            
            // Try enterprise teams by name
            if (EnterpriseData?.Teams != null)
            {
                foreach (var et in EnterpriseData.Teams)
                {
                    if (string.Equals(et.Name, identifier, StringComparison.OrdinalIgnoreCase))
                    {
                        return (null, et.Uid); // Return UID for further processing
                    }
                }
            }
            
            return (null, null);
        }

        private async Task GetCommand(GetObjectOptions options)
        {
            var identifier = options.ObjectIdentifier;
            var tab = new Tabulate(3);
            tab.MaxColumnWidth = 1000; // Set large width to prevent truncation
            
            // Validate that only one object type is specified
            var typeCount = new[] { options.IsRecord, options.IsFolder, options.IsSharedFolder, options.IsTeam }.Count(x => x);
            if (typeCount > 1)
            {
                Console.WriteLine("Error: Only one object type can be specified at a time.");
                Console.WriteLine("Use one of: --record, --folder, --shared-folder, --team");
                return;
            }
            
            // If a specific type is requested, check only that type
            if (options.IsRecord)
            {
                var record = TryResolveRecord(identifier);
                if (record != null)
                {
                    await DisplayRecordInfo(record, tab);
                }
                else
                {
                    Console.WriteLine($"Record with name or UID '{identifier}' not found or not accessible.");
                    return;
                }
            }
            else if (options.IsFolder)
            {
                var folder = TryResolveFolder(identifier);
                if (folder != null)
                {
                    DisplayFolderInfo(folder, tab);
                }
                else
                {
                    Console.WriteLine($"Folder with name or UID '{identifier}' not found or not accessible.");
                    return;
                }
            }
            else if (options.IsSharedFolder)
            {
                var sharedFolder = TryResolveSharedFolder(identifier);
                if (sharedFolder != null)
                {
                    DisplaySharedFolderInfo(sharedFolder, tab);
                }
                else
                {
                    Console.WriteLine($"Shared folder with name or UID '{identifier}' not found or not accessible.");
                    return;
                }
            }
            else if (options.IsTeam)
            {
                var teamResult = await TryResolveTeam(identifier);
                if (teamResult.vaultTeam != null)
                {
                    // User is a team member - show full info
                    tab.AddRow("Team UID:", teamResult.vaultTeam.TeamUid);
                    tab.AddRow("Name:", teamResult.vaultTeam.Name);
                    tab.AddRow("Access Level:", "Full member access");
                    
                    // Try to get enterprise data for this team to show restrictions
                    if (EnterpriseData?.TryGetTeam(teamResult.resolvedUid, out var memberTeamEnterprise) == true)
                    {
                        tab.AddRow("Restrict Edit:", memberTeamEnterprise.RestrictEdit.ToString());
                        tab.AddRow("Restrict Share:", memberTeamEnterprise.RestrictSharing.ToString());
                        tab.AddRow("Restrict View:", memberTeamEnterprise.RestrictView.ToString());
                    }
                }
                else if (!string.IsNullOrEmpty(teamResult.resolvedUid))
                {
                    // Try other team sources using EXISTING IEnterpriseContext properties
                    if (!await TryDisplayTeamFromOtherSources(teamResult.resolvedUid, tab))
                    {
                        return; // Error message already displayed
                    }
                }
                else
                {
                    Console.WriteLine($"Team with name or UID '{identifier}' not found or not accessible.");
                    return;
                }
            }
            else
            {
                // No specific type specified - try all object types in order (original behavior)
                var record = TryResolveRecord(identifier);
                if (record != null)
                {
                    await DisplayRecordInfo(record, tab);
                }
                else
                {
                    var sharedFolder = TryResolveSharedFolder(identifier);
                    if (sharedFolder != null)
                    {
                        DisplaySharedFolderInfo(sharedFolder, tab);
                    }
                    else
                    {
                        var folder = TryResolveFolder(identifier);
                        if (folder != null)
                        {
                            DisplayFolderInfo(folder, tab);
                        }
                        else
                        {
                            var teamResult = await TryResolveTeam(identifier);
                            if (teamResult.vaultTeam != null)
                            {
                                // User is a team member - show full info
                                tab.AddRow("Team UID:", teamResult.vaultTeam.TeamUid);
                                tab.AddRow("Name:", teamResult.vaultTeam.Name);
                                tab.AddRow("Access Level:", "Full member access");
                                
                                // Try to get enterprise data for this team to show restrictions
                                if (EnterpriseData?.TryGetTeam(teamResult.resolvedUid, out var memberTeamEnterprise) == true)
                                {
                                    tab.AddRow("Restrict Edit:", memberTeamEnterprise.RestrictEdit.ToString());
                                    tab.AddRow("Restrict Share:", memberTeamEnterprise.RestrictSharing.ToString());
                                    tab.AddRow("Restrict View:", memberTeamEnterprise.RestrictView.ToString());
                                }
                            }
                            else if (!string.IsNullOrEmpty(teamResult.resolvedUid))
                            {
                                // Try other team sources using EXISTING IEnterpriseContext properties
                                if (!await TryDisplayTeamFromOtherSources(teamResult.resolvedUid, tab))
                                {
                                    return; // Error message already displayed
                                }
                            }
                            else
                            {
                                Console.WriteLine($"Object with name or UID '{identifier}' not found or not accessible.");
                                Console.WriteLine("Checked: Records, Shared Folders, Folders, and Teams");
                                return;
                            }
                        }
                    }
                }
            }

            Console.WriteLine();
            tab.SetColumnRightAlign(0, true);
            tab.LeftPadding = 4;
            tab.Dump();
        }

        private async Task<bool> TryDisplayTeamFromOtherSources(string uid, Tabulate tab)
        {
            // Try available teams (sharing)
            try
            {
                var availableTeams = await _vaultContext.GetAvailableTeams();
                var availableTeam = availableTeams.FirstOrDefault(t => 
                    string.Equals(t.TeamUid, uid, StringComparison.OrdinalIgnoreCase));
                
                if (availableTeam != null)
                {
                    tab.AddRow("Team UID:", availableTeam.TeamUid);
                    tab.AddRow("Name:", availableTeam.Name);
                    tab.AddRow("Access Level:", "Available for sharing");
                    
                    // Try to get enterprise data for restrictions if available
                    if (EnterpriseData?.TryGetTeam(uid, out var availableTeamEnterprise) == true)
                    {
                        tab.AddRow("Restrict Edit:", availableTeamEnterprise.RestrictEdit.ToString());
                        tab.AddRow("Restrict Share:", availableTeamEnterprise.RestrictSharing.ToString());
                        tab.AddRow("Restrict View:", availableTeamEnterprise.RestrictView.ToString());
                    }
                    
                    tab.AddRow("Note:", $"User {_auth.Username} does not belong to team {availableTeam.Name}");
                    return true;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Warning: Could not fetch available teams: {ex.Message}");
            }

            // Try enterprise teams using EXISTING EnterpriseData property
            if (EnterpriseData?.TryGetTeam(uid, out var enterpriseTeam) == true)
            {
                tab.AddRow("Team UID:", enterpriseTeam.Uid);
                tab.AddRow("Name:", enterpriseTeam.Name);
                tab.AddRow("Access Level:", "Enterprise administrative access");
                tab.AddRow("Parent Node ID:", enterpriseTeam.ParentNodeId.ToString());
                tab.AddRow("Restrict Edit:", enterpriseTeam.RestrictEdit.ToString());
                tab.AddRow("Restrict Share:", enterpriseTeam.RestrictSharing.ToString());
                tab.AddRow("Restrict View:", enterpriseTeam.RestrictView.ToString());
                
                // Show member count using EXISTING EnterpriseData
                var memberIds = EnterpriseData.GetUsersForTeam(enterpriseTeam.Uid);
                tab.AddRow("Member Count:", memberIds.Length.ToString());
                
                tab.AddRow("Note:", $"User {_auth.Username} does not belong to team {enterpriseTeam.Name}");
                return true;
            }

            // Not found anywhere
            Console.WriteLine($"UID {uid} is not a valid Keeper object");
            Console.WriteLine("Checked: Records, Shared Folders, Folders, and Teams");
            return false;
        }

        private async Task DisplayRecordInfo(KeeperRecord record, Tabulate tab)
        {
            var totps = new List<string>();

            tab.AddRow("Record UID:", record.Uid);
            tab.AddRow("Type:", record.KeeperRecordType());
            tab.AddRow("Title:", record.Title);
            
            if (record is PasswordRecord legacy)
            {
                tab.AddRow("Notes:", legacy.Notes);
                tab.AddRow("$login:", legacy.Login);
                tab.AddRow("$password:", legacy.Password);
                tab.AddRow("$url:", legacy.Link);
                if (!string.IsNullOrEmpty(legacy.Totp))
                {
                    totps.Add(legacy.Totp);
                    tab.AddRow("$oneTimeCode:", legacy.Totp);
                }

                if (legacy.Custom != null && legacy.Custom.Count > 0)
                {
                    foreach (var c in legacy.Custom)
                    {
                        tab.AddRow(c.Name + ":", c.Value);
                    }
                }
            }
            else if (record is TypedRecord typed)
            {
                tab.AddRow("Notes:", typed.Notes);
                foreach (var f in typed.Fields.Concat(typed.Custom))
                {
                    if (f.FieldName == "oneTimeCode")
                    {
                        if (f is TypedField<string> sf && sf.Count > 0)
                        {
                            totps.AddRange(sf.Values.Where(x => !string.IsNullOrEmpty(x)));
                        }
                    }
                    else
                    {
                        var label = f.GetTypedFieldName();
                        var values = f.GetTypedFieldValues().ToArray();
                        for (var i = 0; i < Math.Max(values.Length, 1); i++)
                        {
                            var v = i < values.Length ? values[i] : "";
                            if (i == 0)
                            {
                                tab.AddRow($"{label}:", v);
                            }
                            else
                            {
                                tab.AddRow("", v);
                            }
                        }
                    }
                }
            }
            else if (record is FileRecord file)
            {
                tab.AddRow("Name:", file.Name);
                tab.AddRow("MIME Type:", file.MimeType ?? "");
                tab.AddRow("Size:", file.FileSize.ToString("N0"));
                if (file.ThumbnailSize > 0)
                {
                    tab.AddRow("Thumbnail Size:", file.ThumbnailSize.ToString("N0"));
                }
            }

            foreach (var url in totps)
            {
                tab.AddRow("$oneTimeCode:", url);
                try
                {
                    var tup = CryptoUtils.GetTotpCode(url);
                    if (tup != null)
                    {
                        tab.AddRow($"{tup.Item1}:", $"expires in {tup.Item3 - tup.Item2} sec.");
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine(e.Message);
                }
            }

            tab.AddRow("Last Modified:", record.ClientModified.LocalDateTime.ToString("F"));
            var shareInfo = (await _vaultContext.Vault.GetSharesForRecords(new[] { record.Uid }))
                .FirstOrDefault(x => x.RecordUid == record.Uid);
            
            if (shareInfo?.UserPermissions?.Length > 0)
            {
                tab.AddRow("", "");
                tab.AddRow("User Shares:", "");
                foreach (var rs in shareInfo.UserPermissions)
                {
                    string status;
                    if (rs.Owner)
                    {
                        status = "Owner";
                    }
                    else
                    {
                        if (rs.AwaitingApproval)
                        {
                            status = "Awaiting Approval";
                        }
                        else
                        {
                            if (!rs.CanEdit && !rs.CanShare)
                            {
                                status = "Read Only";
                            }
                            else if (rs.CanEdit && rs.CanShare)
                            {
                                status = "Can Edit & Share";
                            }
                            else if (rs.CanEdit)
                            {
                                status = "Can Edit";
                            }
                            else
                            {
                                status = "Can Share";
                            }
                        }
                    }

                    if (rs.Expiration.HasValue)
                    {
                        status += $" (Expires: {rs.Expiration.Value.LocalDateTime:g})";
                    }

                    tab.AddRow(rs.Username, status);
                }
            }

            if (shareInfo?.SharedFolderPermissions != null)
            {
                tab.AddRow("", "");
                tab.AddRow("Shared Folders:", "");
                foreach (var sfs in shareInfo.SharedFolderPermissions)
                {
                    string status;
                    if (!sfs.CanEdit && !sfs.CanShare)
                    {
                        status = "Read Only";
                    }
                    else if (sfs.CanEdit && sfs.CanShare)
                    {
                        status = "Can Edit & Share";
                    }
                    else if (sfs.CanEdit)
                    {
                        status = "Can Edit";
                    }
                    else
                    {
                        status = "Can Share";
                    }

                    var name = sfs.SharedFolderUid;
                    if (_vaultContext.Vault.TryGetSharedFolder(sfs.SharedFolderUid, out var sf))
                    {
                        name = sf.Name;
                    }

                    tab.AddRow(name, status);
                }
            }

            _vaultContext.Vault.AuditLogRecordOpen(record.Uid);
        }

        private void DisplaySharedFolderInfo(SharedFolder sf, Tabulate tab)
        {
            tab.AddRow("Shared Folder UID:", sf.Uid);
            tab.AddRow("Name:", sf.Name);
            tab.AddRow("Default Manage Records:", sf.DefaultManageRecords.ToString());
            tab.AddRow("Default Manage Users:", sf.DefaultManageUsers.ToString());
            tab.AddRow("Default Can Edit:", sf.DefaultCanEdit.ToString());
            tab.AddRow("Default Can Share:", sf.DefaultCanShare.ToString());
            
            if (sf.RecordPermissions.Count > 0)
            {
                tab.AddRow("");
                tab.AddRow("Record Permissions:");
                foreach (var r in sf.RecordPermissions)
                {
                    string permission;
                    if (r.CanEdit && r.CanShare)
                    {
                        permission = "Can Edit & Share";
                    }
                    else if (r.CanEdit)
                    {
                        permission = "Can Edit";
                    }
                    else if (r.CanShare)
                    {
                        permission = "Can Share";
                    }
                    else
                    {
                        permission = "View Only";
                    }

                    tab.AddRow(r.RecordUid + ":", permission);
                }
            }

            string GetUsername(string userId, UserType userType)
            {
                switch (userType)
                {
                    case UserType.User:
                        if (_vaultContext.Vault.TryGetUsername(userId, out var email))
                        {
                            return email;
                        }
                        break;
                    case UserType.Team:
                        if (_vaultContext.Vault.TryGetTeam(userId, out var team))
                        {
                            return team.Name;
                        }
                        break;
                }
                return userId;
            }

            if (sf.UsersPermissions.Count > 0)
            {
                tab.AddRow("");
                tab.AddRow("User/Team Permissions:");
                var sortedList = sf.UsersPermissions.ToList();
                sortedList.Sort((x, y) =>
                {
                    var res = x.UserType.CompareTo(y.UserType);
                    if (res == 0)
                    {
                        var xName = GetUsername(x.Uid, x.UserType);
                        var yName = GetUsername(y.Uid, y.UserType);
                        res = string.Compare(xName, yName, StringComparison.OrdinalIgnoreCase);
                    }
                    return res;
                });
                
                foreach (var u in sortedList)
                {
                    string permissions;
                    if (u.ManageRecords || u.ManageUsers)
                    {
                        permissions = "Can Manage " +
                                      string.Join(" & ",
                                          new[] { u.ManageUsers ? "Users" : "", u.ManageRecords ? "Records" : "" }
                                              .Where(x => !string.IsNullOrEmpty(x)));
                    }
                    else
                    {
                        permissions = "No User Permissions";
                    }

                    var subjectName = GetUsername(u.Uid, u.UserType);
                    tab.AddRow($"{u.UserType} {subjectName}:", permissions);
                }
            }
        }

        private void DisplayFolderInfo(FolderNode f, Tabulate tab)
        {
            tab.AddRow("Folder UID:", f.FolderUid);
            if (!string.IsNullOrEmpty(f.ParentUid))
            {
                tab.AddRow("Parent Folder UID:", f.ParentUid);
            }
            tab.AddRow("Folder Type:", f.FolderType.ToString());
            tab.AddRow("Name:", f.Name);
        }

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            _vaultContext.Vault.Dispose();
            _auth.Dispose();
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

    class GetObjectOptions
    {
        [Value(0, Required = true, HelpText = "UID or name of the object (record, folder, shared-folder, team) to retrieve information about")]
        public string ObjectIdentifier { get; set; }

        [Option('r', "record", Required = false, HelpText = "Specify that the UID is a record")]
        public bool IsRecord { get; set; }

        [Option('f', "folder", Required = false, HelpText = "Specify that the UID is a folder")]
        public bool IsFolder { get; set; }

        [Option('s', "shared-folder", Required = false, HelpText = "Specify that the UID is a shared folder")]
        public bool IsSharedFolder { get; set; }

        [Option('t', "team", Required = false, HelpText = "Specify that the UID is a team")]
        public bool IsTeam { get; set; }
    }

}