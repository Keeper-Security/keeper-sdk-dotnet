using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using CommandLine;
using Enterprise;
using Google.Protobuf;
using KeeperSecurity.Sdk;
using KeyType = Enterprise.KeyType;

namespace Commander
{
    public partial class ConnectedContext
    {
        private byte[] _treeKey;

        private EnterpriseNode[] _nodes;
        private EnterpriseUser[] _users;
        private EnterpriseRoleKey2[] _roleKey2s = null;
        private EnterpriseKeys _keys;
        private DeviceForAdminApproval[] _deviceForAdminApprovals;
        /*
        private string EnterpriseName { get; set; }
        private EnterpriseRole[] _roles = null;
        private EnterpriseRoleUser[] _roleUsers = null;
        private EnterpriseRoleKey[] _roleKeys = null;
        private EnterpriseTeam[] _teams = null;
        private EnterpriseTeamUser[] _teamUsers = null;
        */

        private bool EnterpriseNotificationCallback(NotificationEvent evt)
        {
            if (evt.Event == "request_device_admin_approval")
            {
                _deviceForAdminApprovals = null;
                Console.WriteLine($"\n{evt.Email} requested Device Approval\nIP Address: {evt.IPAddress}\nDevice Name: {evt.DeviceName}");
            }

            return false;
        }

        private void CheckIfEnterpriseAdmin()
        {
            if (_auth.AuthContext.IsEnterpriseAdmin)
            {
                lock (Commands)
                {
                    _auth.PushNotifications?.RegisterCallback(EnterpriseNotificationCallback);

                    Commands.Add("enterprise-node",
                        new ParsableCommand<EnterpriseNodeOptions>
                        {
                            Order = 60,
                            Description = "Display node structure ",
                            Action = EnterpriseNodeCommand,
                        });

                    Commands.Add("enterprise-user",
                        new ParsableCommand<EnterpriseUserOptions>
                        {
                            Order = 61,
                            Description = "List Enterprise Users",
                            Action = EnterpriseUserCommand,
                        });

                    Commands.Add("enterprise-device",
                        new ParsableCommand<EnterpriseDeviceOptions>
                        {
                            Order = 62,
                            Description = "Manage User Devices",
                            Action = EnterpriseDeviceCommand,
                        });

                    CommandAliases["en"] = "enterprise-node";
                    CommandAliases["eu"] = "enterprise-user";
                    CommandAliases["ed"] = "enterprise-device";
                }

                Task.Run(async () =>
                {
                    try
                    {
                        await GetEnterpriseData("keys");
                        if (_keys != null)
                        {
                            if (string.IsNullOrEmpty(_keys.EccEncryptedPrivateKey) && _treeKey != null)
                            {
                                Commands.Add("enterprise-add-key",
                                    new SimpleCommand
                                    {
                                        Order = 63,
                                        Description = "Register ECC key pair",
                                        Action = EnterpriseRegisterEcKey,
                                    });
                            }
                        }
                    }
                    catch (Exception e)
                    {
                        Debug.WriteLine(e);
                    }
                });
            }
        }

        class EnterpriseGenericOptions
        {
            [Option('f', "force", Required = false, Default = false, HelpText = "force reload enterprise data")]
            public bool Force { get; set; }
        }

        class EnterpriseNodeOptions : EnterpriseGenericOptions
        {
            [Value(0, Required = false, HelpText = "enterprise-node command: \"tree\"")]
            public string Command { get; set; }
        }

        class EnterpriseUserOptions : EnterpriseGenericOptions
        {
            [Value(0, Required = false, HelpText = "enterprise-node command: \"list\"")]
            public string Command { get; set; }

            [Option("match", Required = false, HelpText = "Filter matching user information")]
            public string Match { get; set; }
        }

        class EnterpriseDeviceOptions : EnterpriseGenericOptions
        {
            [Value(0, Required = false, HelpText = "enterprise-device command: \"list\", \"approve\", \"decline\"")]
            public string Command { get; set; }

            [Value(1, Required = false, HelpText = "enterprise-device command: \"list\", \"approve\", \"decline\"")]
            public string Match { get; set; }
        }

        private void DecryptData(IEncryptedData encrypted)
        {
            if (string.IsNullOrEmpty(encrypted.EncryptedData)) return;
            if (encrypted.EncryptedData.Length < 30) return;
            try
            {
                var decryptedData = CryptoUtils.DecryptAesV1(encrypted.EncryptedData.Base64UrlDecode(), _treeKey);
                var data = JsonUtils.ParseJson<EncryptedData>(decryptedData);
                if (encrypted is IDisplayName dn)
                {
                    dn.DisplayName = data.DisplayName;
                }
            }
            catch (Exception e)
            {
                Debug.WriteLine(e);
            }
        }

        public async Task GetEnterpriseData(params string[] includes)
        {
            var requested = new HashSet<string>(includes);
            var rq = new EnterpriseDataCommand
            {
                include = requested.ToArray()
            };
            var rs = await _auth.ExecuteAuthCommand<EnterpriseDataCommand, EnterpriseDataResponse>(rq);
            if (_treeKey == null)
            {
                var encTreeKey = rs.TreeKey.Base64UrlDecode();
                _treeKey = rs.KeyTypeId switch
                {
                    1 => CryptoUtils.DecryptAesV1(encTreeKey, _auth.AuthContext.DataKey),
                    2 => CryptoUtils.DecryptRsa(encTreeKey, _auth.AuthContext.PrivateKey),
                    _ => throw new Exception("cannot decrypt tree key")
                };
            }

            if (requested.Contains("nodes") && rs.Nodes != null)
            {
                foreach (var node in rs.Nodes)
                {
                    DecryptData(node);
                }

                _nodes = rs.Nodes.ToArray();
            }

            if (requested.Contains("users"))
            {
                if (rs.Users != null)
                {
                    foreach (var user in rs.Users)
                    {
                        DecryptData(user);
                    }

                    _users = rs.Users.ToArray();
                }
                else
                {
                    _users = new EnterpriseUser[0];
                }

            }

            if (requested.Contains("devices_request_for_admin_approval"))
            {
                _deviceForAdminApprovals = rs.DeviceRequestForApproval != null ? rs.DeviceRequestForApproval.ToArray() : new DeviceForAdminApproval[0];
            }

            if (requested.Contains("role_keys2"))
            {
                _roleKey2s = rs.RoleKeys2 != null ? rs.RoleKeys2.ToArray() : new EnterpriseRoleKey2[0];
            }

            if (requested.Contains("keys"))
            {
                _keys = rs.Keys;
            }
        }

        public void PrintNodeTree(EnterpriseNode eNode, string indent, bool last)
        {
            var isRoot = string.IsNullOrEmpty(indent);
            Console.WriteLine(indent + (isRoot ? "" : "+-- ") + eNode.DisplayName);
            indent += isRoot ? " " : (last ? "    " : "|   ");
            var subNodes = _nodes.Where(x => x.ParentId == eNode.NodeId).Where(x => !string.IsNullOrEmpty(x.DisplayName)).ToArray();
            for (var i = 0; i < subNodes.Length; i++)
            {
                PrintNodeTree(subNodes[i], indent, i == subNodes.Length - 1);
            }
        }

        private async Task EnterpriseNodeCommand(EnterpriseNodeOptions arguments)
        {
            if (string.IsNullOrEmpty(arguments.Command)) arguments.Command = "tree";

            if (arguments.Force || _nodes == null)
            {
                await GetEnterpriseData("nodes");
            }

            if (_nodes == null) throw new Exception("Enterprise data: cannot get nodes");
            switch (arguments.Command.ToLowerInvariant())
            {
                case "tree":
                {
                    var rootNode = _nodes.FirstOrDefault(x => x.ParentId == 0);
                    if (rootNode != null)
                    {
                        PrintNodeTree(rootNode, "", true);
                    }
                }
                    break;
                default:
                    Console.WriteLine($"Unsupported command \"{arguments.Command}\": available commands \"tree\"");
                    break;
            }
        }

        private string GetUserStatus(EnterpriseUser user)
        {
            switch (user.Status)
            {
                case "active":
                    switch (user.Lock)
                    {
                        case 0:
                        {
                            if (user.AccountShareExpiration.HasValue)
                            {
                                var ts = (long) user.AccountShareExpiration.Value;
                                if (ts > 0)
                                {
                                    var tsNow = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                                    if (tsNow > ts)
                                    {
                                        return "Blocked";
                                    }
                                }
                            }

                            return "Active";
                        }
                        case 1: return "Locked";
                        case 2: return "Disabled";
                        default: return user.Status;
                    }

                case "invited":
                    return "Invited";

                default:
                    return user.Status;

            }
        }

        private async Task EnterpriseUserCommand(EnterpriseUserOptions arguments)
        {
            if (string.IsNullOrEmpty(arguments.Command)) arguments.Command = "list";

            if (arguments.Force || _users == null)
            {
                await GetEnterpriseData("users");
            }

            if (_users == null) throw new Exception("Enterprise data: cannot get users");
            switch (arguments.Command.ToLowerInvariant())
            {
                case "list":
                {
                    var users = _users
                        .Where(x =>
                        {
                            if (string.IsNullOrEmpty(arguments.Match)) return true;
                            var m = Regex.Match(x.Username, arguments.Match, RegexOptions.IgnoreCase);
                            if (m.Success) return true;
                            if (!string.IsNullOrEmpty(x.DisplayName))
                            {
                                m = Regex.Match(x.DisplayName, arguments.Match, RegexOptions.IgnoreCase);
                                if (m.Success) return true;
                            }

                            var status = GetUserStatus(x);
                            m = Regex.Match(status, arguments.Match, RegexOptions.IgnoreCase);
                            if (m.Success) return true;

                            return false;
                        })
                        .ToArray();

                    var tab = new Tabulate(3)
                    {
                        DumpRowNo = true
                    };
                    tab.AddHeader(new[] {"Email", "Display Name", "Status"});
                    foreach (var user in users)
                    {
                        tab.AddRow(new[] {user.Username, user.DisplayName, GetUserStatus(user)});
                    }

                    tab.Sort(1);
                    tab.Dump();
                }
                    break;
                default:
                    Console.WriteLine($"Unsupported command \"{arguments.Command}\": available commands \"list\"");
                    break;
            }
        }

        private async Task EnterpriseDeviceCommand(EnterpriseDeviceOptions arguments)
        {
            if (string.IsNullOrEmpty(arguments.Command)) arguments.Command = "list";

            if (arguments.Force || _deviceForAdminApprovals == null)
            {
                var includes = new List<string> {"devices_request_for_admin_approval"};
                if (_users == null)
                {
                    includes.Add("users");
                }

                if (_roleKey2s == null)
                {
                    includes.Add("role_keys2");
                }

                await GetEnterpriseData(includes.ToArray());
            }

            if (_deviceForAdminApprovals.Length == 0)
            {
                Console.WriteLine("There are no pending devices");
                return;
            }

            var cmd = arguments.Command.ToLowerInvariant();
            switch (cmd)
            {
                case "list":
                    var tab = new Tabulate(4)
                    {
                        DumpRowNo = false
                    };
                    Console.WriteLine();
                    tab.AddHeader(new[] {"Email", "Device ID", "Device Name", "Client Version"});
                    foreach (var device in _deviceForAdminApprovals)
                    {
                        var user = _users.FirstOrDefault(x => x.EnterpriseUserId == device.EnterpriseUserId);
                        if (user != null)
                        {
                            tab.AddRow(new[] {user.Username, TokenToString(device.EncryptedDeviceToken.Base64UrlDecode()), device.DeviceName, device.ClientVersion});
                        }
                    }

                    tab.Sort(1);
                    tab.Dump();
                    break;

                case "approve":
                case "deny":
                    if (string.IsNullOrEmpty(arguments.Match))
                    {
                        Console.WriteLine($"{arguments.Command} command requires device ID or user email parameter.");
                    }
                    else
                    {
                        var devices = _deviceForAdminApprovals
                            .Where(x =>
                            {
                                if (arguments.Match == "all") return true;
                                var deviceId = TokenToString(x.EncryptedDeviceToken.Base64UrlDecode());
                                if (deviceId.StartsWith(arguments.Match)) return true;
                                var user = _users.FirstOrDefault(y => y.EnterpriseUserId == x.EnterpriseUserId);
                                if (user != null)
                                {
                                    if (user.Username == arguments.Match) return true;
                                }

                                return false;

                            }).ToArray();

                        if (devices.Length > 0)
                        {
                            var userDataKeys = new Dictionary<string, byte[]>();
                            var rq = new ApproveUserDevicesRequest();
                            foreach (var device in devices)
                            {
                                var deviceRq = new ApproveUserDeviceRequest
                                {
                                    EnterpriseUserId = device.EnterpriseUserId,
                                    EncryptedDeviceToken = ByteString.CopyFrom(device.EncryptedDeviceToken.Base64UrlDecode()),
                                    DenyApproval = cmd == "deny"
                                };
                                if (cmd == "approve" && device.DevicePublicKey?.Length > 0)
                                {
                                    byte[] userDataKey = null;
                                    var user = _users.FirstOrDefault(x => x.EnterpriseUserId == device.EnterpriseUserId);
                                    if (user == null) continue;
                                    if (!userDataKeys.ContainsKey(user.Username))
                                    {
                                        var transferRq = new PreAccountTransferCommand
                                        {
                                            TargetUsername = user.Username
                                        };
                                        var transferRs = await _auth.ExecuteAuthCommand<PreAccountTransferCommand, PreAccountTransferDataResponse>(transferRq, false);
                                        if (transferRs.IsSuccess)
                                        {
                                            byte[] roleKey = null;
                                            if (transferRs.RoleKeyId.HasValue)
                                            {
                                                var roleKey2 = _roleKey2s.FirstOrDefault(x => x.RoleId == transferRs.RoleKeyId.Value);
                                                if (roleKey2 != null)
                                                {
                                                    roleKey = CryptoUtils.DecryptAesV2(roleKey2.RoleKey.Base64UrlDecode(), _treeKey);
                                                }
                                            }
                                            else if (!string.IsNullOrEmpty(transferRs.RoleKey))
                                            {
                                                roleKey = CryptoUtils.DecryptRsa(transferRs.RoleKey.Base64UrlDecode(), _auth.AuthContext.PrivateKey);
                                            }

                                            if (roleKey != null)
                                            {
                                                var rolePk = CryptoUtils.DecryptAesV1(transferRs.RolePrivateKey.Base64UrlDecode(), roleKey);
                                                var pk = CryptoUtils.LoadPrivateKey(rolePk);
                                                userDataKey = CryptoUtils.DecryptRsa(transferRs.TransferKey.Base64UrlDecode(), pk);
                                            }
                                        }

                                        userDataKeys[user.Username] = userDataKey;
                                        if (userDataKey == null)
                                        {
                                            Console.WriteLine($"Cannot resolve data key for user {user.Username}: ({transferRs.resultCode}) - {transferRs.message}");
                                        }
                                    }

                                    if (userDataKeys.TryGetValue(user.Username, out userDataKey))
                                    {
                                        if (userDataKey != null)
                                        {
                                            var devicePublicKey = CryptoUtils.LoadPublicEcKey(device.DevicePublicKey.Base64UrlDecode());
                                            deviceRq.EncryptedDeviceDataKey = ByteString.CopyFrom(CryptoUtils.EncryptEc(userDataKey, devicePublicKey));
                                        }
                                    }
                                }

                                rq.DeviceRequests.Add(deviceRq);
                            }

                            if (rq.DeviceRequests.Count == 0)
                            {
                                Console.WriteLine($"No device to approve/deny");
                            }
                            else
                            {
                                var rs = await _auth.ExecuteAuthRest<ApproveUserDevicesRequest, ApproveUserDevicesResponse>(
                                    "enterprise/approve_user_devices",
                                    rq);
                                if (rs.DeviceResponses?.Count > 0)
                                {
                                    foreach (var approveRs in rs.DeviceResponses)
                                    {
                                        if (approveRs.Failed)
                                        {
                                            var user = _users.FirstOrDefault(x => x.EnterpriseUserId == approveRs.EnterpriseUserId);
                                            if (user != null)
                                            {
                                                Console.WriteLine($"Failed to approve {user.Username}: {approveRs.Message}");
                                            }
                                        }
                                    }
                                }

                                _deviceForAdminApprovals = null;
                            }
                        }
                        else
                        {
                            Console.WriteLine($"No device found matching {arguments.Match}");
                        }
                    }

                    break;
            }
        }


        private async Task EnterpriseRegisterEcKey(string _)
        {
            if (_treeKey == null)
            {
                await GetEnterpriseData();
            }

            if (_treeKey == null)
            {
                Console.WriteLine("Cannot get tree key");
                return;
            }

            CryptoUtils.GenerateEcKey(out var privateKey, out var publicKey);
            var exportedPublicKey = CryptoUtils.UnloadEcPublicKey(publicKey);
            var exportedPrivateKey = CryptoUtils.UnloadEcPrivateKey(privateKey);
            var encryptedPrivateKey = CryptoUtils.EncryptAesV2(exportedPrivateKey, _treeKey);
            var request = new EnterpriseKeyPairRequest
            {
                KeyType = KeyType.Ecc,
                EnterprisePublicKey = ByteString.CopyFrom(exportedPublicKey),
                EncryptedEnterprisePrivateKey = ByteString.CopyFrom(encryptedPrivateKey),
            };

            await _auth.ExecuteAuthRest("enterprise/set_enterprise_key_pair", request);
            Commands.Remove("enterprise-add-key");
        }
    }
}
