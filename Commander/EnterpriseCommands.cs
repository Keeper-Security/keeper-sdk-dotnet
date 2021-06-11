using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Authentication;
using CommandLine;
using Enterprise;
using Google.Protobuf;
using KeeperSecurity.Authentication;
using KeeperSecurity.Commands;
using KeeperSecurity.Enterprise;
using KeeperSecurity.Utils;
using Org.BouncyCastle.Crypto.Parameters;
using EnterpriseData = KeeperSecurity.Enterprise.EnterpriseData;

namespace Commander
{
    internal interface IEnterpriseContext
    {
        EnterpriseData Enterprise { get; set; }

        bool AutoApproveAdminRequests { get; set; }
        Dictionary<long, byte[]> UserDataKeys { get; }

        ECPrivateKeyParameters EnterprisePrivateKey { get; set; }

        IDictionary<string, AuditEventType> AuditEvents { get; set; }
    }

    internal static class EnterpriseExtensions
    {
        internal static void AppendEnterpriseCommands(this IEnterpriseContext context, CliCommands cli)
        {
            cli.Commands.Add("enterprise-sync-down",
                new SimpleCommand
                {
                    Order = 60,
                    Description = "Retrieve enterprise data",
                    Action = async _ => { await context.Enterprise.PopulateEnterprise(); },
                });

            cli.Commands.Add("enterprise-node",
                new ParsableCommand<EnterpriseNodeOptions>
                {
                    Order = 61,
                    Description = "Manage enterprise nodes",
                    Action = async options => { await context.EnterpriseNodeCommand(options); },
                });

            cli.Commands.Add("enterprise-user",
                new ParsableCommand<EnterpriseUserOptions>
                {
                    Order = 62,
                    Description = "List Enterprise Users",
                    Action = async options => { await context.EnterpriseUserCommand(options); },
                });

            cli.Commands.Add("enterprise-team",
                new ParsableCommand<EnterpriseTeamOptions>
                {
                    Order = 63,
                    Description = "List Enterprise Teams",
                    Action = async options => { await context.EnterpriseTeamCommand(options); },
                });

            cli.Commands.Add("enterprise-device",
                new ParsableCommand<EnterpriseDeviceOptions>
                {
                    Order = 64,
                    Description = "Manage User Devices",
                    Action = async options => { await context.EnterpriseDeviceCommand(options); },
                });

            cli.Commands.Add("audit-report",
                new ParsableCommand<AuditReportOptions>
                {
                    Order = 64,
                    Description = "Run an audit trail report.",
                    Action = async options => { await context.RunAuditEventsReport(options); },
                });

            cli.CommandAliases["esd"] = "enterprise-sync-down";
            cli.CommandAliases["en"] = "enterprise-node";
            cli.CommandAliases["eu"] = "enterprise-user";
            cli.CommandAliases["et"] = "enterprise-team";
            cli.CommandAliases["ed"] = "enterprise-device";

            if (context.Enterprise.EcPrivateKey == null)
            {
                cli.Commands.Add("enterprise-add-key",
                    new SimpleCommand
                    {
                        Order = 63,
                        Description = "Register ECC key pair",
                        Action = async options => { await context.EnterpriseRegisterEcKey(cli); },
                    });
            }
            else
            {
                context.EnterprisePrivateKey = CryptoUtils.LoadPrivateEcKey(context.Enterprise.EcPrivateKey);
            }
        }

        public static IEnumerable<string> GetNodePath(this IEnterpriseContext context, EnterpriseNode node)
        {
            while (true)
            {
                yield return node.DisplayName;
                if (node.Id <= 0) yield break;
                if (!context.Enterprise.TryGetNode(node.ParentNodeId, out var parent)) yield break;
                node = parent;
            }
        }

        public static void PrintNodeTree(this IEnterpriseContext context, EnterpriseNode eNode, string indent, bool verbose, bool last)
        {
            var isRoot = string.IsNullOrEmpty(indent);
            Console.WriteLine(indent + (isRoot ? "" : "+-- ") + eNode.DisplayName + (verbose ? $" ({eNode.Id})" : "") + (verbose && eNode.RestrictVisibility? " [Isolated]" : ""));
            indent += isRoot ? " " : (last ? "    " : "|   ");
            var subNodes = eNode.Subnodes
                .Select(x => context.Enterprise.TryGetNode(x, out var node) ? node : null)
                .Where(x => x != null)
                .OrderBy(x => x.DisplayName ?? "")
                .ToArray();
            for (var i = 0; i < subNodes.Length; i++)
            {
                context.PrintNodeTree(subNodes[i], indent, verbose, i == subNodes.Length - 1);
            }
        }

        private static EnterpriseNode ResolveNodeName(this EnterpriseData enterprise, string nodeName)
        {
            if (nodeName.All(x => char.IsDigit(x)))
            {
                if (long.TryParse(nodeName, out var nodeId))
                {
                    if (enterprise.TryGetNode(nodeId, out var node))
                    {
                        return node;
                    }
                }
            }

            var nodes = enterprise.Nodes.Where(x => string.Equals(nodeName, x.DisplayName, StringComparison.InvariantCultureIgnoreCase)).ToArray();
            if (nodes.Length == 1)
            {
                return nodes[0];
            }
            if (nodes.Length == 0)
            {
                throw new Exception($"Parent node \"{nodeName}\" is not found.");
            }
            else
            {
                throw new Exception($"There are {nodes.Length} nodes with name \"{nodeName}\". Use NodeID instead of Node name.");
            }
        }

        public static async Task EnterpriseNodeCommand(this IEnterpriseContext context, EnterpriseNodeOptions arguments)
        {
            if (string.IsNullOrEmpty(arguments.Command)) arguments.Command = "tree";

            if (arguments.Force)
            {
                await context.Enterprise.PopulateEnterprise();
            }

            if (context.Enterprise.RootNode == null) throw new Exception("Enterprise data: cannot get root node");

            EnterpriseNode parentNode = null;
            if (!string.IsNullOrEmpty(arguments.Parent))
            {
                parentNode = context.Enterprise.ResolveNodeName(arguments.Parent);
            }

            if (string.Equals(arguments.Command, "add", StringComparison.OrdinalIgnoreCase))  // node in the name of new node
            {
                if (string.IsNullOrEmpty(arguments.Node))
                {
                    var usage = CommandExtensions.GetCommandUsage<EnterpriseNodeOptions>(Console.WindowWidth);
                    Console.WriteLine(usage);
                }
                else
                {
                    var node = await context.Enterprise.CreateNode(arguments.Node, parentNode);
                    Console.WriteLine($"Node \"{arguments.Node}\" created.");
                    if (arguments.RestrictVisibility)
                    {
                        await context.Enterprise.SetRestrictVisibility(node.Id);
                    }
                }
            }
            else  // node is the name of the existing node
            {
                EnterpriseNode node;
                if (string.IsNullOrEmpty(arguments.Node))
                {
                    if (string.Equals(arguments.Command, "tree", StringComparison.OrdinalIgnoreCase))
                    {
                        node = context.Enterprise.RootNode;
                    }
                    else
                    {
                        var usage = CommandExtensions.GetCommandUsage<EnterpriseNodeOptions>(Console.WindowWidth);
                        Console.WriteLine(usage);
                        return;
                    }
                }
                else
                {
                    node = context.Enterprise.ResolveNodeName(arguments.Node);
                }

                switch (arguments.Command.ToLowerInvariant())
                {
                    case "tree":
                    {
                        context.PrintNodeTree(node, "", arguments.Verbose, true);
                        return;
                    }

                    case "update":
                        if (!string.IsNullOrEmpty(arguments.Name))
                        {
                            node.DisplayName = arguments.Name;
                        }
                        await context.Enterprise.UpdateNode(node, parentNode);
                        Console.WriteLine($"Node \"{node.DisplayName}\" updated.");
                        if (arguments.RestrictVisibility)
                        {
                            await context.Enterprise.SetRestrictVisibility(node.Id);
                            Console.WriteLine($"Node Isolation: {(node.RestrictVisibility ? "ON" : "OFF")}");
                        }

                        break;

                    case "delete":
                        await context.Enterprise.DeleteNode(node.Id);
                        Console.WriteLine($"Node \"{node.DisplayName}\" deleted.");
                        break;

                    default:
                        Console.WriteLine($"Unsupported command \"{arguments.Command}\": available commands \"tree\", \"add\", \"update\", \"delete\"");
                        break;
                }
            }
            await context.Enterprise.PopulateEnterprise();
        }

        public static async Task EnterpriseUserCommand(this IEnterpriseContext context, EnterpriseUserOptions arguments)
        {
            if (string.IsNullOrEmpty(arguments.Command)) arguments.Command = "list";

            if (arguments.Force)
            {
                await context.Enterprise.PopulateEnterprise();
            }

            if (string.Compare(arguments.Command, "list", StringComparison.InvariantCultureIgnoreCase) == 0)
            {
                var users = context.Enterprise.Users
                    .Where(x =>
                    {
                        if (string.IsNullOrEmpty(arguments.Name)) return true;
                        var m = Regex.Match(x.Email, arguments.Name, RegexOptions.IgnoreCase);
                        if (m.Success) return true;
                        if (!string.IsNullOrEmpty(x.DisplayName))
                        {
                            m = Regex.Match(x.DisplayName, arguments.Name, RegexOptions.IgnoreCase);
                            if (m.Success) return true;
                        }

                        var status = x.UserStatus.ToString();
                        m = Regex.Match(status, arguments.Name, RegexOptions.IgnoreCase);
                        return m.Success;
                    })
                    .ToArray();

                var tab = new Tabulate(4)
                {
                    DumpRowNo = true
                };
                tab.AddHeader("Email", "Display Name", "Status", "Teams");
                foreach (var user in users)
                {
                    tab.AddRow(user.Email, user.DisplayName, user.UserStatus.ToString(), user.Teams.Count);
                }

                tab.Sort(1);
                tab.Dump();
            }
            else if (string.Compare(arguments.Command, "view", StringComparison.InvariantCultureIgnoreCase) == 0)
            {
                var user = context.Enterprise.Users
                    .FirstOrDefault(x =>
                    {
                        if (string.Compare(x.DisplayName, arguments.Name, StringComparison.CurrentCultureIgnoreCase) == 0) return true;
                        if (x.Email.StartsWith(arguments.Name, StringComparison.InvariantCulture)) return true;
                        return false;
                    });
                if (user == null)
                {
                    Console.WriteLine($"Enterprise user \"{arguments.Name}\" not found");
                    return;
                }
                var tab = new Tabulate(2)
                {
                    DumpRowNo = false
                };
                tab.SetColumnRightAlign(0, true);
                tab.AddRow(" User Email:", user.Email);
                tab.AddRow(" User Name:", user.DisplayName);
                tab.AddRow(" User ID:", user.Id.ToString());
                tab.AddRow(" Status:", user.UserStatus.ToString());

                var teams = user.Teams
                    .Select(x => context.Enterprise.TryGetTeam(x, out var team) ? team.Name : null)
                    .Where(x => !string.IsNullOrEmpty(x))
                    .ToArray();
                Array.Sort(teams);
                tab.AddRow(" Teams:", teams.Length > 0 ? teams[0] : "");
                for (var i = 1; i < teams.Length; i++)
                {
                    tab.AddRow("", teams[i]);
                }

                if (context.Enterprise.TryGetNode(user.ParentNodeId, out var node))
                {
                    var nodes = context.GetNodePath(node).ToArray();
                    Array.Reverse(nodes);
                    tab.AddRow(" Node:", string.Join(" -> ", nodes));
                }

                tab.Dump();
            }
            else if (string.Compare(arguments.Command, "team-add", StringComparison.InvariantCultureIgnoreCase) == 0 || string.Compare(arguments.Command, "team-remove", StringComparison.InvariantCultureIgnoreCase) == 0)
            {
                var user = context.Enterprise.Users
                    .FirstOrDefault(x =>
                    {
                        if (string.Compare(x.DisplayName, arguments.Name, StringComparison.CurrentCultureIgnoreCase) == 0) return true;
                        if (string.Compare(x.Email, arguments.Name, StringComparison.InvariantCulture) == 0) return true;
                        return false;
                    });
                if (user == null)
                {
                    Console.WriteLine($"Enterprise user \"{arguments.Name}\" not found");
                    return;
                }

                if (string.IsNullOrEmpty(arguments.Team))
                {
                    Console.WriteLine("Team name parameter is mandatory.");
                    return;
                }

                var team = context.Enterprise.Teams
                    .FirstOrDefault(x =>
                    {
                        if (string.CompareOrdinal(x.Uid, arguments.Team) == 0) return true;
                        return string.Compare(x.Name, arguments.Team, StringComparison.CurrentCultureIgnoreCase) == 0;
                    });
                if (team == null)
                {
                    Console.WriteLine($"Team {arguments.Team} cannot be found.");
                    return;
                }

                if (string.Compare(arguments.Command, "team-add", StringComparison.InvariantCultureIgnoreCase) == 0)
                {
                    await context.Enterprise.AddUsersToTeams(new[] { user.Email }, new[] { team.Uid }, Console.WriteLine);
                }
                else
                {
                    await context.Enterprise.RemoveUsersFromTeams(new[] { user.Email }, new[] { team.Uid }, Console.WriteLine);
                }
            }
            else
            {
                Console.WriteLine($"Unsupported command \"{arguments.Command}\". Commands are \"list\", \"view\", \"team-add\", \"team-remove\"");
            }
        }

        public static async Task EnterpriseTeamCommand(this IEnterpriseContext context, EnterpriseTeamOptions arguments)
        {
            if (arguments.Force)
            {
                await context.Enterprise.PopulateEnterprise();
            }

            if (string.IsNullOrEmpty(arguments.Command)) arguments.Command = "list";
            if (string.CompareOrdinal(arguments.Command, "list") == 0)
            {
                var teams = context.Enterprise.Teams
                    .Where(x =>
                    {
                        if (string.IsNullOrEmpty(arguments.Name)) return true;
                        if (arguments.Name == x.Uid) return true;
                        var m = Regex.Match(x.Name, arguments.Name, RegexOptions.IgnoreCase);
                        return m.Success;
                    })
                    .ToArray();
                var tab = new Tabulate(7)
                {
                    DumpRowNo = true
                };
                tab.AddHeader("Team Name", "Team UID", "Node Name", "Restrict Edit", "Restrict Share", "Restrict View", "Users");
                foreach (var team in teams)
                {
                    EnterpriseNode node = null;
                    if (team.ParentNodeId > 0)
                    {
                        context.Enterprise.TryGetNode(team.ParentNodeId, out node);
                    }
                    else
                    {
                        node = context.Enterprise.RootNode;
                    }

                    tab.AddRow(team.Name,
                        team.Uid,
                        node != null ? node.DisplayName : "",
                        team.RestrictEdit ? "X" : "-",
                        team.RestrictSharing ? "X" : "-",
                        team.RestrictView ? "X" : "-",
                        team.Users.Count.ToString());
                }

                tab.Sort(1);
                tab.Dump();
            }
            else
            {
                var team = context.Enterprise.Teams
                    .FirstOrDefault(x =>
                    {
                        if (string.IsNullOrEmpty(arguments.Name)) return true;
                        if (arguments.Name == x.Uid) return true;
                        return string.Compare(x.Name, arguments.Name, StringComparison.CurrentCultureIgnoreCase) == 0;
                    });
                if (string.CompareOrdinal(arguments.Command, "delete") == 0)
                {
                    if (team == null)
                    {
                        Console.WriteLine($"Team \"{arguments.Name}\" not found");
                        return;
                    }

                    await context.Enterprise.DeleteTeam(team.Uid);
                }
                else if (string.CompareOrdinal(arguments.Command, "view") == 0)
                {
                    if (team == null)
                    {
                        Console.WriteLine($"Team \"{arguments.Name}\" not found");
                        return;
                    }

                    var tab = new Tabulate(2)
                    {
                        DumpRowNo = false
                    };
                    tab.SetColumnRightAlign(0, true);
                    tab.AddRow(" Team Name:", team.Name);
                    tab.AddRow(" Team UID:", team.Uid);
                    tab.AddRow(" Restrict Edit:", team.RestrictEdit ? "Yes" : "No");
                    tab.AddRow(" Restrict Share:", team.RestrictSharing ? "Yes" : "No");
                    tab.AddRow(" Restrict View:", team.RestrictView ? "Yes" : "No");
                    var users = team.Users
                        .Select(x => context.Enterprise.TryGetUserById(x, out var user) ? user.Email : null)
                        .Where(x => !string.IsNullOrEmpty(x))
                        .ToArray();
                    Array.Sort(users);
                    tab.AddRow(" Users:", users.Length > 0 ? users[0] : "");
                    for (var i = 1; i < users.Length; i++)
                    {
                        tab.AddRow("", users[i]);
                    }

                    if (context.Enterprise.TryGetNode(team.ParentNodeId, out var node))
                    {
                        var nodes = context.GetNodePath(node).ToArray();
                        Array.Reverse(nodes);
                        tab.AddRow(" Node:", string.Join(" -> ", nodes));
                    }

                    tab.Dump();
                }
                else if (string.CompareOrdinal(arguments.Command, "update") == 0 || string.CompareOrdinal(arguments.Command, "add") == 0)
                {
                    if (team == null)
                    {
                        if (string.CompareOrdinal(arguments.Command, "update") == 0 ||
                            string.CompareOrdinal(arguments.Command, "view") == 0)
                        {
                            Console.WriteLine($"Team \"{arguments.Name}\" not found");
                            return;
                        }

                        team = new EnterpriseTeam
                        {
                            ParentNodeId = context.Enterprise.RootNode.Id
                        };
                    }
                    else
                    {
                        if (string.CompareOrdinal(arguments.Command, "add") == 0)
                        {
                            Console.WriteLine($"Team with name \"{arguments.Name}\" already exists.\nDo you want to create a new one? Yes/No");
                            var answer = await Program.GetInputManager().ReadLine();
                            if (string.Compare("y", answer, StringComparison.InvariantCultureIgnoreCase) == 0)
                            {
                                answer = "yes";
                            }

                            if (string.Compare(answer, "yes", StringComparison.InvariantCultureIgnoreCase) != 0)
                            {
                                return;
                            }
                        }
                    }

                    team.Name = arguments.Name;
                    if (CliCommands.ParseBoolOption(arguments.RestrictEdit, out var b))
                    {
                        team.RestrictEdit = b;
                    }

                    if (CliCommands.ParseBoolOption(arguments.RestrictShare, out b))
                    {
                        team.RestrictSharing = b;
                    }

                    if (CliCommands.ParseBoolOption(arguments.RestrictView, out b))
                    {
                        team.RestrictView = b;
                    }

                    if (!string.IsNullOrEmpty(arguments.Node))
                    {
                        long? asId = null;
                        if (arguments.Node.All(char.IsDigit))
                        {
                            if (long.TryParse(arguments.Node, out var l))
                            {
                                asId = l;
                            }
                        }

                        var node = context.Enterprise.Nodes
                            .FirstOrDefault(x =>
                            {
                                if (asId.HasValue && asId.Value == x.Id) return true;
                                return string.Compare(x.DisplayName, arguments.Node, StringComparison.CurrentCultureIgnoreCase) == 0;
                            });
                        if (node != null)
                        {
                            team.ParentNodeId = node.Id;
                        }
                    }

                    await context.Enterprise.UpdateTeam(team);
                }
                else
                {
                    Console.WriteLine($"Unsupported command \"{arguments.Command}\". Valid commands are  \"list\", \"view\", \"add\", \"delete\", \"update\"");
                }
            }
        }

        public static async Task EnterpriseDeviceCommand(this IEnterpriseContext context, EnterpriseDeviceOptions arguments)
        {
            if (arguments.AutoApprove.HasValue)
            {
                context.AutoApproveAdminRequests = arguments.AutoApprove.Value;
                Console.WriteLine($"Automatic Admin Device Approval is {(context.AutoApproveAdminRequests ? "ON" : "OFF")}");
            }

            if (string.IsNullOrEmpty(arguments.Command)) arguments.Command = "list";

            if (arguments.Force)
            {
                await context.Enterprise.PopulateEnterprise();
            }

            var approvals = context.Enterprise.GetDeviceApprovalRequests();

            if (approvals.Length == 0)
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
                    tab.AddHeader("Email", "Device ID", "Device Name", "Client Version");
                    foreach (var device in approvals)
                    {
                        if (!context.Enterprise.TryGetUserById(device.EnterpriseUserId, out var user)) continue;

                        var deiceToken = device.EncryptedDeviceToken.ToByteArray();
                        tab.AddRow(user.Email, deiceToken.TokenToString(), device.DeviceName, device.ClientVersion);
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
                        var devices = approvals
                            .Where(x =>
                            {
                                if (arguments.Match == "all") return true;
                                var deviceToken = x.EncryptedDeviceToken.ToByteArray();
                                var deviceId = deviceToken.TokenToString();
                                if (deviceId.StartsWith(arguments.Match)) return true;

                                if (!context.Enterprise.TryGetUserById(x.EnterpriseUserId, out var user)) return false;
                                return user.Email == arguments.Match;

                            }).ToArray();

                        if (devices.Length > 0)
                        {
                            if (cmd == "approve")
                            {
                                await context.ApproveAdminDeviceRequests(devices);
                            }
                            else
                            {
                                await context.DenyAdminDeviceRequests(devices);
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

        internal static async Task ApproveAdminDeviceRequests(this IEnterpriseContext context, DeviceRequestForAdminApproval[] devices)
        {
            var dataKeys = new Dictionary<long, byte[]>();
            foreach (var device in devices)
            {
                if (!dataKeys.ContainsKey(device.EnterpriseUserId))
                {
                    dataKeys[device.EnterpriseUserId] = context.UserDataKeys.TryGetValue(device.EnterpriseUserId, out var dk) ? dk : null;
                }
            }

            var toLoad = dataKeys.Where(x => x.Value == null).Select(x => x.Key).ToArray();
            if (toLoad.Any() && context.EnterprisePrivateKey != null)
            {
                var dataKeyRq = new UserDataKeyRequest();
                dataKeyRq.EnterpriseUserId.AddRange(toLoad);
                var dataKeyRs = await context.Enterprise.Auth.ExecuteAuthRest<UserDataKeyRequest, EnterpriseUserDataKeys>("enterprise/get_enterprise_user_data_key", dataKeyRq);
                foreach (var key in dataKeyRs.Keys)
                {
                    if (key.UserEncryptedDataKey.IsEmpty) continue;
                    try
                    {
                        var userDataKey = CryptoUtils.DecryptEc(key.UserEncryptedDataKey.ToByteArray(), context.EnterprisePrivateKey);
                        context.UserDataKeys[key.EnterpriseUserId] = userDataKey;
                        dataKeys[key.EnterpriseUserId] = userDataKey;
                    }
                    catch (Exception e)
                    {
                        Debug.WriteLine($"Data key decrypt error: {e.Message}");
                    }
                }
            }

            var rq = new ApproveUserDevicesRequest();
            foreach (var device in devices)
            {
                if (!dataKeys.TryGetValue(device.EnterpriseUserId, out var dk)) continue;
                if (device.DevicePublicKey.IsEmpty) continue;
                var devicePublicKey = CryptoUtils.LoadPublicEcKey(device.DevicePublicKey.ToByteArray());

                try
                {
                    var deviceRq = new ApproveUserDeviceRequest
                    {
                        EnterpriseUserId = device.EnterpriseUserId,
                        EncryptedDeviceToken = ByteString.CopyFrom(device.EncryptedDeviceToken.ToByteArray()),
                        EncryptedDeviceDataKey = ByteString.CopyFrom(CryptoUtils.EncryptEc(dk, devicePublicKey))
                    };
                    rq.DeviceRequests.Add(deviceRq);
                }
                catch (Exception e)
                {
                    Debug.WriteLine(e.Message);
                }
            }
            if (rq.DeviceRequests.Count == 0)
            {
                Console.WriteLine("No device to approve/deny");
            }
            else
            {
                var rs = await
                    context.Enterprise.Auth.ExecuteAuthRest<ApproveUserDevicesRequest, ApproveUserDevicesResponse>("enterprise/approve_user_devices", rq);
                if (rs.DeviceResponses?.Count > 0)
                {
                    foreach (var approveRs in rs.DeviceResponses)
                    {
                        if (!approveRs.Failed) continue;

                        if (context.Enterprise.TryGetUserById(approveRs.EnterpriseUserId, out var user))
                        {
                            Console.WriteLine($"Failed to approve {user.Email}: {approveRs.Message}");
                        }
                    }
                }
                await context.Enterprise.PopulateEnterprise();
            }
        }

        internal static async Task DenyAdminDeviceRequests(this IEnterpriseContext context, DeviceRequestForAdminApproval[] devices)
        {
            var rq = new ApproveUserDevicesRequest();
            foreach (var device in devices)
            {
                var deviceRq = new ApproveUserDeviceRequest
                {
                    EnterpriseUserId = device.EnterpriseUserId,
                    EncryptedDeviceToken = ByteString.CopyFrom(device.EncryptedDeviceToken.ToByteArray()),
                    DenyApproval = true,
                };
                rq.DeviceRequests.Add(deviceRq);
                if (rq.DeviceRequests.Count == 0)
                {
                    Console.WriteLine("No device to approve/deny");
                }
                else
                {
                    var rs = await context.Enterprise.Auth
                        .ExecuteAuthRest<ApproveUserDevicesRequest, ApproveUserDevicesResponse>("enterprise/approve_user_devices", rq);
                    if (rs.DeviceResponses?.Count > 0)
                    {
                        foreach (var approveRs in rs.DeviceResponses)
                        {
                            if (!approveRs.Failed) continue;
                            if (context.Enterprise.TryGetUserById(approveRs.EnterpriseUserId, out var user))
                            {
                                Console.WriteLine($"Failed to approve {user.Email}: {approveRs.Message}");
                            }
                        }
                    }

                    await context.Enterprise.PopulateEnterprise();
                }
            }
        }

        internal static async Task EnterpriseRegisterEcKey(this IEnterpriseContext context, CliCommands cli)
        {
            if (context.Enterprise.TreeKey == null)
            {
                Console.WriteLine("Cannot get tree key");
                return;
            }

            CryptoUtils.GenerateEcKey(out var privateKey, out var publicKey);
            var exportedPublicKey = CryptoUtils.UnloadEcPublicKey(publicKey);
            var exportedPrivateKey = CryptoUtils.UnloadEcPrivateKey(privateKey);
            var encryptedPrivateKey = CryptoUtils.EncryptAesV2(exportedPrivateKey, context.Enterprise.TreeKey);
            var request = new EnterpriseKeyPairRequest
            {
                KeyType = KeyType.Ecc,
                EnterprisePublicKey = ByteString.CopyFrom(exportedPublicKey),
                EncryptedEnterprisePrivateKey = ByteString.CopyFrom(encryptedPrivateKey),
            };

            await context.Enterprise.Auth.ExecuteAuthRest("enterprise/set_enterprise_key_pair", request);
            cli.Commands.Remove("enterprise-add-key");
            context.Enterprise.EcPrivateKey = exportedPrivateKey;
            context.EnterprisePrivateKey = privateKey;
        }

        //private static string IN_PATTERN = @"\s*in\s*\(\s*(.*)\s*\)";
        private static string BETWEEN_PATTERN = @"\s*between\s+(\S*)\s+and\s+(.*)";

        private static bool TryParseUtcDate(string text, out long epochInSec)
        {
            if (long.TryParse(text, out epochInSec))
            {
                var nowInCentis = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() / 10;
                if (epochInSec > nowInCentis)
                {
                    epochInSec /= 1000;
                    return true;
                }
            }

            const DateTimeStyles dtStyle = DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal;
            if (DateTimeOffset.TryParse(text, CultureInfo.InvariantCulture, dtStyle, out var dt))
            {
                epochInSec = dt.ToUnixTimeSeconds();
                return true;
            }

            return false;
        }

        private static object ParseDateCreatedFilter(string text)
        {
            if (string.IsNullOrEmpty(text)) return null;

            switch (text.ToLowerInvariant())
            {
                case "today":
                case "yesterday":
                case "last_7_days":
                case "last_30_days":
                case "month_to_date":
                case "last_month":
                case "year_to_date":
                case "last_year":
                    return text;
            }

            if (text.StartsWith(">") || text.StartsWith("<"))
            {
                var isGreater = text[0] == '>';
                text = text.Substring(1);
                var hasEqual = text.StartsWith("=");
                if (hasEqual)
                {
                    text = text.Substring(1);
                }

                if (TryParseUtcDate(text, out var dt))
                {
                    var filter = new CreatedFilter();
                    if (isGreater)
                    {
                        filter.Min = dt;
                        filter.ExcludeMin = !hasEqual;
                    }
                    else
                    {
                        filter.Max = dt;
                        filter.ExcludeMax = !hasEqual;
                    }
                }
            }
            else
            {
                var match = Regex.Match(text, BETWEEN_PATTERN, RegexOptions.IgnoreCase);
                if (match.Success)
                {
                    if (TryParseUtcDate(match.Groups[1].Value, out var from) && TryParseUtcDate(match.Groups[2].Value, out var to))
                    {
                        return new CreatedFilter
                        {
                            Min = from,
                            Max = to,
                            ExcludeMin = false,
                            ExcludeMax = true,
                        };
                    }
                }
            }


            return null;
        }

        private static string ParameterPattern = @"\${(\w+)}";

        internal static async Task RunAuditEventsReport(this IEnterpriseContext context, AuditReportOptions options)
        {
            if (context.AuditEvents == null)
            {
                var auditEvents = await context.Enterprise.Auth.GetAvailableEvents();
                lock (context)
                {
                    context.AuditEvents = new ConcurrentDictionary<string, AuditEventType>();
                    foreach (var evt in auditEvents)
                    {
                        context.AuditEvents[evt.Name] = evt;
                    }
                }
            }

            var filter = new ReportFilter();
            if (!string.IsNullOrEmpty(options.Created))
            {
                filter.Created = ParseDateCreatedFilter(options.Created);
            }

            if (options.EventType != null && options.EventType.Any())
            {
                filter.EventTypes = options.EventType.ToArray();
            }

            if (!string.IsNullOrEmpty(options.Username))
            {
                filter.Username = options.Username;
            }

            if (!string.IsNullOrEmpty(options.RecordUid))
            {
                filter.RecordUid = options.RecordUid;
            }

            if (!string.IsNullOrEmpty(options.SharedFolderUid))
            {
                filter.SharedFolderUid = options.SharedFolderUid;
            }

            var rq = new GetAuditEventReportsCommand
            {
                Filter = filter,
                Limit = options.Limit,
            };

            var rs = await context.Enterprise.Auth.ExecuteAuthCommand<GetAuditEventReportsCommand, GetAuditEventReportsResponse>(rq);

            var tab = new Tabulate(4) {DumpRowNo = true};
            tab.AddHeader("Created", "Username", "Event", "Message");
            tab.MaxColumnWidth = 100;
            foreach (var evt in rs.Events)
            {
                if (!evt.TryGetValue("audit_event_type", out var v)) continue;
                var eventName = v.ToString();
                if (!context.AuditEvents.TryGetValue(eventName, out var eventType)) continue;

                var message = eventType.SyslogMessage;
                do
                {
                    var match = Regex.Match(message, ParameterPattern);
                    if (!match.Success) break;
                    if (match.Groups.Count != 2) break;
                    var parameter = match.Groups[1].Value;
                    var value = "";
                    if (evt.TryGetValue(parameter, out v))
                    {
                        value = v.ToString();
                    }

                    message = message.Remove(match.Groups[0].Index, match.Groups[0].Length);
                    message = message.Insert(match.Groups[0].Index, value);
                } while (true);
                var created = "";
                if (evt.TryGetValue("created", out v))
                {
                    created = v.ToString();
                    if (long.TryParse(created, out var epoch))
                    {
                        created = DateTimeOffset.FromUnixTimeSeconds(epoch).ToString("G");
                    }
                }
                var username = "";
                if (evt.TryGetValue("username", out v))
                {
                    username = v.ToString();
                }
                tab.AddRow(created, username, eventName, message);
            }
            tab.Dump();
        }
    }

    internal class McEnterpriseContext : BackStateContext, IEnterpriseContext
    {
        public McEnterpriseContext(ManagedCompanyAuth auth)
        {
            if (auth.AuthContext.IsEnterpriseAdmin)
            {
                Enterprise = new EnterpriseData(auth, auth.TreeKey);
                Task.Run(async () =>
                {
                    try
                    {
                        await Enterprise.PopulateEnterprise();
                        this.AppendEnterpriseCommands(this);
                    }
                    catch (Exception e)
                    {
                        Debug.WriteLine(e);
                    }
                });
            }
        }

        public EnterpriseData Enterprise { get; set; }
        public DeviceRequestForAdminApproval[] DeviceForAdminApprovals { get; set; }
        public bool AutoApproveAdminRequests { get; set; }
        public ECPrivateKeyParameters EnterprisePrivateKey { get; set; }
        public Dictionary<long, byte[]> UserDataKeys { get; } = new Dictionary<long, byte[]>();
        public IDictionary<string, AuditEventType> AuditEvents { get; set; }


        public override string GetPrompt()
        {
            return "Managed Company";
        }
    }

    public partial class ConnectedContext: IEnterpriseContext
    {
        public EnterpriseData Enterprise { get; set; }
        public bool AutoApproveAdminRequests { get; set; }
        public ECPrivateKeyParameters EnterprisePrivateKey { get; set; }
        public Dictionary<long, byte[]> UserDataKeys { get; } = new Dictionary<long, byte[]>();
        public IDictionary<string, AuditEventType> AuditEvents { get; set; }

        private void CheckIfEnterpriseAdmin()
        {
            if (_auth.AuthContext.IsEnterpriseAdmin)
            {
                Enterprise = new EnterpriseData(_auth);

                _auth.PushNotifications?.RegisterCallback(EnterpriseNotificationCallback);
                Task.Run(async () =>
                {
                    try
                    {
                        await Enterprise.PopulateEnterprise();

                        this.AppendEnterpriseCommands(this);

                        if (!string.IsNullOrEmpty(Enterprise.EnterpriseLicense?.LicenseStatus) && Enterprise.EnterpriseLicense.LicenseStatus.StartsWith("msp"))
                        {
                            Commands.Add("mc-list",
                                new SimpleCommand
                                {
                                    Order = 70,
                                    Description = "List managed companies",
                                    Action = ListManagedCompanies,
                                });
                            Commands.Add("mc-login",
                                new ParsableCommand<EnterpriseMcLoginOptions>
                                {
                                    Order = 71,
                                    Description = "Login to managed company",
                                    Action = LoginToManagedCompany,
                                });
                        }
                    }
                    catch (Exception e)
                    {
                        Debug.WriteLine(e);
                    }
                });
            }
        }

        private bool EnterpriseNotificationCallback(NotificationEvent evt)
        {
            if (evt.Event == "request_device_admin_approval")
            {
                if (AutoApproveAdminRequests)
                {
                    Task.Run(async () =>
                    {
                        await Enterprise.PopulateEnterprise();
                        if (!Enterprise.TryGetUserByEmail(evt.Email, out var user)) return;

                        var devices = Enterprise.GetDeviceApprovalRequests()
                            .Where(x => x.EnterpriseUserId == user.Id)
                            .ToArray();
                        await this.ApproveAdminDeviceRequests(devices);
                        Console.WriteLine($"Auto approved {evt.Email} at IP Address {evt.IPAddress}.");
                    });
                }
                else
                {
                    Console.WriteLine($"\n{evt.Email} requested Device Approval\nIP Address: {evt.IPAddress}\nDevice Name: {evt.DeviceName}");
                }
            }

            return false;
        }

        private async Task LoginToManagedCompany(EnterpriseMcLoginOptions options)
        {
            var mcAuth = new ManagedCompanyAuth();
            await mcAuth.LoginToManagedCompany(Enterprise, options.CompanyId);
            NextState = new McEnterpriseContext(mcAuth);
        }

        private Task ListManagedCompanies(string _)
        {
            var tab = new Tabulate(6);
            tab.AddHeader("Company Name", "Company ID", "License", "# Seats", "# Users", "Paused");
            foreach (var mc in Enterprise.ManagedCompanies)
            {
                tab.AddRow(mc.EnterpriseName, mc.EnterpriseId, mc.ProductId, 
                    mc.NumberOfSeats, mc.NumberOfUsers, mc.IsExpired ? "Yes" : "");
            }
            tab.Sort(0);
            tab.DumpRowNo = true;
            tab.Dump();
            return Task.CompletedTask;
        }
    }
    class EnterpriseGenericOptions
    {
        [Option('f', "force", Required = false, Default = false, HelpText = "force reload enterprise data")]
        public bool Force { get; set; }
    }


    class EnterpriseNodeOptions : EnterpriseGenericOptions
    {
        [Value(0, Required = false, HelpText = "enterprise-user command: \"--command=[tree, add, update, delete]\" <Node name or ID>")]
        public string Node { get; set; }

        [Option("command", Required = false, HelpText = "[tree, add, update, delete]")]
        public string Command { get; set; }

        [Option("parent", Required = false, HelpText = "parent node name or ID")]
        public string Parent { get; set; }

        [Option("name", Required = false, HelpText = "new node display name")]
        public string Name { get; set; }

        [Option('v', "verbose", Required = false, HelpText = "verbose output")]
        public bool Verbose { get; set; }

        [Option("toggle-isolated", Required = false, HelpText = "toggle node isolation flag")]
        public bool RestrictVisibility { get; set; }
    }

    class EnterpriseUserOptions : EnterpriseGenericOptions
    {
        [Option("team", Required = false, HelpText = "team name or UID")]
        public string Team { get; set; }

        [Value(0, Required = false, HelpText = "enterprise-user command: \"list\", \"view\", \"team-add\", \"team-remove\"")]
        public string Command { get; set; }

        [Value(1, Required = false, HelpText = "enterprise user email, ID, list match")]
        public string Name { get; set; }
    }

    class EnterpriseTeamOptions : EnterpriseGenericOptions
    {
        [Option("node", Required = false, HelpText = "node name or ID. \"add\", \"delete\", \"update\"")]
        public string Node { get; set; }

        [Option("restrict-edit", Required = false, HelpText = "ON | OFF:  disable record edits. \"add\", \"update\"")]
        public string RestrictEdit { get; set; }

        [Option("restrict-share", Required = false, HelpText = "ON | OFF:  disable record re-shares. \"add\", \"update\"")]
        public string RestrictShare { get; set; }

        [Option("restrict-view", Required = false, HelpText = "ON | OFF:  disable view/copy passwords. \"add\", \"update\"")]
        public string RestrictView { get; set; }

        [Value(0, Required = false, HelpText = "enterprise-team command: \"list\", \"view\", \"add\", \"delete\", \"update\"")]
        public string Command { get; set; }

        [Value(1, Required = false, HelpText = "enterprise team Name, UID, list match")]
        public string Name { get; set; }
    }

    class EnterpriseDeviceOptions : EnterpriseGenericOptions
    {
        [Option("auto-approve", Required = false, Default = null, HelpText = "auto approve devices")]
        public bool? AutoApprove { get; set; }

        [Value(0, Required = false, HelpText = "command: \"list\", \"approve\", \"decline\"")]
        public string Command { get; set; }

        [Value(1, Required = false, HelpText = "device approval request: \"all\", email, or device id")]
        public string Match { get; set; }
    }

    class AuditReportOptions 
    {
        [Option("limit", Required = false, Default = 100, HelpText = "maximum number of returned events")]
        public int Limit { get; set; }

        [Option("created", Required = false, Default = null, HelpText = "event creation datetime")]
        public string Created { get; set; }

        [Option("event-type", Required = false, Default = null, Separator = ',', HelpText = "audit event type")]
        public IEnumerable<string> EventType { get; set; }

        [Option("username", Required = false, Default = null, HelpText = "username of event originator")]
        public string Username { get; set; }

        [Option("to_username", Required = false, Default = null, HelpText = "username of event target")]
        public string ToUsername { get; set; }

        [Option("record_uid", Required = false, Default = null, HelpText = "record UID")]
        public string RecordUid { get; set; }

        [Option("shared-folder-uid", Required = false, Default = null, HelpText = "shared folder UID")]
        public string SharedFolderUid { get; set; }
    }

    class EnterpriseMcLoginOptions : EnterpriseGenericOptions
    {
        [Value(0, Required = true, HelpText = "mc-login <mc-company-id>")]
        public int CompanyId { get; set; }
    }
    
}
