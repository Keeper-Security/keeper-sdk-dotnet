﻿using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Authentication;
using Cli;
using Commander.Enterprise;
using CommandLine;
using Enterprise;
using Google.Protobuf;
using KeeperSecurity.Authentication;
using KeeperSecurity.Commands;
using KeeperSecurity.Enterprise;
using KeeperSecurity.Enterprise.AuditLogCommands;
using KeeperSecurity.Utils;
using Org.BouncyCastle.Crypto.Parameters;
using static KeeperSecurity.Enterprise.AuditLogExtensions;
using EnterpriseData = KeeperSecurity.Enterprise.EnterpriseData;

namespace Commander
{
    internal interface IEnterpriseContext
    {
        EnterpriseLoader Enterprise { get; }
        EnterpriseData EnterpriseData { get; }
        RoleData RoleManagement { get; }
        QueuedTeamDataManagement QueuedTeamManagement { get; }
        UserAliasData UserAliasData { get; }

        DeviceApprovalData DeviceApproval { get; }

        bool AutoApproveAdminRequests { get; set; }
        Dictionary<long, byte[]> UserDataKeys { get; }

        ECPrivateKeyParameters EnterprisePrivateKey { get; set; }

        IDictionary<string, AuditEventType> AuditEvents { get; set; }
    }

    internal static class EnterpriseExtensions
    {
        internal static void AppendEnterpriseCommands(this IEnterpriseContext context, Cli.CliCommands cli)
        {
            cli.Commands.Add("enterprise-get-data",
                new Cli.SimpleCommand
                {
                    Order = 60,
                    Description = "Retrieve enterprise data",
                    Action = async _ => { await context.Enterprise.Load(); },
                });

            cli.Commands.Add("enterprise-node",
                new ParseableCommand<EnterpriseNodeOptions>
                {
                    Order = 61,
                    Description = "Manage Enterprise Nodes",
                    Action = async options => { await context.EnterpriseData.EnterpriseNodeCommand(options); },
                });

            cli.Commands.Add("enterprise-user",
                new ParseableCommand<EnterpriseUserOptions>
                {
                    Order = 62,
                    Description = "Manage Enterprise Users",
                    Action = async options => { await context.EnterpriseUserCommand(options); },
                });

            cli.Commands.Add("enterprise-team",
                new ParseableCommand<EnterpriseTeamOptions>
                {
                    Order = 63,
                    Description = "Manage Enterprise Teams",
                    Action = async options => { await context.EnterpriseTeamCommand(options); },
                });

            cli.Commands.Add("enterprise-role",
                new ParseableCommand<EnterpriseRoleOptions>
                {
                    Order = 64,
                    Description = "Manage Enterprise Roles",
                    Action = async options => { await context.RoleManagement.EnterpriseRoleCommand(context.EnterpriseData, options); },
                });

            cli.Commands.Add("enterprise-device",
                new ParseableCommand<EnterpriseDeviceOptions>
                {
                    Order = 65,
                    Description = "Manage User Devices",
                    Action = async options => { await context.EnterpriseDeviceCommand(options); },
                });
            cli.Commands.Add("transfer-user",
                new ParseableCommand<EnterpriseTransferUserOptions>
                {
                    Order = 66,
                    Description = "Transfer User Account",
                    Action = async options => { await context.TransferUserCommand(options); },
                });

            cli.Commands.Add("extend-account-share-expiration",
                new ParseableCommand<EnterpriseUsersOptions>
                {
                    Order = 67,
                    Description = "Extend Account Share Expiration",
                    Action = async options => { await context.ExtendAccountShareExpirationCommand(options); },
                });
            cli.Commands.Add("audit-report",
                new ParseableCommand<AuditReportOptions>
                {
                    Order = 70,
                    Description = "Run an audit trail report.",
                    Action = async options => { await context.RunAuditEventsReport(options); },
                });


            cli.CommandAliases["eget"] = "enterprise-get-data";
            cli.CommandAliases["en"] = "enterprise-node";
            cli.CommandAliases["eu"] = "enterprise-user";
            cli.CommandAliases["et"] = "enterprise-team";
            cli.CommandAliases["er"] = "enterprise-role";
            cli.CommandAliases["ed"] = "enterprise-device";


            if (context.Enterprise.EcPrivateKey == null)
            {
                cli.Commands.Add("enterprise-add-key",
                    new Cli.SimpleCommand
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

        public static IEnumerable<string> GetNodePath(this EnterpriseData enterpriseData, EnterpriseNode node)
        {
            while (true)
            {
                yield return node.DisplayName;
                if (node.Id <= 0) yield break;
                if (!enterpriseData.TryGetNode(node.ParentNodeId, out var parent)) yield break;
                node = parent;
            }
        }

        public static void PrintNodeTree(this EnterpriseData enterpriseData, EnterpriseNode eNode, string indent, bool verbose, bool last)
        {
            var isRoot = string.IsNullOrEmpty(indent);
            Console.WriteLine(indent + (isRoot ? "" : "+-- ") + eNode.DisplayName + (verbose ? $" ({eNode.Id})" : "") + (verbose && eNode.RestrictVisibility ? " [Isolated]" : ""));
            indent += isRoot ? " " : (last ? "    " : "|   ");
            var subNodes = eNode.Subnodes
                .Select(x => enterpriseData.TryGetNode(x, out var node) ? node : null)
                .Where(x => x != null)
                .OrderBy(x => x.DisplayName ?? "")
                .ToArray();
            for (var i = 0; i < subNodes.Length; i++)
            {
                enterpriseData.PrintNodeTree(subNodes[i], indent, verbose, i == subNodes.Length - 1);
            }
        }

        internal static EnterpriseNode ResolveNodeName(this EnterpriseData enterpriseData, string nodeName)
        {
            if (nodeName.All(x => char.IsDigit(x)))
            {
                if (long.TryParse(nodeName, out var nodeId))
                {
                    if (enterpriseData.TryGetNode(nodeId, out var node))
                    {
                        return node;
                    }
                }
            }

            var nodes = enterpriseData.Nodes.Where(x => string.Equals(nodeName, x.DisplayName, StringComparison.InvariantCultureIgnoreCase)).ToArray();
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

        public static async Task EnterpriseNodeCommand(this EnterpriseData enterpriseData, EnterpriseNodeOptions arguments)
        {
            if (string.IsNullOrEmpty(arguments.Command)) arguments.Command = "tree";

            if (arguments.Force)
            {
                await enterpriseData.Enterprise.Load();
            }

            if (enterpriseData.RootNode == null) throw new Exception("Enterprise data: cannot get root node");

            EnterpriseNode parentNode = null;
            if (!string.IsNullOrEmpty(arguments.Parent))
            {
                parentNode = enterpriseData.ResolveNodeName(arguments.Parent);
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
                    var node = await enterpriseData.CreateNode(arguments.Node, parentNode);
                    Console.WriteLine($"Node \"{arguments.Node}\" created.");
                    if (arguments.RestrictVisibility)
                    {
                        await enterpriseData.SetRestrictVisibility(node.Id);
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
                        node = enterpriseData.RootNode;
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
                    node = enterpriseData.ResolveNodeName(arguments.Node);
                }

                switch (arguments.Command.ToLowerInvariant())
                {
                    case "tree":
                    {
                        enterpriseData.PrintNodeTree(node, "", arguments.Verbose, true);
                        return;
                    }

                    case "update":
                        if (!string.IsNullOrEmpty(arguments.Name))
                        {
                            node.DisplayName = arguments.Name;
                        }
                        await enterpriseData.UpdateNode(node, parentNode);
                        Console.WriteLine($"Node \"{node.DisplayName}\" updated.");
                        if (arguments.RestrictVisibility)
                        {
                            await enterpriseData.SetRestrictVisibility(node.Id);
                            await enterpriseData.Enterprise.Load();
                            Console.WriteLine($"Node Isolation: {(node.RestrictVisibility ? "ON" : "OFF")}");
                        }

                        break;

                    case "delete":
                        await enterpriseData.DeleteNode(node.Id);
                        Console.WriteLine($"Node \"{node.DisplayName}\" deleted.");
                        break;

                    default:
                        Console.WriteLine($"Unsupported command \"{arguments.Command}\": available commands \"tree\", \"add\", \"update\", \"delete\"");
                        break;
                }
            }
            await enterpriseData.Enterprise.Load();
        }

        public static async Task EnterpriseUserCommand(this IEnterpriseContext context, EnterpriseUserOptions arguments)
        {
            if (string.IsNullOrEmpty(arguments.Command))
            {
                arguments.Command = "list";
            }
            else
            {
                arguments.Command = arguments.Command.ToLowerInvariant();
            }

            if (arguments.Force)
            {
                await context.Enterprise.Load();
            }

            if (arguments.Command == "list")
            {
                var users = context.EnterpriseData.Users
                    .Where(x =>
                    {
                        if (string.IsNullOrEmpty(arguments.User)) return true;
                        if (x.Email.StartsWith(arguments.User, StringComparison.InvariantCultureIgnoreCase)) return true;
                        var m = Regex.Match(x.Email, arguments.User, RegexOptions.IgnoreCase);
                        if (m.Success) return true;
                        if (!string.IsNullOrEmpty(x.DisplayName))
                        {
                            m = Regex.Match(x.DisplayName, arguments.User, RegexOptions.IgnoreCase);
                            if (m.Success) return true;
                        }

                        var status = x.UserStatus.ToString();
                        m = Regex.Match(status, arguments.User, RegexOptions.IgnoreCase);
                        return m.Success;
                    })
                    .ToArray();

                var tab = new Tabulate(5)
                {
                    DumpRowNo = true
                };
                tab.AddHeader("Email", "Display Name", "Status", "Teams", "Aliases");
                foreach (var user in users)
                {
                    var teams = context.EnterpriseData.GetTeamsForUser(user.Id);
                    var aliases = context.UserAliasData.GetAliasesForUser(user.Id).Where(x => x != user.Email).ToArray();
                    tab.AddRow(user.Email, user.DisplayName, user.UserStatus.ToString(), teams?.Length ?? 0, aliases);
                }

                tab.Sort(1);
                tab.Dump();
                return;
            }

            if (string.IsNullOrEmpty(arguments.User))
            {
                Console.WriteLine("User parameter cannot be empty");
                return;
            }

            if (arguments.Command == "invite")
            {
                var options = new InviteUserOptions
                {
                    FullName = arguments.FullName,
                };
                if (!string.IsNullOrEmpty(arguments.Node))
                {
                    try
                    {
                        var n = context.EnterpriseData.ResolveNodeName(arguments.Node);
                        options.NodeId = n.Id;
                    }
                    catch { }
                }
                await context.EnterpriseData.InviteUser(arguments.User, options);
                Console.WriteLine($"User {arguments.User} invited.");
                return;
            }

            KeeperSecurity.Enterprise.EnterpriseUser singleUser = null;
            if (arguments.User.All(x => char.IsDigit(x)))
            {
                if (long.TryParse(arguments.User, out var userId))
                {
                    context.EnterpriseData.TryGetUserById(userId, out singleUser);
                }
            }
            if (singleUser == null) {
                context.EnterpriseData.TryGetUserByEmail(arguments.User, out singleUser);
            }
            if (singleUser == null)
            {
                Console.WriteLine($"Enterprise user \"{arguments.User}\" not found");
                return;
            }

            if (arguments.Command == "view")
            {
                var tab = new Tabulate(2)
                {
                    DumpRowNo = false
                };
                tab.SetColumnRightAlign(0, true);
                tab.AddRow(" User Email:", singleUser.Email);
                tab.AddRow(" User Name:", singleUser.DisplayName);
                tab.AddRow(" User ID:", singleUser.Id.ToString());
                tab.AddRow(" Status:", singleUser.UserStatus.ToString());

                var teams = context.EnterpriseData.GetTeamsForUser(singleUser.Id) ?? Enumerable.Empty<string>();

                var teamNames = teams
                    .Select(x => context.EnterpriseData.TryGetTeam(x, out var team) ? team.Name : null)
                    .Where(x => !string.IsNullOrEmpty(x))
                    .ToArray();
                Array.Sort(teamNames);
                tab.AddRow(" Teams:", teamNames.Length > 0 ? teamNames[0] : "");
                for (var i = 1; i < teamNames.Length; i++)
                {
                    tab.AddRow("", teamNames[i]);
                }

                if (context.EnterpriseData.TryGetNode(singleUser.ParentNodeId, out var node))
                {
                    var nodes = context.EnterpriseData.GetNodePath(node).ToArray();
                    Array.Reverse(nodes);
                    tab.AddRow(" Node:", string.Join(" -> ", nodes));
                }

                tab.Dump();
            }
            else if (arguments.Command == "alias-add" || arguments.Command == "alias-remove") {
                if (string.IsNullOrEmpty(arguments.Alias))
                {
                    Console.WriteLine("User alias parameter is mandatory.");
                    return;
                }
                if (arguments.Command == "alias-add")
                {
                    var aliasExists = context.UserAliasData.GetAliasesForUser(singleUser.Id).Where(x => x == arguments.Alias).Any();
                    if (aliasExists)
                    {
                        var rq = new EnterpriseUserAliasRequest { 
                            EnterpriseUserId = singleUser.Id,
                            Alias = arguments.Alias
                        };
                        await context.Enterprise.Auth.ExecuteAuthRest("enterprise/enterprise_user_set_primary_alias", rq);
                    }
                    else {
                        var rq = new EnterpriseUserAddAliasRequestV2();
                        rq.EnterpriseUserAddAliasRequest.Add(new EnterpriseUserAddAliasRequest
                        {
                            Primary = true,
                            EnterpriseUserId = singleUser.Id,
                            Alias = arguments.Alias
                        });
                        var rs = await context.Enterprise.Auth.ExecuteAuthRest<EnterpriseUserAddAliasRequestV2, EnterpriseUserAddAliasResponse>("enterprise/enterprise_user_add_alias", rq, apiVersion: 1);
                        foreach (var st in rs.Status)
                        {
                            if (st.Status != "success")
                            {
                                Console.WriteLine($"Failed to add alias to user {st.EnterpriseUserId}: {st.Status}");
                            }
                        }
                    }
                }
                else
                {
                    var rq = new EnterpriseUserAliasRequest
                    {
                        EnterpriseUserId = singleUser.Id,
                        Alias = arguments.Alias
                    };
                    await context.Enterprise.Auth.ExecuteAuthRest("enterprise/enterprise_user_delete_alias", rq);
                }
                await context.Enterprise.Load();
            }
            else if (arguments.Command == "team-add" || arguments.Command == "team-remove")
            {
                if (string.IsNullOrEmpty(arguments.Team))
                {
                    Console.WriteLine("Team name parameter is mandatory.");
                    return;
                }

                var team = context.EnterpriseData.Teams
                    .FirstOrDefault(x =>
                    {
                        if (string.CompareOrdinal(x.Uid, arguments.Team) == 0) return true;
                        return string.Compare(x.Name, arguments.Team, StringComparison.CurrentCultureIgnoreCase) == 0;
                    });
                var queuedTeam = context.QueuedTeamManagement.QueuedTeams
                    .FirstOrDefault(x =>
                    {
                        if (string.CompareOrdinal(x.Uid, arguments.Team) == 0) return true;
                        return string.Compare(x.Name, arguments.Team, StringComparison.CurrentCultureIgnoreCase) == 0;
                    });
                if (team == null && queuedTeam == null)
                {
                    Console.WriteLine($"Team {arguments.Team} cannot be found.");
                    return;
                }

                if (arguments.Command == "team-add")
                {
                    if (team != null)
                    {
                        if (singleUser.UserStatus == UserStatus.Active)
                        {
                            await context.EnterpriseData.AddUsersToTeams(new[] { singleUser.Email }, new[] { team.Uid }, Console.WriteLine);
                        }
                        else
                        {
                            await context.QueuedTeamManagement.QueueUserToTeam(singleUser.Id, team.Uid);
                        }
                    }
                    else if (queuedTeam != null)
                    {
                        await context.QueuedTeamManagement.QueueUserToTeam(singleUser.Id, queuedTeam.Uid);
                    }
                }
                else
                {
                    if (team != null)
                    {
                        await context.EnterpriseData.RemoveUsersFromTeams(new[] { singleUser.Email }, new[] { team.Uid }, Console.WriteLine);
                    }
                    else if (queuedTeam != null)
                    {
                        await context.EnterpriseData.RemoveUsersFromTeams(new[] { singleUser.Email }, new[] { queuedTeam.Uid }, Console.WriteLine);
                    }
                }
            }
            else if (arguments.Command == "lock" || arguments.Command == "unlock")
            {
                var user = await context.EnterpriseData.SetUserLocked(singleUser, arguments.Command == "lock");
                if (user != null)
                {
                    Console.WriteLine($"User {user.Email} status: {user.UserStatus}");
                }
                else
                {
                    Console.WriteLine($"User {singleUser.Email} deleted");
                }
            }
            else if (arguments.Command == "delete")
            {
                if (!arguments.Confirm) {
                    Console.WriteLine("Deleting a user will also delete any records owned and shared by this user.\n" +
                        "Before you delete this user, we strongly recommend you lock their account\n" +
                        "and transfer any important records to other user.\nThis action cannot be undone.\n");
                    Console.Write("Do you want to proceed with deletion (Yes/No)? > ");
                    var answer = await Program.GetInputManager().ReadLine();
                    if (string.Compare("y", answer, StringComparison.InvariantCultureIgnoreCase) == 0)
                    {
                        answer = "yes";
                    }
                    arguments.Confirm = string.Equals(answer, "yes", StringComparison.InvariantCultureIgnoreCase);
                }
                if (!arguments.Confirm) return;

                await context.EnterpriseData.DeleteUser(singleUser);

                Console.WriteLine($"User {singleUser.Email} deleted");
            }
            else
            {
                Console.WriteLine($"Unsupported command \"{arguments.Command}\". Commands are \"list\", \"view\", \"invite\", \"team-add\", \"team-remove\"");
            }
        }

        public static async Task TransferUserCommand(this IEnterpriseContext context, EnterpriseTransferUserOptions arguments)
        {
            KeeperSecurity.Enterprise.EnterpriseUser fromUser = null;
            if (arguments.FromUser.All(x => char.IsDigit(x)))
            {
                if (long.TryParse(arguments.FromUser, out var userId))
                {
                    context.EnterpriseData.TryGetUserById(userId, out fromUser);
                }
            }
            if (fromUser == null)
            {
                context.EnterpriseData.TryGetUserByEmail(arguments.FromUser, out fromUser);
            }
            if (fromUser == null)
            {
                Console.WriteLine($"Enterprise user \"{arguments.FromUser}\" not found");
                return;
            }
            KeeperSecurity.Enterprise.EnterpriseUser targetUser = null;
            if (arguments.TargetUser.All(x => char.IsDigit(x)))
            {
                if (long.TryParse(arguments.TargetUser, out var userId))
                {
                    context.EnterpriseData.TryGetUserById(userId, out targetUser);
                }
            }
            if (targetUser == null)
            {
                context.EnterpriseData.TryGetUserByEmail(arguments.TargetUser, out targetUser);
            }
            if (targetUser == null)
            {
                Console.WriteLine($"Enterprise user \"{arguments.TargetUser}\" not found");
                return;
            }

            if (fromUser.Id == targetUser.Id)
            {
                Console.WriteLine($"From and Target users cannot be the same.");
                return;
            }
            Console.Write($"This action cannot be undone.\n\nDo you want to proceed with transferring {fromUser.Email} account (Yes/No)? > ");
            var answer = await Program.GetInputManager().ReadLine();
            if (string.Compare("y", answer, StringComparison.InvariantCultureIgnoreCase) == 0)
            {
                answer = "yes";
            }

            if (!string.Equals(answer, "yes", StringComparison.InvariantCultureIgnoreCase)) return;

            var result = await context.EnterpriseData.TransferUserAccount(context.RoleManagement, fromUser, targetUser);
            var tab = new Tabulate(2)
            {
                DumpRowNo = false
            };

            tab.SetColumnRightAlign(0, true);
            tab.AddRow("Successfully Transfered  ", "");
            tab.AddRow("Records:", result.RecordsTransfered);
            tab.AddRow("Shared Folders:", result.SharedFoldersTransfered);
            tab.AddRow("Teams:", result.TeamsTransfered);
            if (result.RecordsCorrupted > 0 || result.SharedFoldersCorrupted > 0 || result.TeamsCorrupted > 0)
            {
                tab.AddRow("Failed to Transfer       ", "");
                if (result.RecordsCorrupted > 0)
                {
                    tab.AddRow("Records:", result.RecordsCorrupted);
                }
                if (result.SharedFoldersCorrupted > 0)
                {
                    tab.AddRow("Shared Folders:", result.SharedFoldersCorrupted);
                }
                if (result.TeamsCorrupted > 0)
                {
                    tab.AddRow("Teams:", result.TeamsCorrupted);
                }
            }
            tab.Dump();
        }

        public static async Task ExtendAccountShareExpirationCommand(this IEnterpriseContext context, EnterpriseUsersOptions options)
        {
            var availabeUsers = new Dictionary<long, KeeperSecurity.Enterprise.EnterpriseUser>();
            foreach (var u in context.EnterpriseData.Users)
            {
                if (u.AccountShareExpiration > 0)
                {
                    availabeUsers[u.Id] = u;
                }
            }
            if (availabeUsers.Count == 0)
            {
                Console.WriteLine("There are no users with pending Account Share status");
                return;
            }

            if (options.Users == null || !options.Users.Any())
            {
                var tab = new Tabulate(3)
                {
                    DumpRowNo = true
                };
                tab.AddHeader("User ID", "Email", "Expiration");
                foreach (var u in availabeUsers.Values)
                {
                    var exp = DateTimeOffset.FromUnixTimeMilliseconds(u.AccountShareExpiration).ToLocalTime();
                    tab.AddRow(u.Id, u.Email, exp.ToString("g"));
                }
                tab.Sort(1);
                tab.Dump();
                return;
            }

            var matchingUsers = new HashSet<long>();
            foreach (var user in options.Users)
            {
                var cnt = matchingUsers.Count;
                var allDigits = user.All(x => char.IsDigit(x));
                if (allDigits)
                {
                    if (long.TryParse(user, out var userId))
                    {
                        if (availabeUsers.ContainsKey(userId))
                        {
                            matchingUsers.Add(userId);
                        }
                    }
                }
                else
                {
                    foreach (var t in availabeUsers)
                    {
                        var matched = t.Value.Email.StartsWith(user, StringComparison.InvariantCultureIgnoreCase);
                        if (!matched)
                        {
                            var m = Regex.Match(t.Value.Email, user, RegexOptions.IgnoreCase);
                            matched = m.Success;

                        }
                        if (matched)
                        {
                            matchingUsers.Add(t.Key);
                        }
                    }
                }

                if (matchingUsers.Count > cnt)
                {
                    foreach (var uid in matchingUsers)
                    {
                        if (availabeUsers.ContainsKey(uid))
                        {
                            availabeUsers.Remove(uid);
                        }
                    }
                    if (availabeUsers.Count == 0)
                    {
                        break;
                    }
                }
            }
            if (matchingUsers.Count == 0)
            {
                Console.WriteLine("No users are found");
                return;
            }

            Console.Write($"Do you want to extend Account Share Expiration period for {matchingUsers.Count} account(s) (Yes/No)? > ");
            var answer = await Program.GetInputManager().ReadLine();
            if (string.Compare("y", answer, StringComparison.InvariantCultureIgnoreCase) == 0)
            {
                answer = "yes";
            }

            if (!string.Equals(answer, "yes", StringComparison.InvariantCultureIgnoreCase)) return;

            var commands = matchingUsers.Select(x => new ExtendAccountShareExpirationCommand { EnterpriseUserId = x }).Cast<KeeperApiCommand>().ToArray();

            var execRq = new ExecuteCommand
            {
                Requests = commands.Take(99).ToList()
            };
            var execRs = await context.Enterprise.Auth.ExecuteAuthCommand<ExecuteCommand, ExecuteResponse>(execRq);
            if (execRs.Results?.Count > 0)
            {
                var last = execRs.Results.Last();
                var success = execRs.Results.Count + (last.IsSuccess ? 0 : -1);
                if (success > 0)
                {
                    Console.WriteLine($"Successfully extended {success} account(s)");
                }
                if (!last.IsSuccess) 
                {
                    Console.WriteLine($"Error: {last.message}");
                }
            }

            await context.Enterprise.Load();
        }

        private static string[] _privilegeNames = new string[] { "MANAGE_NODES", "MANAGE_USER", "MANAGE_ROLES", "MANAGE_TEAMS", "RUN_REPORTS", "MANAGE_BRIDGE", "APPROVE_DEVICE", "TRANSFER_ACCOUNT" };

        public static async Task EnterpriseRoleCommand(this RoleData roleData, EnterpriseData enterpriseData, EnterpriseRoleOptions arguments)
        {
            if (arguments.Force)
            {
                await roleData.Enterprise.Load();
            }

            EnterpriseRole[] roles = null;
            if (!string.IsNullOrEmpty(arguments.Role))
            {
                long roleId = 0;
                long.TryParse(arguments.Role, out roleId);
                roles = roleData.Roles
                    .Where(x =>
                    {
                        if (string.IsNullOrEmpty(arguments.Role)) return true;
                        if (roleId > 0)
                        {
                            if (roleId == x.Id) return true;
                        }

                        if (x.DisplayName.StartsWith(arguments.Role, StringComparison.CurrentCultureIgnoreCase))
                        {
                            return true;
                        }

                        return false;
                    })
                    .ToArray();
            }

            if (string.IsNullOrEmpty(arguments.Command)) arguments.Command = "list";

            if (string.CompareOrdinal(arguments.Command, "list") == 0)
            {
                if (roles == null)
                {
                    roles = roleData.Roles.ToArray();
                }
                if (roles.Length == 0)
                {
                    Console.WriteLine($"Role \"{arguments.Role ?? ""}\" not found");
                    return;
                }
                {
                    // Display role info
                    var tab = new Tabulate(7)
                    {
                        DumpRowNo = true
                    };
                    tab.AddHeader("Role Name", "Role ID", "Node Name", "Visible Below?", "New User?", "Users", "Teams");
                    foreach (var r in roles)
                    {
                        EnterpriseNode node = null;
                        if (r.ParentNodeId > 0)
                        {
                            enterpriseData.TryGetNode(r.ParentNodeId, out node);
                        }
                        else
                        {
                            node = enterpriseData.RootNode;
                        }

                        var users = roleData.GetUsersForRole(r.Id).ToArray();
                        var teams = roleData.GetTeamsForRole(r.Id).ToArray();

                        tab.AddRow(
                            r.DisplayName,
                            r.Id,
                            node != null ? node.DisplayName : "",
                            r.VisibleBelow,
                            r.NewUserInherit,
                            users.Length.ToString(),
                            teams.Length.ToString());

                    }
                    Console.WriteLine("\nRoles\n");
                    tab.Sort(0);
                    tab.Dump();
                }

                var roleIds = new HashSet<long>(roles.Select(x => x.Id));
                var managedNodes = roleData.GetManagedNodes().Where(x => roleIds.Contains(x.RoleId)).ToArray();
                if (managedNodes.Length > 0)  // Display managed roles
                {
                    var tab = new Tabulate(11)
                    {
                        DumpRowNo = true
                    };
                    tab.AddHeader("Role Name", "Node Name", "Cascade?", "Node", "Users", "Roles", "Teams", "Reports", "Bridge", "Approval", "Transfer");
                    var privileges = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    foreach (var mn in managedNodes)
                    {
                        if (!roleData.TryGetRole(mn.RoleId, out var r) || !enterpriseData.TryGetNode(mn.ManagedNodeId, out var node)) continue;
                        privileges.Clear();
                        privileges.UnionWith(roleData.GetPrivilegesForRoleAndNode(mn.RoleId, mn.ManagedNodeId).Select(x => x.PrivilegeType));

                        var row = new object[] { r.DisplayName, node.DisplayName, mn.CascadeNodeManagement }
                        .Concat(_privilegeNames.Select(x => privileges.Contains(x)).Cast<object>()).ToArray();

                        tab.AddRow(row);
                    }
                    Console.WriteLine("\nAdministrative Permissions\n");
                    tab.Sort(0);
                    tab.Dump();
                }
                return;
            }
            if (roles == null)
            {
                Console.WriteLine($"Role parameter is required.");
                return;
            }

            if (string.CompareOrdinal(arguments.Command, "add") == 0)
            {
                if (roles.Length > 0)
                {
                    Console.WriteLine($"Role with name \"{arguments.Role}\" already exists.\nDo you want to create a new one? Yes/No");
                    var answer = await Program.GetInputManager().ReadLine();
                    if (string.Compare("y", answer, StringComparison.InvariantCultureIgnoreCase) == 0)
                    {
                        answer = "yes";
                    }

                    if (string.Compare(answer, "yes", StringComparison.InvariantCultureIgnoreCase) != 0) return;
                }

                long nodeId = 0;
                if (!string.IsNullOrEmpty(arguments.Node))
                {
                    long nId = 0;
                    if (long.TryParse(arguments.Node, out nId))
                    {
                        if (enterpriseData.TryGetNode(nId, out _))
                        {
                            nodeId = nId;
                        }
                    }
                    if (nodeId == 0)
                    {
                        var nodes = enterpriseData.Nodes
                            .Where(x => string.Equals(x.DisplayName, arguments.Node, StringComparison.InvariantCultureIgnoreCase))
                            .ToArray();
                        if (nodes.Length == 1)
                        {
                            nodeId = nodes[0].Id;
                        }
                        else
                        {
                            if (nodes.Length == 0)
                            {
                                Console.WriteLine($"Node \"{arguments.Node}\" not found");
                            }
                            else
                            {
                                Console.WriteLine($"More than one nodes with name \"{arguments.Node}\" are found. Use Node ID.");
                            }
                            return;
                        }
                    }
                }
                else
                {
                    nodeId = enterpriseData.RootNode.Id;
                }

                await roleData.CreateRole(arguments.Role, nodeId, arguments.NewUser);
                Console.WriteLine($"Role \"{arguments.Role}\" successfully added.");
                return;
            }

            if (roles.Length != 1)
            {
                if (roles.Length == 0)
                {
                    Console.WriteLine($"Role \"{arguments.Role}\" not found");
                }
                else
                {
                    Console.WriteLine($"Role \"{arguments.Role}\" - multiple matches found ({roles.Length}), please use Role ID.");
                }
                return;
            }
            var role = roles[0];

            if (string.CompareOrdinal(arguments.Command, "view") == 0)
            {
                var tab = new Tabulate(2)
                {
                    DumpRowNo = false
                };

                tab.SetColumnRightAlign(0, true);
                tab.AddRow(" Role Name:", role.DisplayName);
                tab.AddRow(" Role ID:", role.Id);
                tab.AddRow(" Node ID:", role.ParentNodeId);
                tab.AddRow(" Role Type:", role.RoleType);
                tab.AddRow(" Visible Below:", role.VisibleBelow);
                tab.AddRow(" New User Inherit:", role.NewUserInherit);


                var users = roleData
                    .GetUsersForRole(role.Id)
                    .Select(x => enterpriseData.TryGetUserById(x, out var user) ? user.Email : "")
                    .Where(x => !string.IsNullOrEmpty(x))
                    .ToArray();
                Array.Sort(users);
                tab.AddRow();
                tab.AddRow(" Users:", users.FirstOrDefault() ?? "");
                foreach (var u in users.Skip(1))
                {
                    tab.AddRow("", u);
                }

                var teams = roleData
                    .GetTeamsForRole(role.Id)
                    .Select(x => enterpriseData.TryGetTeam(x, out var team) ? team.Name : "")
                    .Where(x => !string.IsNullOrEmpty(x))
                    .ToArray();
                Array.Sort(teams);
                tab.AddRow();
                tab.AddRow(" Teams:", teams.FirstOrDefault() ?? "");
                foreach (var t in teams.Skip(1))
                {
                    tab.AddRow("", t);
                }

                var mnodes = roleData
                    .GetManagedNodes()
                    .Where(x => x.RoleId == role.Id)
                    .Select(x => enterpriseData.TryGetNode(x.ManagedNodeId, out var node) ? node : null)
                    .Where(x => x != null)
                    .OrderBy(x => string.IsNullOrEmpty(x.DisplayName) ? x.Id.ToString() : x.DisplayName.ToLowerInvariant())
                    .ToArray();

                if (mnodes.Length > 0)
                {
                    tab.AddRow();
                    tab.AddRow(" Managed Nodes:");
                    foreach (var mNode in mnodes)
                    {
                        var privileges = roleData
                            .GetPrivilegesForRoleAndNode(role.Id, mNode.Id)
                            .Select(x => x.PrivilegeType)
                            .ToArray();
                        tab.AddRow(mNode.DisplayName, string.Join(", ", privileges));
                    }
                }

                var enforcements = roleData.GetEnforcementsForRole(role.Id).ToArray();
                if (enforcements.Length > 0)
                {
                    tab.AddRow();
                    tab.AddRow(" Enforcements:");
                    foreach (var e in enforcements)
                    {
                        tab.AddRow(e.EnforcementType, e.Value);
                    }
                }

                tab.Dump();
                return;
            }

            if (string.CompareOrdinal(arguments.Command, "delete") == 0)
            {
                await roleData.DeleteRole(role);
                return;
            }

            var cmds = new HashSet<string>(StringComparer.InvariantCultureIgnoreCase);
            cmds.UnionWith(new[] { "add-members", "remove-members" });
            if (cmds.Contains(arguments.Command))
            {
                var users = new Dictionary<long, KeeperSecurity.Enterprise.EnterpriseUser>();
                var teams = new Dictionary<string, EnterpriseTeam>();
                if (arguments.Parameters == null) {
                    Console.WriteLine($"\"members\" parameter is required.");
                    return;
                }

                foreach (var member in arguments.Parameters)
                {
                    long nId = 0;
                    if (long.TryParse(member, out nId))
                    {
                        if (enterpriseData.TryGetUserById(nId, out var u))
                        {
                            users[nId] = u;
                            continue;
                        }
                    }
                    {
                        if (enterpriseData.TryGetUserByEmail(member, out var u))
                        {
                            users[u.Id] = u;
                            continue;
                        }
                    }
                    if (enterpriseData.TryGetTeam(member, out var t))
                    {
                        teams[t.Uid] = t;
                        continue;
                    }
                    var ts = enterpriseData.Teams.Where(x => string.Equals(x.Name, member, StringComparison.CurrentCultureIgnoreCase)).ToArray();
                    if (ts.Length == 1)
                    {
                        t = ts[0];
                        teams[t.Uid] = t;
                        continue;
                    }
                    if (ts.Length > 1) {
                        Console.WriteLine($"More than one team with name \"{member}\" are found. Use TeamUID instead.");
                        continue;
                    }
                    Console.WriteLine($"Member with name \"{member}\" not found.");
                }

                var isAdd = string.Equals(arguments.Command, "add-members");
                Console.WriteLine($"{(isAdd ? "Addding members to" : "Removing members from")} role \"{role.DisplayName}\"");
                foreach (var user in users.Values) {
                    try
                    {
                        Console.Write($"User: \"{user.Email}\" : ");
                        if (isAdd)
                        {
                            await roleData.AddUserToRole(role, user);
                        }
                        else
                        {
                            await roleData.RemoveUserFromRole(role, user);
                        }
                        Console.WriteLine("Success");
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine($"Error: {e.Message}");
                    }
                }
                foreach (var team in teams.Values)
                {
                    try
                    {
                        Console.Write($"Team: \"{team.Name}\" : ");
                        if (isAdd)
                        {
                            await roleData.AddTeamToRole(role, team);
                        }
                        else
                        {
                            await roleData.RemoveTeamFromRole(role, team);
                        }
                        Console.WriteLine("Success");
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine($"Error: {e.Message}");
                    }
                }

                return;
            }

            Console.WriteLine($"Unsupported command \"{arguments.Command}\". Valid commands are  \"list\", \"view\", \"add\", \"delete\", \"add-members\", \"remove-members\"");
        }

        public static async Task EnterpriseTeamCommand(this IEnterpriseContext context, EnterpriseTeamOptions arguments)
        {
            if (arguments.Force)
            {
                await context.Enterprise.Load();
            }

            if (string.IsNullOrEmpty(arguments.Command)) arguments.Command = "list";
            if (string.CompareOrdinal(arguments.Command, "list") == 0)
            {
                var teams = context.EnterpriseData.Teams
                    .Where(x =>
                    {
                        if (string.IsNullOrEmpty(arguments.Name)) return true;
                        if (arguments.Name == x.Uid) return true;
                        var m = Regex.Match(x.Name, arguments.Name, RegexOptions.IgnoreCase);
                        return m.Success;
                    })
                    .ToArray();
                var tab = new Tabulate(7 + (arguments.Queued ? 2 : 0))
                {
                    DumpRowNo = true
                };
                tab.AddHeader("Team Name", "Team UID", "Node Name", "Restrict Edit", "Restrict Share", "Restrict View", "Users", "Queued?", "Queued Users");
                foreach (var team in teams)
                {
                    EnterpriseNode node = null;
                    if (team.ParentNodeId > 0)
                    {
                        context.EnterpriseData.TryGetNode(team.ParentNodeId, out node);
                    }
                    else
                    {
                        node = context.EnterpriseData.RootNode;
                    }

                    var users = context.EnterpriseData.GetUsersForTeam(team.Uid);
                    var queuedUserCount = context.QueuedTeamManagement.GetQueuedUsersForTeam(team.Uid)?.Count() ?? 0;
                    tab.AddRow(team.Name,
                        team.Uid,
                        node != null ? node.DisplayName : "",
                        team.RestrictEdit,
                        team.RestrictSharing,
                        team.RestrictView,
                        (users?.Length ?? 0).ToString(),
                        false, queuedUserCount.ToString());
                }

                if (arguments.Queued)
                {
                    foreach (var qteam in context.QueuedTeamManagement.QueuedTeams)
                    {
                        EnterpriseNode node = null;
                        if (qteam.ParentNodeId > 0)
                        {
                            context.EnterpriseData.TryGetNode(qteam.ParentNodeId, out node);
                        }
                        else
                        {
                            node = context.EnterpriseData.RootNode;
                        }

                        var queuedUserCount = context.QueuedTeamManagement.GetQueuedUsersForTeam(qteam.Uid).Count();
                        tab.AddRow(qteam.Name,
                            qteam.Uid,
                            node != null ? node.DisplayName : "",
                            "", "", "", "",
                            true, queuedUserCount.ToString());
                    }
                }

                tab.Sort(1);
                tab.Dump();
            }
            else
            {
                var team = context.EnterpriseData.Teams
                    .FirstOrDefault(x =>
                    {
                        if (string.IsNullOrEmpty(arguments.Name)) return true;
                        if (arguments.Name == x.Uid) return true;
                        return string.Compare(x.Name, arguments.Name, StringComparison.CurrentCultureIgnoreCase) == 0;
                    });
                var queuedTeam = context.QueuedTeamManagement.QueuedTeams
                    .FirstOrDefault(x =>
                    {
                        if (string.IsNullOrEmpty(arguments.Name)) return true;
                        if (arguments.Name == x.Uid) return true;
                        return string.Compare(x.Name, arguments.Name, StringComparison.CurrentCultureIgnoreCase) == 0;
                    });
                if (string.CompareOrdinal(arguments.Command, "delete") == 0)
                {
                    if (team == null && queuedTeam == null)
                    {
                        Console.WriteLine($"Team \"{arguments.Name}\" not found");
                        return;
                    }

                    await context.EnterpriseData.DeleteTeam(team.Uid);
                }
                else if (string.CompareOrdinal(arguments.Command, "view") == 0)
                {
                    if (team == null && queuedTeam == null)
                    {
                        Console.WriteLine($"Team \"{arguments.Name}\" not found");
                        return;
                    }

                    var tab = new Tabulate(2)
                    {
                        DumpRowNo = false
                    };
                    tab.SetColumnRightAlign(0, true);
                    if (team != null)
                    {
                        tab.AddRow(" Team Name:", team.Name);
                        tab.AddRow(" Team UID:", team.Uid);
                        tab.AddRow(" Restrict Edit:", team.RestrictEdit ? "Yes" : "No");
                        tab.AddRow(" Restrict Share:", team.RestrictSharing ? "Yes" : "No");
                        tab.AddRow(" Restrict View:", team.RestrictView ? "Yes" : "No");
                    }
                    else if (queuedTeam != null)
                    {
                        tab.AddRow(" Queued Team Name:", queuedTeam.Name);
                        tab.AddRow(" Queued Team UID:", queuedTeam.Uid);
                    }

                    var teamUid = team != null ? team.Uid : queuedTeam.Uid;
                    if (team != null)
                    {
                        var users = context.EnterpriseData.GetUsersForTeam(teamUid) ?? Enumerable.Empty<long>(); ;
                        var userEmails = users
                            .Select(x => context.EnterpriseData.TryGetUserById(x, out var user) ? user.Email : null)
                            .Where(x => !string.IsNullOrEmpty(x))
                            .ToArray();
                        Array.Sort(userEmails);
                        tab.AddRow(" Users:", userEmails.Length > 0 ? userEmails[0] : "");
                        for (var i = 1; i < userEmails.Length; i++)
                        {
                            tab.AddRow("", userEmails[i]);
                        }
                    }
                    var queuedUsers = context.QueuedTeamManagement.GetQueuedUsersForTeam(teamUid) ?? Enumerable.Empty<long>(); ;
                    var queuedUserEmails = queuedUsers
                        .Select(x => context.EnterpriseData.TryGetUserById(x, out var user) ? user.Email : null)
                        .Where(x => !string.IsNullOrEmpty(x))
                        .ToArray();
                    Array.Sort(queuedUserEmails);
                    tab.AddRow(" Queued Users:", queuedUserEmails.Length > 0 ? queuedUserEmails[0] : "");
                    for (var i = 1; i < queuedUserEmails.Length; i++)
                    {
                        tab.AddRow("", queuedUserEmails[i]);
                    }


                    var parentNodeId = team != null ? team.ParentNodeId : queuedTeam.ParentNodeId;
                    if (context.EnterpriseData.TryGetNode(parentNodeId, out var node))
                    {
                        var nodes = context.EnterpriseData.GetNodePath(node).ToArray();
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
                            ParentNodeId = context.EnterpriseData.RootNode.Id
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

                        var node = context.EnterpriseData.Nodes
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

                    await context.EnterpriseData.UpdateTeam(team);
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
                await context.Enterprise.Load();
            }

            var approvals = context.DeviceApproval.DeviceApprovalRequests.ToArray();

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
                        if (!context.EnterpriseData.TryGetUserById(device.EnterpriseUserId, out var user)) continue;

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

                                if (!context.EnterpriseData.TryGetUserById(x.EnterpriseUserId, out var user)) return false;
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

                        if (context.EnterpriseData.TryGetUserById(approveRs.EnterpriseUserId, out var user))
                        {
                            Console.WriteLine($"Failed to approve {user.Email}: {approveRs.Message}");
                        }
                    }
                }
                await context.Enterprise.Load();
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
                            if (context.EnterpriseData.TryGetUserById(approveRs.EnterpriseUserId, out var user))
                            {
                                Console.WriteLine($"Failed to approve {user.Email}: {approveRs.Message}");
                            }
                        }
                    }

                    await context.Enterprise.Load();
                }
            }
        }

        internal static async Task EnterpriseRegisterEcKey(this IEnterpriseContext context, Cli.CliCommands cli)
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
                    return filter;
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

            if (options.Username != null && options.Username.Any())
            {
                filter.Username = options.Username.ToArray();
            }

            if (!string.IsNullOrEmpty(options.ToUsername))
            {
                filter.ToUsername = new[] { options.ToUsername };
            }

            if (options.RecordUid != null && options.RecordUid.Any())
            {
                filter.RecordUid = options.RecordUid.ToArray();
            }

            if (options.SharedFolderUid != null && options.SharedFolderUid.Any())
            {
                filter.SharedFolderUid = options.SharedFolderUid.ToArray();
            }

            var rq = new GetAuditEventReportsCommand
            {
                Filter = filter,
                Limit = options.Limit,
            };

            if (!string.IsNullOrEmpty(options.Order)) 
            {
                if (options.Order == "asc") 
                {
                    rq.Order = "ascending";
                }
            }

            if (!string.IsNullOrEmpty(options.ReportType))
            {
                rq.ReportType = options.ReportType;
            }
            if (options.Aggregate != null && options.Aggregate.Any())
            {
                rq.Aggregate = options.Aggregate.ToArray();
            }
            if (options.Columns != null && options.Columns.Any())
            {
                rq.Columns = options.Columns.ToArray();
            }

            var rs = await context.Enterprise.Auth.ExecuteAuthCommand<GetAuditEventReportsCommand, GetAuditEventReportsResponse>(rq);

            Tabulate tab;

            if (rq.ReportType == "raw")
            {
                tab = new Tabulate(4) { DumpRowNo = true };
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
            }
            else
            {
                var columns = options.Aggregate.Concat(options.Columns).ToArray();
                tab = new Tabulate(columns.Length) { DumpRowNo = true };
                tab.AddHeader(columns);
                tab.MaxColumnWidth = 100;
                foreach (var evt in rs.Events)
                {
                    var values = columns.Select(x => {
                        object value = null;
                        evt.TryGetValue(x, out value);
                        if (value != null && (x == "last_created" || x == "first_created")) 
                        {
                            if (value is IConvertible c) 
                            {
                                var ts = c.ToInt64(CultureInfo.InvariantCulture);
                                var dt = DateTimeOffset.FromUnixTimeSeconds(ts);
                                value = dt.ToString("g");
                            }
                        }
                        return value;
                    }).ToArray();
                    tab.AddRow(values);
                }
            }
            tab.Dump();
        }
    }

    internal class McEnterpriseContext : StateCommands, IEnterpriseContext
    {
        public EnterpriseLoader Enterprise { get; }
        public EnterpriseData EnterpriseData { get; }
        public DeviceApprovalData DeviceApproval { get; }
        public RoleData RoleManagement { get; }
        public QueuedTeamDataManagement QueuedTeamManagement { get; }
        public UserAliasData UserAliasData { get; }

        public McEnterpriseContext(ManagedCompanyAuth auth)
        {
            if (auth.AuthContext.IsEnterpriseAdmin)
            {
                DeviceApproval = new DeviceApprovalData();
                RoleManagement = new RoleData();
                EnterpriseData = new EnterpriseData();
                QueuedTeamManagement = new QueuedTeamDataManagement();
                UserAliasData = new UserAliasData();

                Enterprise = new EnterpriseLoader(auth, new EnterpriseDataPlugin[] { EnterpriseData, RoleManagement, DeviceApproval, QueuedTeamManagement, UserAliasData });
                Task.Run(async () =>
                {
                    try
                    {
                        await Enterprise.LoadKeys(auth.TreeKey);
                        await Enterprise.Load();
                        this.AppendEnterpriseCommands(this);
                    }
                    catch (Exception e)
                    {
                        Debug.WriteLine(e);
                    }
                });
            }
        }

        public bool AutoApproveAdminRequests { get; set; }
        public ECPrivateKeyParameters EnterprisePrivateKey { get; set; }
        public Dictionary<long, byte[]> UserDataKeys { get; } = new Dictionary<long, byte[]>();
        public IDictionary<string, AuditEventType> AuditEvents { get; set; }

        public override string GetPrompt()
        {
            return "Managed Company";
        }
    }

    public partial class ConnectedContext : IEnterpriseContext
    {
        public EnterpriseLoader Enterprise { get; private set; }
        public EnterpriseData EnterpriseData { get; private set; }
        public RoleData RoleManagement { get; private set; }
        public QueuedTeamDataManagement QueuedTeamManagement { get; private set; }
        public UserAliasData UserAliasData { get; internal set; }

        public DeviceApprovalData DeviceApproval { get; private set; }
        public bool AutoApproveAdminRequests { get; set; }
        public Dictionary<long, byte[]> UserDataKeys { get; } = new Dictionary<long, byte[]>();


        public ECPrivateKeyParameters EnterprisePrivateKey { get; set; }
        public IDictionary<string, AuditEventType> AuditEvents { get; set; }

        private ManagedCompanyData _managedCompanies;

        private void CheckIfEnterpriseAdmin()
        {
            if (_auth.AuthContext.IsEnterpriseAdmin)
            {
                EnterpriseData = new EnterpriseData();
                RoleManagement = new RoleData();
                DeviceApproval = new DeviceApprovalData();
                _managedCompanies = new ManagedCompanyData();
                QueuedTeamManagement = new QueuedTeamDataManagement();
                UserAliasData = new UserAliasData();

                Enterprise = new EnterpriseLoader(_auth, new EnterpriseDataPlugin[] { EnterpriseData, RoleManagement, DeviceApproval, _managedCompanies, QueuedTeamManagement, UserAliasData });

                _auth.PushNotifications?.RegisterCallback(EnterpriseNotificationCallback);
                Task.Run(async () =>
                {
                    try
                    {
                        await Enterprise.Load();

                        this.AppendEnterpriseCommands(this);

                        if (!string.IsNullOrEmpty(EnterpriseData.EnterpriseLicense?.LicenseStatus) && EnterpriseData.EnterpriseLicense.LicenseStatus.StartsWith("msp"))
                        {
                            Commands.Add("mc-list",
                                new Cli.SimpleCommand
                                {
                                    Order = 72,
                                    Description = "List managed companies",
                                    Action = ListManagedCompanies,
                                });
                            Commands.Add("mc-create",
                                new ParseableCommand<ManagedCompanyCreateOptions>
                                {
                                    Order = 73,
                                    Description = "Create managed company",
                                    Action = CreateManagedCompany,
                                });
                            Commands.Add("mc-update",
                                new ParseableCommand<ManagedCompanyUpdateOptions>
                                {
                                    Order = 74,
                                    Description = "Updates managed company",
                                    Action = UpdateManagedCompany,
                                });
                            Commands.Add("mc-delete",
                                new ParseableCommand<ManagedCompanyRemoveOptions>
                                {
                                    Order = 75,
                                    Description = "Removes managed company",
                                    Action = RemoveManagedCompany,
                                });
                            Commands.Add("mc-login",
                                new ParseableCommand<ManagedCompanyLoginOptions>
                                {
                                    Order = 79,
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
                        await Enterprise.Load();
                        if (!EnterpriseData.TryGetUserByEmail(evt.Email, out var user)) return;

                        var devices = DeviceApproval.DeviceApprovalRequests
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

        private async Task LoginToManagedCompany(ManagedCompanyLoginOptions options)
        {
            var mcAuth = new ManagedCompanyAuth();
            await mcAuth.LoginToManagedCompany(Enterprise, options.CompanyId);
            NextStateCommands = new McEnterpriseContext(mcAuth);
        }

        private Task ListManagedCompanies(string _)
        {
            var tab = new Tabulate(9);
            tab.AddHeader("Company Name", "Company ID", "Node", "Plan", "Storage", "Addons", "Seats Allowed", "Seats Used", "Paused");
            foreach (var mc in _managedCompanies.ManagedCompanies)
            {
                string nodeName = "";
                if (EnterpriseData.TryGetNode(mc.ParentNodeId, out var node))
                {
                    if (node.ParentNodeId > 0)
                    {
                        nodeName = node.DisplayName;
                    }
                    else
                    {
                        nodeName = EnterpriseData.Enterprise.EnterpriseName;
                    }
                }
                var plan = ManagedCompanyConstants.MspProducts.FirstOrDefault(x => x.ProductCode == mc.ProductId);
                var filePlan = ManagedCompanyConstants.MspFilePlans.FirstOrDefault(x => x.FilePlanCode == mc.FilePlanType);
                var addons = mc.AddOns.Select(x =>
                {
                    var addon = ManagedCompanyConstants.MspAddons.FirstOrDefault(y => x.Name == y.AddonCode);
                    return addon?.AddonName ?? x.Name;
                }).ToArray();
                tab.AddRow(mc.EnterpriseName, mc.EnterpriseId, nodeName, plan?.ProductName ?? mc.ProductId, filePlan?.FilePlanName ?? mc.FilePlanType,
                    addons, mc.NumberOfSeats < 2000000 ? mc.NumberOfSeats : (object)"Unlimited", mc.NumberOfUsers, mc.IsExpired ? "Yes" : "");
            }
            tab.Sort(0);
            tab.DumpRowNo = true;
            tab.SetColumnRightAlign(6, true);
            tab.SetColumnRightAlign(7, true);
            tab.Dump();
            return Task.CompletedTask;
        }


        private void PopulateMspCommonOptions(ManagedCompanyCommonOptions arguments, ManagedCompanyOptions options)
        {
            if (!string.IsNullOrEmpty(arguments.Node))
            {
                var n = EnterpriseData.ResolveNodeName(arguments.Node);
                options.NodeId = n.Id;
            }

            if (!string.IsNullOrEmpty(arguments.Product))
            {
                var plan = ManagedCompanyConstants.MspProducts.FirstOrDefault(x => string.Equals(arguments.Product, x.ProductCode, StringComparison.InvariantCultureIgnoreCase));
                if (plan == null)
                {
                    throw new Exception($"Invalid license plan: {arguments.Product}. Supported plans are {string.Join(", ", ManagedCompanyConstants.MspProducts.Select(x => x.ProductCode))}");
                }
                options.ProductId = plan.ProductCode;
            }

            if (arguments.Seats != null)
            {
                options.NumberOfSeats = arguments.Seats.Value >= 0 ? arguments.Seats.Value : 2147483647;
            }

            if (!string.IsNullOrEmpty(arguments.Storage))
            {
                var filePlan = ManagedCompanyConstants.MspFilePlans.FirstOrDefault(x =>
                string.Equals(arguments.Storage, x.FilePlanName, StringComparison.InvariantCultureIgnoreCase) ||
                string.Equals(arguments.Storage, x.FilePlanCode, StringComparison.InvariantCultureIgnoreCase));

                if (filePlan == null)
                {
                    throw new Exception($"Invalid storage plan: {arguments.Storage}. Supported plans are {string.Join(", ", ManagedCompanyConstants.MspProducts.Select(x => x.ProductName))}");
                }
                options.FilePlanType = filePlan.FilePlanCode;
            }

            if (!string.IsNullOrEmpty(arguments.Addons))
            {
                var addonList = new List<ManagedCompanyAddonOptions>();
                foreach (var aon in arguments.Addons.Split(','))
                {
                    string addonName = aon.Trim();
                    if (string.IsNullOrEmpty(addonName))
                    {
                        continue;
                    }
                    int addonSeats = 0;
                    var pos = addonName.IndexOf(':');
                    if (pos > 0)
                    {
                        var seats = addonName.Substring(pos + 1);
                        addonName = addonName.Substring(0, pos);
                        if (!int.TryParse(seats, out addonSeats))
                        {
                            throw new Exception($"Invalid number of seats \"{seats}\" for addon \"{addonName}\"");
                        }
                    }
                    var addon = ManagedCompanyConstants.MspAddons.FirstOrDefault(x => string.Equals(x.AddonCode, addonName, StringComparison.InvariantCultureIgnoreCase));
                    if (addon == null)
                    {
                        throw new Exception($"Invalid addon {addonName}. Supported addons are {string.Join(", ", ManagedCompanyConstants.MspAddons.Select(x => x.AddonCode))}");
                    }
                    addonList.Add(new ManagedCompanyAddonOptions
                    {
                        Addon = addon.AddonCode,
                        NumberOfSeats = addonSeats > 0 ? addonSeats : (int?) null
                    });
                }
                options.Addons = addonList.ToArray();
            }
        }

        private async Task CreateManagedCompany(ManagedCompanyCreateOptions arguments)
        {
            var mcOptions = new ManagedCompanyOptions
            {
                NodeId = EnterpriseData.RootNode.Id,
                Name = arguments.Name,
            };

            PopulateMspCommonOptions(arguments, mcOptions);

            if (string.IsNullOrEmpty(mcOptions.ProductId))
            {
                throw new Exception($"License plan is required.");
            }

            if (mcOptions.NumberOfSeats == null)
            {
                mcOptions.NumberOfSeats = 0;
            }

            var mc = await _managedCompanies.CreateManagedCompany(mcOptions);
            Console.WriteLine($"Managed Company \"{mc.EnterpriseName}\", ID:{mc.EnterpriseId} has been created.");
        }


        private async Task UpdateManagedCompany(ManagedCompanyUpdateOptions arguments)
        {
            int companyId = -1;
            int.TryParse(arguments.Company, out companyId);

            var mc = _managedCompanies.ManagedCompanies.FirstOrDefault(x =>
            {
                if (companyId > 0)
                {
                    if (companyId == x.EnterpriseId)
                    {
                        return true;
                    }
                }

                return string.Equals(x.EnterpriseName, arguments.Company, StringComparison.InvariantCultureIgnoreCase);
            });

            if (mc == null)
            {
                Console.WriteLine($"Managed company {arguments.Company} not found.");
            }

            var mcOptions = new ManagedCompanyOptions
            {
                ProductId = mc.ProductId,
                NumberOfSeats = mc.NumberOfSeats
            };
            PopulateMspCommonOptions(arguments, mcOptions);

            if (!string.IsNullOrEmpty(arguments.Name))
            {
                mcOptions.Name = arguments.Name;
            }

            var mc1 = await _managedCompanies.UpdateManagedCompany(mc.EnterpriseId, mcOptions);

            Console.WriteLine($"Managed Company \"{mc1.EnterpriseName}\", ID:{mc1.EnterpriseId} has been updated.");
        }

        private async Task RemoveManagedCompany(ManagedCompanyRemoveOptions options)
        {
            int companyId = -1;
            int.TryParse(options.Company, out companyId);

            var mc = _managedCompanies.ManagedCompanies.FirstOrDefault(x =>
            {
                if (companyId > 0)
                {
                    if (companyId == x.EnterpriseId)
                    {
                        return true;
                    }
                }

                return string.Equals(x.EnterpriseName, options.Company, StringComparison.InvariantCultureIgnoreCase);
            });

            if (mc != null)
            {
                await _managedCompanies.RemoveManagedCompany(mc.EnterpriseId);
                Console.WriteLine($"Managed Company \"{mc.EnterpriseName}\", ID:{mc.EnterpriseId} has been removed.");
            }
            else
            {
                Console.WriteLine($"Managed company {options.Company} not found.");
            }
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
        [Option("team", Required = false, HelpText = "team name or UID. \"team-add\", \"team-remove\"")]
        public string Team { get; set; }

        [Option("alias", Required = false, HelpText = "user alias. \"alias-add\", \"alias-remove\"")]
        public string Alias { get; set; }

        [Option("node", Required = false, HelpText = "node name or ID. \"invite\"")]
        public string Node { get; set; }

        [Option("name", Required = false, HelpText = "user full name. \"invite\"")]
        public string FullName { get; set; }

        [Option("yes", Required = false, HelpText = "delete user without confirmation prompt. \"delete\"")]
        public bool Confirm { get; set; }

        [Value(0, Required = false, HelpText = "enterprise-user command: \"list\", \"view\", \"invite\", \"lock\", \"unlock\", \"team-add\", \"team-remove\", " +
            "\"delete\", \"alias-add\", \"alias-remove\"")]
        public string Command { get; set; }

        [Value(1, Required = false, HelpText = "enterprise user email, ID (except \"invite\")")]
        public string User { get; set; }
    }

    class EnterpriseTransferUserOptions : EnterpriseGenericOptions 
    {
        [Value(0, Required = true, HelpText = "email or user ID to transfer vault from user")]
        public string FromUser { get; set; }

        [Value(1, Required = true, HelpText = "email or user ID to transfer vault to user")]
        public string TargetUser { get; set; }
    }

    class EnterpriseTeamOptions : EnterpriseGenericOptions
    {
        [Option("node", Required = false, HelpText = "node name or ID. \"add\", \"update\"")]
        public string Node { get; set; }

        [Option('q', "queued", Required = false, HelpText = "include queued team/user information. \"list\", \"view\"")]
        public bool Queued { get; set; }

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

    class EnterpriseRoleOptions : EnterpriseGenericOptions
    {
        [Option("node", Required = false, HelpText = "Node Name or ID. \"add\"")]
        public string Node { get; set; }

        [Option('n', "new-user", Required = false, Default = false, HelpText = "New users automatically get this role assigned. \"add\"")]
        public bool NewUser { get; set; }

        [Value(0, Required = false, HelpText = "command: \"list\", \"view\", \"add\", \"delete\", \"add-members\", \"remove-members\"")]
        public string Command { get; set; }

        [Value(1, Required = false, HelpText = "Role Name or ID")]
        public string Role { get; set; }

        [Value(2, Required = false, HelpText = "Command parameters:\n\"add-members\", \"remove-members\": list of User Emails, Team Names, User IDs, or Team UIDs. ")]
        public IEnumerable<string> Parameters { get; set; }
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

        [Option("order", Required = false, Default = null, HelpText = "sort order: asc, desc")]
        public string Order { get; set; }

        [Option("created", Required = false, Default = null, HelpText = "event creation datetime")]
        public string Created { get; set; }

        [Option("event-type", Required = false, Default = null, Separator = ',', HelpText = "audit event type")]
        public IEnumerable<string> EventType { get; set; }

        [Option("username", Required = false, Default = null, HelpText = "username of event originator")]
        public IEnumerable<string> Username { get; set; }

        [Option("to-username", Required = false, Default = null, HelpText = "username of event target")]
        public string ToUsername { get; set; }

        [Option("record-uid", Required = false, Default = null, HelpText = "record UID")]
        public IEnumerable<string> RecordUid { get; set; }

        [Option("shared-folder-uid", Required = false, Default = null, HelpText = "shared folder UID")]
        public IEnumerable<string> SharedFolderUid { get; set; }

        [Option("report-type", Required = false, Default = "raw", HelpText = "report type")]
        public string ReportType { get; set; }

        [Option("aggregate", Required = false, HelpText = "aggregate columns")]
        public IEnumerable<string> Aggregate { get; set; }

        [Option("columns", Required = false, HelpText = "report columns")]
        public IEnumerable<string> Columns { get; set; }
    }

    class EnterpriseUsersOptions : EnterpriseGenericOptions
    {
        [Value(0, Required = false, HelpText = "Email, User ID, or email pattern")]
        public IEnumerable<string> Users { get; set; }
    }

    class ManagedCompanyLoginOptions : EnterpriseGenericOptions
    {
        [Value(0, Required = true, HelpText = "mc-login <mc-company-id>")]
        public int CompanyId { get; set; }
    }

    class ManagedCompanyRemoveOptions : EnterpriseGenericOptions
    {
        [Value(0, Required = true, HelpText = "Managed company name or ID")]
        public string Company { get; set; }
    }

    class ManagedCompanyCommonOptions : EnterpriseGenericOptions
    {
        [Option("product", Required = false, HelpText = "Product Plan: business, businessPlus, enterprise, enterprisePlus")]
        public string Product { get; set; }

        [Option("seats", Required = false, HelpText = "Maximum number of seats. -1 unlimited.")]
        public int? Seats { get; set; }

        [Option("node", Required = false, HelpText = "Node Name or ID.")]
        public string Node { get; set; }

        [Option("storage", Required = false, HelpText = "Storage Plan: 100GB, 1TB, 10TB")]
        public string Storage { get; set; }

        [Option("addons", Required = false, HelpText = "Comma-separated list of addons: \nenterprise_breach_watch, compliance_report, enterprise_audit_and_reporting, \nmsp_service_and_support, secrets_manager, connection_manager:N, chat")]
        public string Addons { get; set; }
    }

    class ManagedCompanyCreateOptions : ManagedCompanyCommonOptions
    {

        [Value(0, Required = true, HelpText = "Managed Company Name")]
        public string Name { get; set; }
    }

    class ManagedCompanyUpdateOptions : ManagedCompanyCommonOptions
    {
        [Option("name", Required = false, HelpText = "New Managed Company Name.")]
        public string Name { get; set; }

        [Value(0, Required = true, HelpText = "Managed company name or ID")]
        public string Company { get; set; }
    }
}
