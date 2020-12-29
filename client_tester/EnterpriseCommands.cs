using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Runtime.Serialization;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Authentication;
using Cli;
using CommandLine;
using Google.Protobuf;
using KeeperSecurity.Authentication;
using KeeperSecurity.Commands;
using KeeperSecurity.Enterprise;
using KeeperSecurity.Utils;

namespace ClientTester
{
    public class EnterpriseCommands : StateCommands
    {
        private EnterpriseData Enterprise { get; }

        public EnterpriseCommands(EnterpriseData enterprise)
        {
            Enterprise = enterprise;

            Commands.Add("enterprise-data",
                new SimpleCommand
                {
                    Order = 100,
                    Description = "Reload enterprise data",
                    Action = async _ => { await Enterprise.PopulateEnterprise(); },
                });

            Commands.Add("enterprise-info",
                new SimpleCommand
                {
                    Order = 101,
                    Description = "Prints enterprise tree",
                    Action = EnterpriseInfo,
                });

            Commands.Add("enterprise-user",
                new ParsableCommand<UserOptions>
                {
                    Order = 102,
                    Description = "Prints enterprise users",
                    Action = EnterpriseUser,
                });

            Commands.Add("enterprise-team",
                new ParsableCommand<ListPatternOptions>
                {
                    Order = 103,
                    Description = "Prints enterprise teams",
                    Action = EnterpriseTeam,
                });

            Commands.Add("activate",
                new ParsableCommand<ActivateOptions>
                {
                    Order = 110,
                    Description = "Creates a regex of users",
                    Action = Activate,
                });

            Commands.Add("delete-users",
                new ParsableCommand<ActivateOptions>
                {
                    Order = 111,
                    Description = "delete a regex of users",
                    Action = DeleteUsers,
                });

            Commands.Add("delete-teams",
                new ParsableCommand<ActivateOptions>
                {
                    Order = 112,
                    Description = "delete a regex of teams",
                    Action = DeleteTeams,
                });

            Commands.Add("delete-node",
                new ParsableCommand<NodeOptions>
                {
                    Order = 113,
                    Description = "delete node hierarchy",
                    Action = DeleteNodes,
                });

            CommandAliases["ed"] = "enterprise-data";
            CommandAliases["ei"] = "enterprise-info";
            CommandAliases["eu"] = "enterprise-user";
            CommandAliases["et"] = "enterprise-team";
        }

        public void PrintNodeTree(EnterpriseNode eNode, string indent, bool last)
        {
            var isRoot = string.IsNullOrEmpty(indent);
            Console.WriteLine(indent + (isRoot ? "" : "+-- ") + $"{eNode.DisplayName} ({eNode.Id})");
            indent += isRoot ? " " : (last ? "    " : "|   ");
            var subNodes = eNode.Subnodes
                .Select(x => Enterprise.TryGetNode(x, out var node) ? node : null)
                .Where(x => x != null)
                .OrderBy(x => x.DisplayName ?? "")
                .ToArray();
            for (var i = 0; i < subNodes.Length; i++)
            {
                PrintNodeTree(subNodes[i], indent, i == subNodes.Length - 1);
            }
        }

        private Task EnterpriseInfo(string _)
        {
            PrintNodeTree(Enterprise.RootNode, "", true);
            return Task.CompletedTask;
        }

        private Task EnterpriseTeam(ListPatternOptions options)
        {
            var regex = new Regex(options.Pattern ?? ".+", RegexOptions.None);
            var tab = new Tabulate(4);
            tab.AddHeader("Name", "UID", "Users", "Node");
            var cnt = 0;
            foreach (var team in Enterprise.Teams)
            {
                if (regex.IsMatch(team.Name))
                {
                    string nodeName = Enterprise.EnterpriseName;
                    if (Enterprise.TryGetNode(team.ParentNodeId, out var node))
                    {
                        nodeName = " " + node.DisplayName;
                    }

                    tab.AddRow(team.Name, team.Uid, team.Users.Count, nodeName);
                    cnt++;
                    if (cnt >= 100)
                    {
                        break;
                    }
                }
            }

            tab.Sort(0);
            tab.SetColumnRightAlign(2, true);
            tab.DumpRowNo = true;
            tab.Dump();
            if (cnt >= 100)
            {
                Console.WriteLine($"Printed first {cnt} teams.");
            }

            return Task.CompletedTask;
        }

        private Task EnterpriseUser(UserOptions options)
        {
            var regex = new Regex(options.Pattern ?? ".+", RegexOptions.None);
            var tab = new Tabulate(5);
            tab.AddHeader("Email", "Name", "User ID", "Status", "Node");
            var cnt = 0;
            foreach (var user in Enterprise.Users)
            {
                if (options.Pending && user.UserStatus != UserStatus.Inactive) continue;
                if (regex.IsMatch(user.Email))
                {
                    string nodeName = Enterprise.EnterpriseName;
                    if (Enterprise.TryGetNode(user.ParentNodeId, out var node))
                    {
                        nodeName = " " + node.DisplayName;
                    }

                    tab.AddRow(user.Email, user.DisplayName, user.Id, user.UserStatus.ToString(), nodeName);
                    cnt++;
                    if (cnt >= 100)
                    {
                        break;
                    }
                }
            }

            tab.Sort(0);
            tab.DumpRowNo = true;
            tab.Dump();
            if (cnt >= 100)
            {
                Console.WriteLine($"Printed first {cnt} users.");
            }

            return Task.CompletedTask;
        }

        private async Task DeleteNodes(NodeOptions options)
        {
            EnterpriseNode node = null;
            if (long.TryParse(options.Node, NumberStyles.Integer, CultureInfo.CurrentUICulture, out var nodeId))
            {
                Enterprise.TryGetNode(nodeId, out node);
            }

            if (node == null)
            {
                var matches = Enterprise.Nodes
                    .Where(x => x.DisplayName == options.Node)
                    .ToArray();
                if (matches.Length == 1)
                {
                    node = matches[0];
                }
                else if (matches.Length > 1)
                {
                    Console.WriteLine($"Found {matches.Length} nodes with name {options.Node}. Please use Node ID");
                    return;
                }
            }

            if (node == null)
            {
                Console.WriteLine($"No node with name {options.Node} is found.");
                return;
            }

            var subnodes = new List<long>(node.Subnodes);
            var pos = 0;
            while (pos < subnodes.Count)
            {
                if (Enterprise.TryGetNode(subnodes[pos], out node))
                {
                    subnodes.AddRange(node.Subnodes);
                }

                pos++;
            }

            var nodesToDelete = new HashSet<long>(subnodes);
            var usersToDelete = Enterprise.Users
                .Where(x => nodesToDelete.Contains(x.ParentNodeId))
                .Select(x => x.Id)
                .ToList();
            var teamsToDelete = Enterprise.Teams
                .Where(x => nodesToDelete.Contains(x.ParentNodeId))
                .Select(x => x.Uid)
                .ToList();
            var entRs = await Enterprise.GetEnterpriseData("roles", "queued_teams");
            var rolesToDelete = new Dictionary<long, GetEnterpriseRole>();
            if (entRs.Roles != null)
            {
                foreach (var r in entRs.Roles)
                {
                    if (!nodesToDelete.Contains(r.NodeId)) continue;
                    rolesToDelete[r.RoleId] = r;
                }
            }

            var queuedTeamsToDelete = new Dictionary<string, GetEnterpriseQueuedTeam>();
            if (entRs.QueuedTeams != null)
            {
                foreach (var qt in entRs.QueuedTeams)
                {
                    if (!nodesToDelete.Contains(qt.NodeId)) continue;
                    queuedTeamsToDelete[qt.TeamUid] = qt;
                }
            }


            Console.WriteLine("To be removed:");
            if (rolesToDelete.Count > 0)
            {
                Console.WriteLine($"{"Roles",-16}: {rolesToDelete.Count}");
            }

            if (teamsToDelete.Count > 0)
            {
                Console.WriteLine($"{"Teams",-16}: {teamsToDelete.Count}");
            }

            if (usersToDelete.Count > 0)
            {
                Console.WriteLine($"{"Users",-16}: {usersToDelete.Count}");
            }

            if (nodesToDelete.Count > 0)
            {
                Console.WriteLine($"{"Nodes",-16}: {nodesToDelete.Count}");
            }

            if (queuedTeamsToDelete.Count > 0)
            {
                Console.WriteLine($"{"Queued Teams",-16}: {queuedTeamsToDelete.Count}");
            }

            Console.Write("Do you want to proceed (y/n): ");
            var answer = await Program.GetInputManager().ReadLine();
            if (string.Compare(answer, "y", StringComparison.InvariantCultureIgnoreCase) != 0)
            {
                return;
            }


            var rqs = new List<KeeperApiCommand>();
            rqs.AddRange(rolesToDelete.Keys.Select(x => new EnterpriseRoleDeleteCommand {RoleId = x}));
            rqs.AddRange(teamsToDelete.Select(x => new TeamDeleteCommand {TeamUid = x}));
            rqs.AddRange(usersToDelete.Select(x => new EnterpriseUserDeleteCommand {EnterpriseUserId = x}));
            rqs.AddRange(nodesToDelete.Reverse().Select(x => new EnterpriseNodeDeleteCommand {NodeId = x}));
            rqs.AddRange(queuedTeamsToDelete.Keys.Select(x => new TeamDeleteCommand {TeamUid = x}));

            try
            {
                while (rqs.Count > 0)
                {
                    var chunk = rqs.Take(99).ToList();
                    rqs.RemoveRange(0, chunk.Count);

                    var execRq = new ExecuteCommand
                    {
                        Requests = chunk
                    };
                    var execRs = await Enterprise.Auth.ExecuteAuthCommand<ExecuteCommand, ExecuteResponse>(execRq);
                    var lastRs = execRs.Results.Last();
                    if (!lastRs.IsSuccess)
                    {
                        var cmd = chunk[execRs.Results.Count - 1];
                        var objectType = "Unknown";
                        var objectName = "";
                        switch (cmd)
                        {
                            case EnterpriseRoleDeleteCommand rd:
                                objectType = "Role";
                                if (rolesToDelete.TryGetValue(rd.RoleId, out var r))
                                {
                                    objectName = r.RoleId.ToString();
                                }

                                break;
                            case TeamDeleteCommand td:
                                if (Enterprise.TryGetTeam(td.TeamUid, out var t))
                                {
                                    objectType = "Team";
                                    objectName = t.Name;
                                }
                                else
                                {
                                    objectType = "Queued Team";
                                    if (queuedTeamsToDelete.TryGetValue(td.TeamUid, out var qt))
                                    {
                                        objectType = qt.Name;
                                    }
                                }

                                break;
                            case EnterpriseUserDeleteCommand ud:
                                objectType = "User";
                                if (Enterprise.TryGetUserById(ud.EnterpriseUserId, out var u))
                                {
                                    objectName = u.Email;
                                }

                                break;
                            case EnterpriseNodeDeleteCommand nd:
                                objectType = "Node";
                                if (Enterprise.TryGetNode(nd.NodeId, out var n))
                                {
                                    objectName = n.DisplayName;
                                }

                                break;
                        }

                        throw new Exception($"Failed to remove {objectType}: \"{objectName}\". ({lastRs.resultCode}): {lastRs.message}");
                    }

                    if (rqs.Count > 0)
                    {
                        Console.WriteLine($"Remaining {rqs.Count} object(s) to remove");
                        await Task.Delay(TimeSpan.FromSeconds(5));
                    }
                }
            }
            finally
            {
                await Enterprise.PopulateEnterprise();
            }
        }

        private async Task DeleteTeams(ActivateOptions options)
        {
            var pattern = new Regex(options.Pattern, RegexOptions.None);
            var toDelete = new HashSet<string>();
            toDelete.UnionWith(
                Enterprise.Teams
                    .Where(x => pattern.IsMatch(x.Name))
                    .Select(x => x.Uid));
            if (toDelete.Count == 0)
            {
                return;
            }

            Console.WriteLine($"{toDelete.Count} team(s) to be removed.");

            if (!options.Force)
            {
                Console.Write("Do you want to proceed (y/n): ");
                var answer = await Program.GetInputManager().ReadLine();
                if (string.Compare(answer, "y", StringComparison.InvariantCultureIgnoreCase) != 0)
                {
                    return;
                }
            }

            try
            {
                while (toDelete.Count > 0)
                {
                    var chunk = toDelete.Take(99).ToArray();
                    toDelete.ExceptWith(chunk);
                    var rqs = chunk
                        .Select(x => new TeamDeleteCommand {TeamUid = x})
                        .Cast<KeeperApiCommand>()
                        .ToList();
                    var executeRq = new ExecuteCommand
                    {
                        Requests = rqs
                    };
                    var executeRs = await Enterprise.Auth.ExecuteAuthCommand<ExecuteCommand, ExecuteResponse>(executeRq);
                    var lastRs = executeRs.Results.Last();
                    if (!lastRs.IsSuccess)
                    {
                        throw new KeeperPostLoginErrors(lastRs.resultCode, lastRs.message);
                    }
                    if (rqs.Count > 0)
                    {
                        Console.WriteLine($"Remaining {rqs.Count} team(s) to remove");
                        await Task.Delay(TimeSpan.FromSeconds(5));
                    }
                }
            }
            finally
            {
                await Enterprise.PopulateEnterprise();
            }
        }

        private async Task DeleteUsers(ActivateOptions options)
        {
            var pattern = new Regex(options.Pattern, RegexOptions.None);
            var toDelete = new HashSet<long>();
            toDelete.UnionWith(
                Enterprise.Users
                    .Where(x => pattern.IsMatch(x.Email))
                    .Select(x => x.Id));
            if (toDelete.Count == 0)
            {
                return;
            }

            Console.WriteLine($"{toDelete.Count} user(s) to be removed.");

            if (!options.Force)
            {
                Console.Write("Do you want to proceed (y/n): ");
                var answer = await Program.GetInputManager().ReadLine();
                if (string.Compare(answer, "y", StringComparison.InvariantCultureIgnoreCase) != 0)
                {
                    return;
                }
            }

            try
            {
                while (toDelete.Count > 0)
                {
                    var chunk = toDelete.Take(99).ToArray();
                    toDelete.ExceptWith(chunk);
                    var rqs = chunk
                        .Select(x => new EnterpriseUserDeleteCommand() {EnterpriseUserId = x})
                        .Cast<KeeperApiCommand>()
                        .ToList();
                    var executeRq = new ExecuteCommand
                    {
                        Requests = rqs
                    };
                    var executeRs = await Enterprise.Auth.ExecuteAuthCommand<ExecuteCommand, ExecuteResponse>(executeRq);
                    var lastRs = executeRs.Results.Last();
                    if (!lastRs.IsSuccess)
                    {
                        throw new KeeperPostLoginErrors(lastRs.resultCode, lastRs.message);
                    }
                    if (rqs.Count > 0)
                    {
                        Console.WriteLine($"Remaining {rqs.Count} user(s) to remove");
                        await Task.Delay(TimeSpan.FromSeconds(5));
                    }
                }
            }
            finally
            {
                await Enterprise.PopulateEnterprise();
            }
        }

        private async Task Activate(ActivateOptions options)
        {
            _ = new Regex(options.Pattern, RegexOptions.None);
            var command = new VerificationCodeCommand
            {
                EnterpriseName = Enterprise.EnterpriseName,
                EnterpriseId = (int) (Enterprise.RootNode.Id >> 32),
                UsernamePattern = options.Pattern
            };
            var rs = await Enterprise.Auth.ExecuteAuthCommand<VerificationCodeCommand, VerificationCodeResponse>(command);
            if (rs.Users == null || rs.Users.Length == 0)
            {
                Console.WriteLine($"No pending users are found according to criteria: {options.Pattern}");
                return;
            }

            Console.WriteLine($"{rs.Users.Length} user(s) to activate.");

            Console.Write("Enterprise user's password (this will be the user's master password if the account does not exist): ");
            var password = await Program.GetInputManager().ReadLine(new ReadLineParameters
            {
                IsHistory = false,
                IsSecured = true
            });

            if (!options.Force)
            {
                Console.Write("Do you want to proceed (y/n): ");
                var answer = await Program.GetInputManager().ReadLine();
                if (string.Compare(answer, "y", StringComparison.InvariantCultureIgnoreCase) != 0)
                {
                    return;
                }
            }

            const int authIterations = 100000;
            try
            {
                foreach (var code in rs.Users)
                {
                    if (Enterprise.TryGetUserByEmail(code.Username, out var user))
                    {
                        if (user.UserStatus == UserStatus.Inactive)
                        {
                            var salt = CryptoUtils.GetRandomBytes(16);
                            var dataKey = CryptoUtils.GenerateEncryptionKey();
                            CryptoUtils.GenerateRsaKey(out var rsaPrivateKey, out var rsaPublicKey);
                            CryptoUtils.GenerateEcKey(out var ecPrivateKey, out var ecPublicKey);
                            var registerRq = new CreateUserRequest
                            {
                                Username = code.Username,
                                ClientVersion = Enterprise.Auth.Endpoint.ClientVersion,
                                AuthVerifier = ByteString.CopyFrom(CryptoUtils.CreateAuthVerifier(password, salt, authIterations)),
                                EncryptionParams = ByteString.CopyFrom(CryptoUtils.CreateEncryptionParams(password, salt, authIterations, dataKey)),
                                RsaPublicKey = ByteString.CopyFrom(rsaPublicKey),
                                RsaEncryptedPrivateKey = ByteString.CopyFrom(CryptoUtils.EncryptAesV1(rsaPrivateKey, dataKey)),
                                EccPublicKey = ByteString.CopyFrom(CryptoUtils.UnloadEcPublicKey(ecPublicKey)),
                                EccEncryptedPrivateKey = ByteString.CopyFrom(CryptoUtils.EncryptAesV2(CryptoUtils.UnloadEcPrivateKey(ecPrivateKey), dataKey)),
                                EncryptedDeviceToken = ByteString.CopyFrom(Enterprise.Auth.DeviceToken),
                                EncryptedClientKey = ByteString.CopyFrom(CryptoUtils.EncryptAesV1(CryptoUtils.GenerateEncryptionKey(), dataKey)),
                                VerificationCode = code.Code,
                            };

                            try
                            {
                                Console.Write($"{code.Username}: ");
                                await Enterprise.Auth.Endpoint.ExecuteRest("authentication/request_create_user", new ApiRequestPayload {Payload = registerRq.ToByteString()});
                                Console.WriteLine("Created.");
                            }
                            catch (Exception e)
                            {
                                Console.WriteLine($"Failed: {e.Message}");
                            }
                        }
                    }
                }
            }
            finally
            {
                await Enterprise.PopulateEnterprise();
            }
        }

        public override string GetPrompt()
        {
            return Enterprise.EnterpriseName;
        }

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            if (Enterprise.Auth is IDisposable disp)
            {
                disp.Dispose();
            }
        }
    }

    public class NodeOptions
    {
        [Value(0, Required = true, MetaName = "Node", HelpText = "Node Name or ID")]
        public string Node { get; set; }
    }

    public class ListPatternOptions
    {
        [Value(0, Required = false, MetaName = "Pattern", HelpText = "Search pattern.")]
        public string Pattern { get; set; }
    }

    public class ActivateOptions
    {
        [Option("force", Required = false, HelpText = "Skips confirmations.")]
        public bool Force { get; set; }

        [Value(0, Required = true, MetaName = "Pattern", HelpText = "Search pattern.")]
        public string Pattern { get; set; }
    }

    public class UserOptions : ListPatternOptions
    {
        [Option("pending", Required = false, HelpText = "Print pending users only.")]
        public bool Pending { get; set; }
    }

    [DataContract]
    public class EnterpriseUserDeleteCommand : AuthenticatedCommand
    {
        public EnterpriseUserDeleteCommand() : base("enterprise_user_delete")
        {
        }

        [DataMember(Name = "enterprise_user_id")]
        public long EnterpriseUserId { get; set; }
    }

    [DataContract]
    public class EnterpriseRoleDeleteCommand : AuthenticatedCommand
    {
        public EnterpriseRoleDeleteCommand() : base("role_delete")
        {
        }

        [DataMember(Name = "role_id")]
        public long RoleId { get; set; }
    }

    [DataContract]
    public class EnterpriseNodeDeleteCommand : AuthenticatedCommand
    {
        public EnterpriseNodeDeleteCommand() : base("node_delete")
        {
        }

        [DataMember(Name = "node_id")]
        public long NodeId { get; set; }
    }


    [DataContract]
    public class VerificationCodeCommand : AuthenticatedCommand
    {
        public VerificationCodeCommand() : base("get_enterprise_verification_code")
        {
        }

        [DataMember(Name = "enterprise_id")]
        public int EnterpriseId { get; set; }

        [DataMember(Name = "enterprise_name")]
        public string EnterpriseName { get; set; }

        [DataMember(Name = "username_pattern")]
        public string UsernamePattern { get; set; }
    }

    [DataContract]
    public class UserCode
    {
        [DataMember(Name = "username")]
        public string Username { get; internal set; }

        [DataMember(Name = "code")]
        public string Code { get; internal set; }
    }

    [DataContract]
    public class VerificationCodeResponse : KeeperApiResponse
    {
        [DataMember(Name = "users")]
        public UserCode[] Users { get; internal set; }
    }
}
