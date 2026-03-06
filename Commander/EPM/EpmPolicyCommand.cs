using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Cli;
using CommandLine;
using Google.Protobuf;
using KeeperSecurity.Authentication;
using KeeperSecurity.Plugins.EPM;
using KeeperSecurity.Utils;
using PEDMProto = PEDM;

namespace Commander.EPM
{
    internal class EpmPolicyCommand : EpmCommandBase
    {
        public EpmPolicyCommand(IEnterpriseContext context) : base(context)
        {
        }

        public async Task ExecuteAsync(EpmPolicyOptions options)
        {
            if (options == null)
                return;
            if (!await EnsurePluginAsync())
                return;

            var command = string.IsNullOrEmpty(options.Command) ? "list" : options.Command.Trim().ToLowerInvariant();

            switch (command)
            {
                case "list":
                    ListPolicies();
                    break;

                case "view":
                    ViewPolicy(options.PolicyUid);
                    break;

                case "add":
                    await AddPolicyAsync(options);
                    break;

                case "update":
                    await UpdatePolicyAsync(options);
                    break;

                case "remove":
                case "delete":
                    await RemovePolicyAsync(options.PolicyUid);
                    break;

                case "agents":
                    await ListPolicyAgentsAsync(options);
                    break;

                case "assign":
                    await AssignPolicyCollectionsAsync(options);
                    break;

                default:
                    Console.WriteLine($"Unsupported command '{command}'. Available commands: list, view, add, update, remove, agents, assign");
                    break;
            }
        }

        private void ListPolicies()
        {
            var policies = Plugin.Policies.GetAll().ToList();
            if (policies.Count == 0)
            {
                Console.WriteLine("No policies found.");
            }
            else
            {
                var tab = new Tabulate(9);
                tab.AddHeader("Policy UID", "Policy Name", "Policy Type", "Status", "Controls", "Users", "Machines", "Applications", "Collections");
                foreach (var pol in policies.OrderBy(x => x.PolicyUid))
                {
                    var policyInfo = ParsePolicyData(pol, Plugin);
                    
                    string status = "off";
                    if (!pol.Disabled)
                    {
                        try
                        {
                            if (pol.Data != null)
                            {
                                status = pol.Data.Status ?? "on";
                            }
                            else if (pol.PolicyData != null && pol.PolicyData.Length > 0)
                            {
                                var data = JsonUtils.ParseJson<Dictionary<string, object>>(pol.PolicyData);
                                if (data.TryGetValue("Status", out var statusObj))
                                {
                                    status = statusObj?.ToString() ?? "off";
                                }
                                else
                                {
                                    status = "on";
                                }
                            }
                            else
                            {
                                status = "on";
                            }
                        }
                        catch (Exception)
                        {
                            status = "on";
                        }
                    }
                    
                    var controls = string.Join("\n", policyInfo.Controls).Trim();
                    var users = policyInfo.Users;
                    var machines = policyInfo.Machines;
                    var applications = policyInfo.Applications;
                    var collections = policyInfo.Collections;
                    tab.AddRow(pol.PolicyUid, policyInfo.Name ?? "", policyInfo.Type ?? "", status, controls, users, machines, applications, collections);
                }
                tab.Dump();
            }
        }

        private void ViewPolicy(string policyUid)
        {
            var uid = policyUid?.Trim();
            if (string.IsNullOrEmpty(uid))
            {
                Console.WriteLine("Policy UID or name is required for 'view' command.");
                return;
            }

            var policy = Plugin.Policies.GetEntity(uid);
            if (policy == null)
            {
                var matches = Plugin.Policies.GetAll()
                    .Select(p => new { Policy = p, Info = ParsePolicyData(p, Plugin) })
                    .Where(x => !string.IsNullOrEmpty(x.Info.Name) &&
                                string.Equals(x.Info.Name, uid, StringComparison.OrdinalIgnoreCase))
                    .Select(x => x.Policy)
                    .ToList();

                if (matches.Count > 1)
                {
                    Console.WriteLine($"Multiple policies match name \"{uid}\". Please specify Policy UID.");
                    return;
                }

                policy = matches.FirstOrDefault();
            }

            if (policy == null)
            {
                Console.WriteLine($"Policy '{uid}' not found.");
                return;
            }

            var policyInfo = ParsePolicyData(policy, Plugin);
            
            Console.WriteLine($"Policy: {policyInfo.Name}");
            Console.WriteLine($"  UID: {policy.PolicyUid}");
            Console.WriteLine($"  Type: {policyInfo.Type}");
            Console.WriteLine($"  Disabled: {policy.Disabled}");
            
            if (policy.Data != null)
            {
                Console.WriteLine($"  Status: {policy.Data.Status ?? "off"}");
                
                if (!string.IsNullOrEmpty(policy.Data.PolicyId))
                {
                    Console.WriteLine($"  Policy ID: {policy.Data.PolicyId}");
                }
                
                if (!string.IsNullOrEmpty(policy.Data.NotificationMessage))
                {
                    Console.WriteLine($"  Notification Message: {policy.Data.NotificationMessage}");
                }
                
                if (policy.Data.NotificationRequiresAcknowledge)
                {
                    Console.WriteLine($"  Notification Requires Acknowledge: {policy.Data.NotificationRequiresAcknowledge}");
                }
                
                if (policy.Data.RiskLevel > 0)
                {
                    Console.WriteLine($"  Risk Level: {policy.Data.RiskLevel}");
                }
                
                if (!string.IsNullOrEmpty(policy.Data.Operator))
                {
                    Console.WriteLine($"  Operator: {policy.Data.Operator}");
                }
                
                if (policy.Data.Rules != null && policy.Data.Rules.Count > 0)
                {
                    Console.WriteLine($"  Rules ({policy.Data.Rules.Count}):");
                    foreach (var rule in policy.Data.Rules)
                    {
                        Console.WriteLine($"    - {rule.RuleName}: {rule.Expression} ({rule.RuleExpressionType})");
                        if (!string.IsNullOrEmpty(rule.ErrorMessage))
                        {
                            Console.WriteLine($"      Error: {rule.ErrorMessage}");
                        }
                    }
                }
                
                if (policy.Data.Actions != null)
                {
                    if (policy.Data.Actions.OnSuccess != null && policy.Data.Actions.OnSuccess.Controls != null && policy.Data.Actions.OnSuccess.Controls.Count > 0)
                    {
                        Console.WriteLine($"  On Success Controls: {string.Join(", ", policy.Data.Actions.OnSuccess.Controls)}");
                    }
                    if (policy.Data.Actions.OnFailure != null && !string.IsNullOrEmpty(policy.Data.Actions.OnFailure.Command))
                    {
                        Console.WriteLine($"  On Failure Command: {policy.Data.Actions.OnFailure.Command}");
                    }
                }
            }
            
            if (policyInfo.Controls.Count > 0)
            {
                Console.WriteLine($"  Controls: {string.Join(", ", policyInfo.Controls)}");
            }
            
            if (!string.IsNullOrEmpty(policyInfo.Users))
            {
                Console.WriteLine($"  Users: {policyInfo.Users}");
            }
            if (!string.IsNullOrEmpty(policyInfo.Machines))
            {
                Console.WriteLine($"  Machines: {policyInfo.Machines}");
            }
            if (!string.IsNullOrEmpty(policyInfo.Applications))
            {
                Console.WriteLine($"  Applications: {policyInfo.Applications}");
            }
            if (!string.IsNullOrEmpty(policyInfo.Collections))
            {
                Console.WriteLine($"  Collections: {policyInfo.Collections}");
            }
            
            if (policy.Data != null)
            {
                if (policy.Data.DayCheck != null && policy.Data.DayCheck.Count > 0)
                {
                    var dayNames = new[] { "Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday" };
                    var days = policy.Data.DayCheck.Select(d => dayNames[d % 7]).ToList();
                    Console.WriteLine($"  Allowed Days: {string.Join(", ", days)}");
                }
                
                if (policy.Data.DateCheck != null && policy.Data.DateCheck.Count > 0)
                {
                    Console.WriteLine($"  Date Ranges ({policy.Data.DateCheck.Count}):");
                    foreach (var dateRange in policy.Data.DateCheck)
                    {
                        var start = DateTimeOffset.FromUnixTimeMilliseconds(dateRange.StartDate).ToString("yyyy-MM-dd");
                        var end = DateTimeOffset.FromUnixTimeMilliseconds(dateRange.EndDate).ToString("yyyy-MM-dd");
                        Console.WriteLine($"    - {start} to {end}");
                    }
                }
                
                if (policy.Data.TimeCheck != null && policy.Data.TimeCheck.Count > 0)
                {
                    Console.WriteLine($"  Time Ranges ({policy.Data.TimeCheck.Count}):");
                    foreach (var timeRange in policy.Data.TimeCheck)
                    {
                        Console.WriteLine($"    - {timeRange.StartTime} to {timeRange.EndTime}");
                    }
                }
                
                if (policy.Data.CertificationCheck != null && policy.Data.CertificationCheck.Count > 0)
                {
                    Console.WriteLine($"  Certification Checks: {string.Join(", ", policy.Data.CertificationCheck)}");
                }
                
                if (policy.Data.Extension != null && policy.Data.Extension.Count > 0)
                {
                    Console.WriteLine($"  Extensions ({policy.Data.Extension.Count} custom fields)");
                }
            }
            
            Console.WriteLine($"  Created: {DateTimeOffset.FromUnixTimeMilliseconds(policy.Created):yyyy-MM-dd HH:mm:ss}");
            Console.WriteLine($"  Updated: {DateTimeOffset.FromUnixTimeMilliseconds(policy.Updated):yyyy-MM-dd HH:mm:ss}");
        }


        private static string ReadJsonText(string json, string filePath)
        {
            if (!string.IsNullOrEmpty(json))
            {
                return json;
            }

            if (!string.IsNullOrEmpty(filePath))
            {
                return File.ReadAllText(filePath);
            }

            return null;
        }

        private async Task AddPolicyAsync(EpmPolicyOptions options)
        {
            if (options == null)
                return;

            var plainJson = ReadJsonText(options.PlainDataJson, options.PlainDataFile);
            var policyJson = ReadJsonText(options.PolicyDataJson, options.PolicyDataFile);

            if (string.IsNullOrEmpty(plainJson) || string.IsNullOrEmpty(policyJson))
            {
                Console.WriteLine("Both --plain and --data (or --plain-file and --data-file) are required for 'add' command.");
                return;
            }

            var addStatus = await Plugin.ModifyPolicies(
                addPolicies: new[]
                {
                    new EpmPlugin.PolicyInput
                    {
                        PolicyUid = options.NewPolicyUid,
                        PlainDataJson = plainJson,
                        PolicyDataJson = policyJson
                    }
                },
                updatePolicies: null,
                removePolicies: null);

            if (addStatus.AddErrors?.Count > 0)
            {
                foreach (var error in addStatus.AddErrors)
                {
                    if (!error.Success)
                    {
                        Console.WriteLine($"Failed to add policy \"{error.EntityUid}\": {error.Message}");
                    }
                }
                return;
            }

            Console.WriteLine("Policy added.");
            if (addStatus.Add?.Count > 0 || addStatus.Update?.Count > 0 || addStatus.Remove?.Count > 0)
            {
                PrintModifyStatus(addStatus);
            }

            await Plugin.SyncDown();
        }

        private async Task UpdatePolicyAsync(EpmPolicyOptions options)
        {
            if (options == null)
                return;

            var policyUidValue = options.PolicyUid?.Trim();
            if (string.IsNullOrEmpty(policyUidValue))
            {
                Console.WriteLine("Policy UID or name is required for 'update' command.");
                return;
            }

            var policy = ResolvePolicy(policyUidValue);
            if (policy == null)
            {
                Console.WriteLine($"Policy \"{policyUidValue}\" does not exist");
                return;
            }

            var plainJson = ReadJsonText(options.PlainDataJson, options.PlainDataFile);
            var policyJson = ReadJsonText(options.PolicyDataJson, options.PolicyDataFile);

            if (string.IsNullOrEmpty(plainJson) && string.IsNullOrEmpty(policyJson))
            {
                Console.WriteLine("At least one of --plain/--plain-file or --data/--data-file is required for 'update' command.");
                return;
            }

            var updateStatus = await Plugin.ModifyPolicies(
                addPolicies: null,
                updatePolicies: new[]
                {
                    new EpmPlugin.PolicyInput
                    {
                        PolicyUid = policy.PolicyUid,
                        PlainDataJson = plainJson,
                        PolicyDataJson = policyJson
                    }
                },
                removePolicies: null);

            if (updateStatus.UpdateErrors?.Count > 0)
            {
                foreach (var error in updateStatus.UpdateErrors)
                {
                    if (!error.Success)
                    {
                        Console.WriteLine($"Failed to update policy \"{error.EntityUid}\": {error.Message}");
                    }
                }
                return;
            }

            Console.WriteLine($"Policy '{policy.PolicyUid}' updated.");
            if (updateStatus.Add?.Count > 0 || updateStatus.Update?.Count > 0 || updateStatus.Remove?.Count > 0)
            {
                PrintModifyStatus(updateStatus);
            }

            await Plugin.SyncDown();
        }

        private async Task RemovePolicyAsync(string identifier)
        {
            var uid = identifier?.Trim();
            if (string.IsNullOrEmpty(uid))
            {
                Console.WriteLine("Policy UID or name is required for 'remove' command.");
                return;
            }

            var policy = ResolvePolicy(uid);
            if (policy == null)
            {
                Console.WriteLine($"Policy \"{uid}\" does not exist");
                return;
            }

            var removeStatus = await Plugin.ModifyPolicies(
                addPolicies: null,
                updatePolicies: null,
                removePolicies: new[] { policy.PolicyUid });

            if (removeStatus.RemoveErrors?.Count > 0)
            {
                foreach (var error in removeStatus.RemoveErrors)
                {
                    if (!error.Success)
                    {
                        Console.WriteLine($"Failed to remove policy \"{error.EntityUid}\": {error.Message}");
                    }
                }
                return;
            }

            Console.WriteLine($"Policy '{policy.PolicyUid}' removed.");
            if (removeStatus.Add?.Count > 0 || removeStatus.Update?.Count > 0 || removeStatus.Remove?.Count > 0)
            {
                PrintModifyStatus(removeStatus);
            }

            await Plugin.SyncDown();
        }

        private async Task ListPolicyAgentsAsync(EpmPolicyOptions options)
        {
            if (options == null)
                return;

            var policyIdentifiers = options.PolicyUid?.Trim();
            if (string.IsNullOrEmpty(policyIdentifiers))
            {
                Console.WriteLine("Policy UID or name is required for 'agents' command.");
                return;
            }

            var policyUids = new List<string>();
            var identifiers = policyIdentifiers.Split(new[] { ' ', ',' }, StringSplitOptions.RemoveEmptyEntries);
            
            foreach (var identifier in identifiers)
            {
                var policy = ResolvePolicy(identifier);
                if (policy == null)
                {
                    Console.WriteLine($"Policy '{identifier}' not found.");
                    continue;
                }
                policyUids.Add(policy.PolicyUid);
            }

            if (policyUids.Count == 0)
            {
                return;
            }

            var auth = Context.Enterprise?.Auth;
            if (auth == null)
            {
                Console.WriteLine("Authentication context is not available.");
                return;
            }

            try
            {
                var rq = new PEDMProto.PolicyAgentRequest();
                foreach (var policyUid in policyUids)
                {
                    rq.PolicyUid.Add(ByteString.CopyFrom(policyUid.Base64UrlDecode()));
                }
                rq.SummaryOnly = false;

                var rs = await auth.ExecuteRouter<PEDMProto.PolicyAgentResponse>("pedm/get_policy_agents", rq);
                if (rs != null)
                {
                    var tab = new Tabulate(4);
                    tab.AddHeader("Key", "UID", "Name", "Status");

                    foreach (var policyUid in policyUids)
                    {
                        var policy = Plugin.Policies.GetEntity(policyUid);
                        if (policy != null)
                        {
                            var policyInfo = ParsePolicyData(policy, Plugin);
                            string status = policy.Disabled ? "off" : (policy.Data?.Status ?? "on");
                            tab.AddRow("Policy", policyUid, policyInfo.Name, status);
                        }
                    }

                    var activeAgentUids = new HashSet<string>();
                    foreach (var agentUidBytes in rs.AgentUid)
                    {
                        activeAgentUids.Add(agentUidBytes.ToByteArray().Base64UrlEncode());
                    }

                    foreach (var agentUid in activeAgentUids)
                    {
                        var agent = Plugin.Agents.GetEntity(agentUid);
                        string machineName = "";
                        string status = "";
                        if (agent != null)
                        {
                            machineName = agent.MachineId ?? "";
                            status = agent.Disabled ? "off" : "on";
                        }
                        tab.AddRow("Agent", agentUid, machineName, status);
                    }

                    tab.Dump();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error getting policy agents: {ex.Message}");
            }
        }

        private async Task AssignPolicyCollectionsAsync(EpmPolicyOptions options)
        {
            if (options == null)
                return;

            var policyIdentifiers = options.PolicyUid?.Trim();
            if (string.IsNullOrEmpty(policyIdentifiers))
            {
                Console.WriteLine("Policy UID or name is required for 'assign' command.");
                return;
            }

            var identifiers = policyIdentifiers.Split(new[] { ' ', ',' }, StringSplitOptions.RemoveEmptyEntries);
            var policies = new List<EpmPolicy>();
            
            foreach (var identifier in identifiers)
            {
                var policy = ResolvePolicy(identifier);
                if (policy == null)
                {
                    Console.WriteLine($"Policy '{identifier}' not found.");
                    continue;
                }
                policies.Add(policy);
            }

            if (policies.Count == 0)
            {
                return;
            }

            var collectionUids = new List<byte[]>();
            if (options.CollectionUids != null && options.CollectionUids.Count > 0)
            {
                foreach (var collUid in options.CollectionUids)
                {
                    if (collUid == "*" || collUid == "all")
                    {
                        var allAgentsUid = Plugin.AllAgentsCollectionUid;
                        if (!string.IsNullOrEmpty(allAgentsUid))
                        {
                            try
                            {
                                collectionUids.Add(allAgentsUid.Base64UrlDecode());
                            }
                            catch (Exception)
                            {
                                Console.WriteLine($"Invalid all-agents collection UID. Skipped.");
                            }
                        }
                    }
                    else
                    {
                        try
                        {
                            var collUidBytes = collUid.Base64UrlDecode();
                            if (collUidBytes.Length == 16)
                            {
                                collectionUids.Add(collUidBytes);
                            }
                            else
                            {
                                Console.WriteLine($"Invalid collection UID: {collUid}. Skipped.");
                            }
                        }
                        catch (Exception)
                        {
                            Console.WriteLine($"Invalid collection UID: {collUid}. Skipped.");
                        }
                    }
                }
            }

            if (collectionUids.Count == 0)
            {
                Console.WriteLine("No collections to assign.");
                return;
            }

            var setLinks = new List<CollectionLink>();
            foreach (var policy in policies)
            {
                foreach (var collUidBytes in collectionUids)
                {
                    setLinks.Add(new CollectionLink
                    {
                        CollectionUid = collUidBytes.Base64UrlEncode(),
                        LinkUid = policy.PolicyUid,
                        LinkType = PEDMProto.CollectionLinkType.CltPolicy
                    });
                }
            }

            var status = await Plugin.SetCollectionLinks(setLinks: setLinks, unsetLinks: null);
            
            if (status.AddErrors?.Count > 0)
            {
                foreach (var error in status.AddErrors)
                {
                    if (!error.Success)
                    {
                        Console.WriteLine($"Failed to add to policy: {error.Message}");
                    }
                }
            }

            if (status.RemoveErrors?.Count > 0)
            {
                foreach (var error in status.RemoveErrors)
                {
                    if (!error.Success)
                    {
                        Console.WriteLine($"Failed to remove from policy: {error.Message}");
                    }
                }
            }

            if (status.Add?.Count > 0 || status.Update?.Count > 0 || status.Remove?.Count > 0)
            {
                PrintModifyStatus(status);
            }

            await Plugin.SyncDown();
        }

    }

    internal class EpmPolicyOptions : EnterpriseGenericOptions
    {
        [Value(0, Required = false, HelpText = "Command: list, view, add, update, remove")]
        public string Command { get; set; }

        [Value(1, Required = false, HelpText = "Policy UID or name (for view, update, remove)")]
        public string PolicyUid { get; set; }

        [Option("uid", Required = false, HelpText = "New Policy UID (for add). If omitted, server will accept generated UID.")]
        public string NewPolicyUid { get; set; }

        [Option("plain", Required = false, HelpText = "Plain policy JSON (template/admin data)")]
        public string PlainDataJson { get; set; }

        [Option("plain-file", Required = false, HelpText = "Path to file containing plain policy JSON")]
        public string PlainDataFile { get; set; }

        [Option("data", Required = false, HelpText = "Policy JSON data to encrypt")]
        public string PolicyDataJson { get; set; }

        [Option("data-file", Required = false, HelpText = "Path to file containing policy JSON data to encrypt")]
        public string PolicyDataFile { get; set; }

        [Option("collection", Required = false, HelpText = "Collection UID(s) to assign to policy (for assign command). Use '*' or 'all' for all agents.")]
        public IList<string> CollectionUids { get; set; }
    }
}

