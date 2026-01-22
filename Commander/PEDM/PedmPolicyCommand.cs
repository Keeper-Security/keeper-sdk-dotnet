using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;
using Cli;
using CommandLine;
using KeeperSecurity.Plugins.PEDM;
using KeeperSecurity.Utils;

namespace Commander.PEDM
{
    internal class PedmPolicyCommand : PedmCommandBase
    {
        public PedmPolicyCommand(IEnterpriseContext context) : base(context)
        {
        }

        public async Task ExecuteAsync(PedmPolicyOptions options)
        {
            if (!await EnsurePluginAsync())
                return;

            if (string.IsNullOrEmpty(options.Command))
            {
                options.Command = "list";
            }

            options.Command = options.Command.ToLowerInvariant();

            switch (options.Command)
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

                default:
                    Console.WriteLine($"Unsupported command '{options.Command}'. Available commands: list, view, add, update, remove");
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
                        catch
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
            if (string.IsNullOrEmpty(policyUid))
            {
                Console.WriteLine("Policy UID or name is required for 'view' command.");
                return;
            }

            var policy = Plugin.Policies.GetEntity(policyUid);
            if (policy == null)
            {
                var matches = Plugin.Policies.GetAll()
                    .Select(p => new { Policy = p, Info = ParsePolicyData(p, Plugin) })
                    .Where(x => !string.IsNullOrEmpty(x.Info.Name) &&
                                string.Equals(x.Info.Name, policyUid, StringComparison.OrdinalIgnoreCase))
                    .Select(x => x.Policy)
                    .ToList();

                if (matches.Count > 1)
                {
                    Console.WriteLine($"Multiple policies match name \"{policyUid}\". Please specify Policy UID.");
                    return;
                }

                policy = matches.FirstOrDefault();
            }

            if (policy == null)
            {
                Console.WriteLine($"Policy '{policyUid}' not found.");
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

        private PedmPolicy ResolvePolicy(string identifier)
        {
            if (string.IsNullOrEmpty(identifier))
            {
                return null;
            }

            var policy = Plugin.Policies.GetEntity(identifier);
            if (policy != null)
            {
                return policy;
            }

            var matches = Plugin.Policies.GetAll()
                .Select(p => new { Policy = p, Info = ParsePolicyData(p, Plugin) })
                .Where(x => !string.IsNullOrEmpty(x.Info.Name) &&
                            string.Equals(x.Info.Name, identifier, StringComparison.OrdinalIgnoreCase))
                .Select(x => x.Policy)
                .ToList();

            if (matches.Count == 1)
            {
                return matches[0];
            }

            if (matches.Count > 1)
            {
                Console.WriteLine($"Multiple policies match name \"{identifier}\". Please specify Policy UID.");
            }

            return null;
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

        private async Task AddPolicyAsync(PedmPolicyOptions options)
        {
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
                    new PedmPlugin.PolicyInput
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

        private async Task UpdatePolicyAsync(PedmPolicyOptions options)
        {
            if (string.IsNullOrEmpty(options.PolicyUid))
            {
                Console.WriteLine("Policy UID or name is required for 'update' command.");
                return;
            }

            var policy = ResolvePolicy(options.PolicyUid);
            if (policy == null)
            {
                Console.WriteLine($"Policy \"{options.PolicyUid}\" does not exist");
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
                    new PedmPlugin.PolicyInput
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
            if (string.IsNullOrEmpty(identifier))
            {
                Console.WriteLine("Policy UID or name is required for 'remove' command.");
                return;
            }

            var policy = ResolvePolicy(identifier);
            if (policy == null)
            {
                Console.WriteLine($"Policy \"{identifier}\" does not exist");
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

        private static (string Name, string Type, List<string> Controls, string Users, string Machines, string Applications, string Collections) ParsePolicyData(PedmPolicy policy, PedmPlugin plugin)
        {
            string name = "";
            string type = "";
            var controls = new List<string>();
            string users = "";
            string machines = "";
            string applications = "";
            string collections = "";

            var data = policy.Data;
            if (data == null)
            {
                return (name, type, controls, users, machines, applications, collections);
            }

            name = data.PolicyName ?? "";
            
            type = data.PolicyType ?? "";
            
            if (data.Actions?.OnSuccess?.Controls != null)
            {
                foreach (var control in data.Actions.OnSuccess.Controls)
                {
                    var controlStr = control?.ToUpperInvariant();
                    if (!string.IsNullOrEmpty(controlStr))
                    {
                        // Map control names to display format
                        if (controlStr == "APPROVAL" || controlStr.Contains("APPROVAL"))
                            controls.Add("APPROVAL");
                        else if (controlStr == "JUSTIFY" || controlStr.Contains("JUSTIFY"))
                            controls.Add("JUSTIFY");
                        else if (controlStr == "MFA" || controlStr.Contains("MFA"))
                            controls.Add("MFA");
                        else
                            controls.Add(controlStr);
                    }
                }
            }
            
            if (data.UserCheck != null && data.UserCheck.Count > 0)
            {
                users = string.Join(", ", data.UserCheck);
            }
            
            if (data.MachineCheck != null && data.MachineCheck.Count > 0)
            {
                machines = string.Join(", ", data.MachineCheck);
            }
            
            if (data.ApplicationCheck != null && data.ApplicationCheck.Count > 0)
            {
                applications = string.Join(", ", data.ApplicationCheck);
            }
            
            try
            {
                var storageField = typeof(PedmPlugin).GetField("_storage", BindingFlags.NonPublic | BindingFlags.Instance);
                if (storageField != null)
                {
                    var storage = storageField.GetValue(plugin);
                    var collectionLinksProperty = storage?.GetType().GetProperty("CollectionLinks");
                    if (collectionLinksProperty != null)
                    {
                        var collectionLinksStorage = collectionLinksProperty.GetValue(storage);
                        var getLinksForObjectMethod = collectionLinksStorage?.GetType().GetMethod("GetLinksForObject", new[] { typeof(string) });
                        if (getLinksForObjectMethod != null)
                        {
                            var policyLinks = getLinksForObjectMethod.Invoke(collectionLinksStorage, new object[] { policy.PolicyUid }) as System.Collections.IEnumerable;
                            if (policyLinks != null)
                            {
                                var collectionUids = new List<string>();
                                
                                var allAgentsField = typeof(PedmPlugin).GetField("_allAgents", BindingFlags.NonPublic | BindingFlags.Instance);
                                string allAgents = null;
                                if (allAgentsField != null)
                                {
                                    var allAgentsBytes = allAgentsField.GetValue(plugin) as byte[];
                                    if (allAgentsBytes != null)
                                    {
                                        allAgents = allAgentsBytes.Base64UrlEncode();
                                    }
                                }
                                
                                foreach (var link in policyLinks)
                                {
                                    var collectionUidProperty = link.GetType().GetProperty("CollectionUid");
                                    if (collectionUidProperty != null)
                                    {
                                        var collectionUid = collectionUidProperty.GetValue(link)?.ToString();
                                        if (!string.IsNullOrEmpty(collectionUid))
                                        {
                                            if (allAgents != null && collectionUid == allAgents)
                                            {
                                                collectionUids.Add("*");
                                            }
                                            else
                                            {
                                                collectionUids.Add(collectionUid);
                                            }
                                        }
                                    }
                                }
                                collectionUids.Sort();
                                collections = string.Join(", ", collectionUids);
                            }
                        }
                    }
                }
            }
            catch
            {
            }

            return (name, type, controls, users, machines, applications, collections);
        }
    }

    internal class PedmPolicyOptions : EnterpriseGenericOptions
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
    }
}

