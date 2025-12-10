using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;
using Cli;
using Commander;
using CommandLine;
using KeeperSecurity.Enterprise;
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

                default:
                    Console.WriteLine($"Unsupported command '{options.Command}'. Available commands: list, view");
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
                Console.WriteLine("Policy UID is required for 'view' command.");
                return;
            }

            var policy = Plugin.Policies.GetEntity(policyUid);
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
            Console.WriteLine($"  Created: {DateTimeOffset.FromUnixTimeMilliseconds(policy.Created):yyyy-MM-dd HH:mm:ss}");
            Console.WriteLine($"  Updated: {DateTimeOffset.FromUnixTimeMilliseconds(policy.Updated):yyyy-MM-dd HH:mm:ss}");
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
        [Value(0, Required = false, HelpText = "Command: list, view")]
        public string Command { get; set; }

        [Value(1, Required = false, HelpText = "Policy UID (for view)")]
        public string PolicyUid { get; set; }
    }
}

