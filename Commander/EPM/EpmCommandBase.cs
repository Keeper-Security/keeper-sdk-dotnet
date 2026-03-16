using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Commander;
using KeeperSecurity.Enterprise;
using KeeperSecurity.Plugins.EPM;
using KeeperSecurity.Utils;
using PEDMProto = PEDM;

namespace Commander.EPM
{
    internal abstract class EpmCommandBase
    {
        protected IEnterpriseContext Context { get; }
        protected EpmPlugin Plugin { get; private set; }

        protected EpmCommandBase(IEnterpriseContext context)
        {
            Context = context ?? throw new ArgumentNullException(nameof(context));
        }

        protected async Task<bool> EnsurePluginAsync(bool syncIfNeeded = true)
        {
            Plugin = Context.GetEpmPlugin() as EpmPlugin;
            if (Plugin == null)
            {
                Console.WriteLine("EPM plugin is not available. Enterprise admin access is required.");
                return false;
            }

            if (syncIfNeeded && Plugin.NeedSync)
            {
                Console.WriteLine("Syncing EPM data...");
                await Plugin.SyncDown();
            }

            return true;
        }

        protected static bool? ParseBoolOption(string value)
        {
            var v = value?.Trim();
            if (string.IsNullOrEmpty(v))
                return null;

            if (bool.TryParse(v, out var result))
                return result;

            var lower = v.ToLowerInvariant();
            if (lower == "true" || lower == "1" || lower == "yes" || lower == "on")
                return true;
            if (lower == "false" || lower == "0" || lower == "no" || lower == "off")
                return false;

            return null;
        }

        protected static void PrintModifyStatus(ModifyStatus status)
        {
            if (status.Add?.Count > 0)
            {
                Console.WriteLine($"  Added: {string.Join(", ", status.Add)}");
            }
            if (status.Update?.Count > 0)
            {
                Console.WriteLine($"  Updated: {string.Join(", ", status.Update)}");
            }
            if (status.Remove?.Count > 0)
            {
                Console.WriteLine($"  Removed: {string.Join(", ", status.Remove)}");
            }
        }

        protected static string GetCollectionTypeName(int collectionType)
        {
            return collectionType switch
            {
                1 => "OS Build",
                2 => "Application",
                3 => "User Account",
                4 => "Group Account",
                202 => "OS Version",
                _ => $"Type {collectionType}"
            };
        }

        protected EpmPolicy ResolvePolicy(string identifier)
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

        protected static (string Name, string Type, List<string> Controls, string Users, string Machines, string Applications, string Collections) ParsePolicyData(EpmPolicy policy, EpmPlugin plugin)
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
                var allAgentsUid = plugin.AllAgentsCollectionUid;
                var policyLinks = plugin.GetCollectionLinksForObject(policy.PolicyUid);
                var collectionUids = new List<string>();
                foreach (var link in policyLinks)
                {
                    var collectionUid = link.CollectionUid;
                    if (!string.IsNullOrEmpty(collectionUid))
                    {
                        collectionUids.Add(allAgentsUid != null && collectionUid == allAgentsUid ? "*" : collectionUid);
                    }
                }
                collectionUids.Sort();
                collections = string.Join(", ", collectionUids);
            }
            catch
            {
            }

            return (name, type, controls, users, machines, applications, collections);
        }
    }
}

