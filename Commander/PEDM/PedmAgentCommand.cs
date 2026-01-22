using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Cli;
using CommandLine;
using KeeperSecurity.Plugins.PEDM;

namespace Commander.PEDM
{
    internal class PedmAgentCommand : PedmCommandBase
    {
        public PedmAgentCommand(IEnterpriseContext context) : base(context)
        {
        }

        public async Task ExecuteAsync(PedmAgentOptions options)
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
                    ListAgents();
                    break;

                case "view":
                    ViewAgent(options.AgentUid);
                    break;

                case "update":
                    await UpdateAgentAsync(options);
                    break;

                case "remove":
                case "delete":
                    await RemoveAgentAsync(options.AgentUid?.FirstOrDefault());
                    break;

                default:
                    Console.WriteLine($"Unsupported command '{options.Command}'. Available commands: list, view, update, remove");
                    break;
            }
        }

        private void ListAgents()
        {
            var agents = Plugin.Agents.GetAll().ToList();
            if (agents.Count == 0)
            {
                Console.WriteLine("No agents found.");
            }
            else
            {
                var tab = new Tabulate(5);
                tab.AddHeader("Agent UID", "Machine Name", "Deployment", "Disabled", "Created");
                foreach (var ag in agents.OrderBy(x => x.AgentUid))
                {
                    string deploymentName = "";
                    if (!string.IsNullOrEmpty(ag.DeploymentUid))
                    {
                        var deployment = Plugin.Deployments.GetEntity(ag.DeploymentUid);
                        if (deployment != null)
                        {
                            deploymentName = deployment.Name ?? ag.DeploymentUid;
                        }
                        else
                        {
                            deploymentName = ag.DeploymentUid;
                        }
                    }
                    
                    var machineName = ag.MachineId ?? "";
                    var disabled = ag.Disabled ? "True" : "False";
                    var created = DateTimeOffset.FromUnixTimeMilliseconds(ag.Created).ToString("yyyy-MM-dd HH:mm:ss");
                    
                    tab.AddRow(ag.AgentUid, machineName, deploymentName, disabled, created);
                }
                tab.Dump();
            }
        }

        private void ViewAgent(IList<string> agentUids)
        {
            if (agentUids == null || agentUids.Count == 0)
            {
                Console.WriteLine("Agent UID is required for 'view' command.");
                return;
            }

            var agentUid = agentUids[0];
            var agentView = Plugin.Agents.GetEntity(agentUid);
            if (agentView == null)
            {
                Console.WriteLine($"Agent '{agentUid}' not found.");
                return;
            }

            Console.WriteLine($"Agent: {agentView.MachineId}");
            Console.WriteLine($"  UID: {agentView.AgentUid}");
            Console.WriteLine($"  Status: {(agentView.Disabled ? "Disabled" : "Active")}");
            if (!string.IsNullOrEmpty(agentView.DeploymentUid))
            {
                Console.WriteLine($"  Deployment: {agentView.DeploymentUid}");
            }
            Console.WriteLine($"  Created: {DateTimeOffset.FromUnixTimeMilliseconds(agentView.Created):yyyy-MM-dd HH:mm:ss}");
            Console.WriteLine($"  Modified: {DateTimeOffset.FromUnixTimeMilliseconds(agentView.Modified):yyyy-MM-dd HH:mm:ss}");
        }

        private async Task UpdateAgentAsync(PedmAgentOptions options)
        {
            var agentUids = options.AgentUid?.Where(u => !string.IsNullOrEmpty(u)).ToList() ?? new List<string>();

            if (agentUids.Count == 0)
            {
                Console.WriteLine("Agent UID(s) are required for 'update' command.");
                return;
            }

            string deploymentUid = null;
            if (!string.IsNullOrEmpty(options.DeploymentUid))
            {
                var deployment = Plugin.Deployments.GetEntity(options.DeploymentUid);
                if (deployment == null)
                {
                    Console.WriteLine($"Deployment \"{options.DeploymentUid}\" does not exist");
                    return;
                }
                deploymentUid = options.DeploymentUid;
            }

            bool? disabled = null;
            if (!string.IsNullOrEmpty(options.Enable))
            {
                var enableLower = options.Enable.ToLowerInvariant();
                if (enableLower == "on")
                {
                    disabled = false;
                }
                else if (enableLower == "off")
                {
                    disabled = true;
                }
                else
                {
                    Console.WriteLine($"\"enable\" argument must be \"on\" or \"off\"");
                    return;
                }
            }

            var updateAgents = new List<UpdateAgent>();
            foreach (var agentUid in agentUids)
            {
                var agent = Plugin.Agents.GetEntity(agentUid);
                if (agent == null)
                {
                    Console.WriteLine($"Agent \"{agentUid}\" does not exist");
                    return;
                }

                updateAgents.Add(new UpdateAgent
                {
                    AgentUid = agent.AgentUid,
                    DeploymentUid = deploymentUid,
                    Disabled = disabled
                });
            }

            if (updateAgents.Count == 0)
            {
                return;
            }

            var updateStatus = await Plugin.ModifyAgents(
                updateAgents: updateAgents,
                removeAgents: null);

            if (updateStatus.UpdateErrors?.Count > 0)
            {
                foreach (var error in updateStatus.UpdateErrors)
                {
                    if (!error.Success)
                    {
                        Console.WriteLine($"Failed to update agent \"{error.EntityUid}\": {error.Message}");
                    }
                }
            }

            if (updateStatus.Update?.Count > 0 || updateStatus.Add?.Count > 0 || updateStatus.Remove?.Count > 0)
            {
                PrintModifyStatus(updateStatus);
            }

            await Plugin.SyncDown();
        }

        private async Task RemoveAgentAsync(string agentUid)
        {
            if (string.IsNullOrEmpty(agentUid))
            {
                Console.WriteLine("Agent UID or machine name is required for 'remove' command.");
                return;
            }

            var agent = Plugin.Agents.GetEntity(agentUid);
            if (agent == null)
            {
                var matches = Plugin.Agents.GetAll()
                    .Where(x => string.Equals(x.MachineId, agentUid, StringComparison.OrdinalIgnoreCase))
                    .ToList();

                if (matches.Count > 1)
                {
                    Console.WriteLine($"Multiple agents match machine name \"{agentUid}\". Please specify Agent UID.");
                    return;
                }

                agent = matches.FirstOrDefault();
            }

            if (agent == null)
            {
                Console.WriteLine($"Agent \"{agentUid}\" does not exist");
                return;
            }

            var removeStatus = await Plugin.ModifyAgents(
                updateAgents: null,
                removeAgents: new[] { agent.AgentUid });

            if (removeStatus.RemoveErrors?.Count > 0)
            {
                foreach (var error in removeStatus.RemoveErrors)
                {
                    if (!error.Success)
                    {
                        Console.WriteLine($"Failed to remove agent \"{error.EntityUid}\": {error.Message}");
                    }
                }
                return;
            }

            Console.WriteLine($"Agent '{agent.AgentUid}' removed.");
            if (removeStatus.Add?.Count > 0 || removeStatus.Update?.Count > 0 || removeStatus.Remove?.Count > 0)
            {
                PrintModifyStatus(removeStatus);
            }

            await Plugin.SyncDown();
        }
    }

    internal class PedmAgentOptions : EnterpriseGenericOptions
    {
        [Value(0, Required = false, HelpText = "Command: list, view, update, remove")]
        public string Command { get; set; }

        [Value(1, Required = false, HelpText = "Agent UID(s) (for view, update, remove) - can specify multiple for update")]
        public IList<string> AgentUid { get; set; }

        [Option("deployment", Required = false, HelpText = "Deployment UID (for update)")]
        public string DeploymentUid { get; set; }

        [Option("enable", Required = false, HelpText = "Enable or disable agents: 'on' to enable, 'off' to disable (for update)")]
        public string Enable { get; set; }
    }
}

