using System;
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
                    await RemoveAgentAsync(options.AgentUid);
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

        private void ViewAgent(string agentUid)
        {
            if (string.IsNullOrEmpty(agentUid))
            {
                Console.WriteLine("Agent UID is required for 'view' command.");
                return;
            }

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
            if (string.IsNullOrEmpty(options.AgentUid))
            {
                Console.WriteLine("Agent UID is required for 'update' command.");
                return;
            }

            var updateAgent = new UpdateAgent
            {
                AgentUid = options.AgentUid,
                DeploymentUid = options.DeploymentUid,
                Disabled = ParseBoolOption(options.Disabled)
            };

            var updateStatus = await Plugin.ModifyAgents(
                updateAgents: new[] { updateAgent },
                removeAgents: null);

            Console.WriteLine($"Agent '{options.AgentUid}' updated.");
            if (updateStatus.Add?.Count > 0 || updateStatus.Update?.Count > 0 || updateStatus.Remove?.Count > 0)
            {
                PrintModifyStatus(updateStatus);
            }

            await Plugin.SyncDown();
        }

        private async Task RemoveAgentAsync(string agentUid)
        {
            if (string.IsNullOrEmpty(agentUid))
            {
                Console.WriteLine("Agent UID is required for 'remove' command.");
                return;
            }

            var removeStatus = await Plugin.ModifyAgents(
                updateAgents: null,
                removeAgents: new[] { agentUid });

            Console.WriteLine($"Agent '{agentUid}' removed.");
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

        [Value(1, Required = false, HelpText = "Agent UID (for view, update, remove)")]
        public string AgentUid { get; set; }

        [Option("deployment", Required = false, HelpText = "Deployment UID (for update)")]
        public string DeploymentUid { get; set; }

        [Option("disabled", Required = false, HelpText = "true/false: Disable agent (for update)")]
        public string Disabled { get; set; }
    }
}

