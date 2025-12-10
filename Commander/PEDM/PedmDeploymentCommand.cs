using System;
using System.Linq;
using System.Threading.Tasks;
using Cli;
using Commander;
using CommandLine;
using KeeperSecurity.Enterprise;
using KeeperSecurity.Plugins.PEDM;
using KeeperSecurity.Utils;

namespace Commander.PEDM
{
    internal class PedmDeploymentCommand : PedmCommandBase
    {
        public PedmDeploymentCommand(IEnterpriseContext context) : base(context)
        {
        }

        public async Task ExecuteAsync(PedmDeploymentOptions options)
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
                    await ListDeploymentsAsync();
                    break;

                case "view":
                    await ViewDeploymentAsync(options.DeploymentUid);
                    break;

                case "add":
                    await AddDeploymentAsync(options);
                    break;

                case "update":
                    await UpdateDeploymentAsync(options);
                    break;

                case "remove":
                case "delete":
                    await RemoveDeploymentAsync(options.DeploymentUid);
                    break;

                default:
                    Console.WriteLine($"Unsupported command '{options.Command}'. Available commands: list, view, add, update, remove");
                    break;
            }
        }

        private Task ListDeploymentsAsync()
        {
            var deployments = Plugin.Deployments.GetAll().ToList();
            if (deployments.Count == 0)
            {
                Console.WriteLine("No deployments found.");
            }
            else
            {
                var tab = new Tabulate(6);
                tab.AddHeader("Deployment UID", "Name", "Disabled", "Created", "Updated", "Agent Count");
                foreach (var dep in deployments.OrderBy(x => x.Name))
                {
                    var agentCount = Plugin.DeploymentAgents.GetLinksForSubject(dep.DeploymentUid).Count();
                    var created = DateTimeOffset.FromUnixTimeMilliseconds(dep.Created).ToString("yyyy-MM-dd HH:mm:ss");
                    var updated = DateTimeOffset.FromUnixTimeMilliseconds(dep.Modified).ToString("yyyy-MM-dd HH:mm:ss");
                    tab.AddRow(dep.DeploymentUid, dep.Name, dep.Disabled ? "True" : "False", created, updated, agentCount);
                }
                tab.Dump();
            }
            return Task.CompletedTask;
        }

        private Task ViewDeploymentAsync(string deploymentUid)
        {
            if (string.IsNullOrEmpty(deploymentUid))
            {
                Console.WriteLine("Deployment UID is required for 'view' command.");
                return Task.CompletedTask;
            }

            var deployment = Plugin.Deployments.GetEntity(deploymentUid);
            if (deployment == null)
            {
                Console.WriteLine($"Deployment '{deploymentUid}' not found.");
                return Task.CompletedTask;
            }

            Console.WriteLine($"Deployment: {deployment.Name}");
            Console.WriteLine($"  UID: {deployment.DeploymentUid}");
            Console.WriteLine($"  Status: {(deployment.Disabled ? "Disabled" : "Active")}");
            Console.WriteLine($"  Created: {DateTimeOffset.FromUnixTimeMilliseconds(deployment.Created):yyyy-MM-dd HH:mm:ss}");
            Console.WriteLine($"  Modified: {DateTimeOffset.FromUnixTimeMilliseconds(deployment.Modified):yyyy-MM-dd HH:mm:ss}");
            return Task.CompletedTask;
        }

        private async Task AddDeploymentAsync(PedmDeploymentOptions options)
        {
            if (string.IsNullOrEmpty(options.Name))
            {
                Console.WriteLine("Deployment name is required for 'add' command.");
                return;
            }

            var addDeployment = new DeploymentDataInput
            {
                Name = options.Name,
                SpiffeCert = options.SpiffeCert
            };

            var addStatus = await Plugin.ModifyDeployments(
                addDeployments: new[] { addDeployment },
                updateDeployments: null,
                removeDeployments: null);

            Console.WriteLine($"Deployment '{options.Name}' added.");
            if (addStatus.Add?.Count > 0 || addStatus.Update?.Count > 0 || addStatus.Remove?.Count > 0)
            {
                PrintModifyStatus(addStatus);
            }

            await Plugin.SyncDown();
        }

        private async Task UpdateDeploymentAsync(PedmDeploymentOptions options)
        {
            if (string.IsNullOrEmpty(options.DeploymentUid))
            {
                Console.WriteLine("Deployment UID is required for 'update' command.");
                return;
            }

            var updateDeployment = new DeploymentDataInput
            {
                DeploymentUid = options.DeploymentUid,
                Name = options.Name,
                Disabled = ParseBoolOption(options.Disabled),
                SpiffeCert = options.SpiffeCert
            };

            var updateStatus = await Plugin.ModifyDeployments(
                addDeployments: null,
                updateDeployments: new[] { updateDeployment },
                removeDeployments: null);

            Console.WriteLine($"Deployment '{options.DeploymentUid}' updated.");
            if (updateStatus.Add?.Count > 0 || updateStatus.Update?.Count > 0 || updateStatus.Remove?.Count > 0)
            {
                PrintModifyStatus(updateStatus);
            }

            await Plugin.SyncDown();
        }

        private async Task RemoveDeploymentAsync(string deploymentUid)
        {
            if (string.IsNullOrEmpty(deploymentUid))
            {
                Console.WriteLine("Deployment UID is required for 'remove' command.");
                return;
            }

            var removeStatus = await Plugin.ModifyDeployments(
                addDeployments: null,
                updateDeployments: null,
                removeDeployments: new[] { deploymentUid });

            Console.WriteLine($"Deployment '{deploymentUid}' removed.");
            if (removeStatus.Add?.Count > 0 || removeStatus.Update?.Count > 0 || removeStatus.Remove?.Count > 0)
            {
                PrintModifyStatus(removeStatus);
            }

            await Plugin.SyncDown();
        }
    }

    internal class PedmDeploymentOptions : EnterpriseGenericOptions
    {
        [Value(0, Required = false, HelpText = "Command: list, view, add, update, remove")]
        public string Command { get; set; }

        [Value(1, Required = false, HelpText = "Deployment UID (for view, update, remove)")]
        public string DeploymentUid { get; set; }

        [Option("name", Required = false, HelpText = "Deployment name (for add, update)")]
        public string Name { get; set; }

        [Option("disabled", Required = false, HelpText = "true/false: Disable deployment (for update)")]
        public string Disabled { get; set; }

        [Option("spiffe-cert", Required = false, HelpText = "SPIFFE certificate (base64url encoded)")]
        public string SpiffeCert { get; set; }
    }
}

