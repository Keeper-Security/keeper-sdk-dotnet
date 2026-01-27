using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Text;
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
                    await ViewDeploymentAsync(options);
                    break;

                case "add":
                    await AddDeploymentAsync(options);
                    break;

                case "update":
                    await UpdateDeploymentAsync(options);
                    break;

                case "remove":
                case "delete":
                    await RemoveDeploymentAsync(options);
                    break;

                case "download":
                    await DownloadDeploymentAsync(options);
                    break;

                default:
                    Console.WriteLine($"Unsupported command '{options.Command}'. Available commands: list, view, add, update, remove, download");
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

        private PedmDeployment ResolveDeployment(string deploymentIdentifier)
        {
            if (string.IsNullOrEmpty(deploymentIdentifier))
            {
                return null;
            }

            // Try as UID first
            var deployment = Plugin.Deployments.GetEntity(deploymentIdentifier);
            if (deployment != null)
            {
                return deployment;
            }

            // Try as name (case-insensitive)
            var lName = deploymentIdentifier.ToLowerInvariant();
            var deployments = Plugin.Deployments.GetAll()
                .Where(x => x.Name != null && x.Name.ToLowerInvariant() == lName)
                .ToList();

            if (deployments.Count == 0)
            {
                return null;
            }

            if (deployments.Count > 1)
            {
                Console.WriteLine($"Deployment name \"{deploymentIdentifier}\" is not unique. Use Deployment UID.");
                return null;
            }

            return deployments[0];
        }

        private Task ViewDeploymentAsync(PedmDeploymentOptions options)
        {
            var deploymentIdentifier = options.DeploymentUid ?? options.Name;
            if (string.IsNullOrEmpty(deploymentIdentifier))
            {
                Console.WriteLine("Deployment UID or name is required for 'view' command.");
                return Task.CompletedTask;
            }

            var deployment = ResolveDeployment(deploymentIdentifier);
            if (deployment == null)
            {
                Console.WriteLine($"Deployment '{deploymentIdentifier}' not found.");
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

            if (!options.Force)
            {
                var lName = options.Name.ToLowerInvariant();
                var hasName = Plugin.Deployments.GetAll()
                    .Any(x => x.Name.ToLowerInvariant() == lName);
                if (hasName)
                {
                    Console.WriteLine($"Deployment \"{options.Name}\" already exists.");
                    return;
                }
            }

            string spiffeCertBase64 = null;
            if (!string.IsNullOrEmpty(options.SpiffeCert))
            {
                var spiffePath = options.SpiffeCert;
                if (File.Exists(spiffePath))
                {
                    try
                    {
                        var ext = Path.GetExtension(spiffePath).ToLowerInvariant();
                        byte[] certBytes;
                        
                        if (ext == ".cer" || ext == ".der")
                        {
                            certBytes = File.ReadAllBytes(spiffePath);
                        }
                        else if (ext == ".pem")
                        {
                            var cert = new X509Certificate2(spiffePath);
                            certBytes = cert.Export(X509ContentType.Cert);
                        }
                        else
                        {
                            var cert = new X509Certificate2(spiffePath);
                            certBytes = cert.Export(X509ContentType.Cert);
                        }
                        
                        spiffeCertBase64 = certBytes.Base64UrlEncode();
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Failed to load SPIFFE certificate from file \"{spiffePath}\": {ex.Message}");
                        return;
                    }
                }
                else
                {
                    spiffeCertBase64 = options.SpiffeCert;
                }
            }

            var addDeployment = new DeploymentDataInput
            {
                Name = options.Name,
                SpiffeCert = spiffeCertBase64
            };

            var addStatus = await Plugin.ModifyDeployments(
                addDeployments: new[] { addDeployment },
                updateDeployments: null,
                removeDeployments: null);

            if (addStatus.AddErrors?.Count > 0)
            {
                var error = addStatus.AddErrors[0];
                Console.WriteLine($"Failed to add deployment \"{error.EntityUid}\": {error.Message}");
                return;
            }

            if (addStatus.Add?.Count > 0)
            {
                Console.WriteLine($"Deployment '{options.Name}' added.");
            }
            else
            {
                Console.WriteLine($"Warning: No deployment was added. Check server response for errors.");
            }

            if (addStatus.Add?.Count > 0 || addStatus.Update?.Count > 0 || addStatus.Remove?.Count > 0)
            {
                PrintModifyStatus(addStatus);
            }

            await Plugin.SyncDown();
        }

        private async Task UpdateDeploymentAsync(PedmDeploymentOptions options)
        {
            var deploymentIdentifier = options.DeploymentUid ?? options.Name;
            if (string.IsNullOrEmpty(deploymentIdentifier))
            {
                Console.WriteLine("Deployment UID or name is required for 'update' command.");
                return;
            }

            var deployment = ResolveDeployment(deploymentIdentifier);
            if (deployment == null)
            {
                Console.WriteLine($"Deployment '{deploymentIdentifier}' not found.");
                return;
            }

            var updateDeployment = new DeploymentDataInput
            {
                DeploymentUid = deployment.DeploymentUid,
                Name = options.Name,
                Disabled = ParseBoolOption(options.Disabled),
                SpiffeCert = options.SpiffeCert
            };

            var updateStatus = await Plugin.ModifyDeployments(
                addDeployments: null,
                updateDeployments: new[] { updateDeployment },
                removeDeployments: null);

            Console.WriteLine($"Deployment '{deployment.DeploymentUid}' updated.");
            if (updateStatus.Add?.Count > 0 || updateStatus.Update?.Count > 0 || updateStatus.Remove?.Count > 0)
            {
                PrintModifyStatus(updateStatus);
            }

            await Plugin.SyncDown();
        }

        private async Task RemoveDeploymentAsync(PedmDeploymentOptions options)
        {
            var deploymentIdentifier = options.DeploymentUid ?? options.Name;
            if (string.IsNullOrEmpty(deploymentIdentifier))
            {
                Console.WriteLine("Deployment UID or name is required for 'remove' command.");
                return;
            }

            var deployment = ResolveDeployment(deploymentIdentifier);
            if (deployment == null)
            {
                Console.WriteLine($"Deployment \"{deploymentIdentifier}\" does not exist");
                return;
            }

            var deploymentUid = deployment.DeploymentUid;

            if (!options.Force)
            {
                Console.Write($"Do you want to delete 1 deployment(s)? [y/n]: ");
                var answer = await Program.GetInputManager().ReadLine();
                if (string.IsNullOrEmpty(answer) || 
                    !answer.Trim().StartsWith("y", StringComparison.InvariantCultureIgnoreCase))
                {
                    return;
                }
            }

            var removeStatus = await Plugin.ModifyDeployments(
                addDeployments: null,
                updateDeployments: null,
                removeDeployments: new[] { deploymentUid });

            if (removeStatus.RemoveErrors?.Count > 0)
            {
                var error = removeStatus.RemoveErrors[0];
                Console.WriteLine($"Failed to delete deployment \"{error.EntityUid}\": {error.Message}");
                return;
            }

            if (removeStatus.Remove?.Count > 0 || removeStatus.Add?.Count > 0 || removeStatus.Update?.Count > 0)
            {
                PrintModifyStatus(removeStatus);
            }

            await Plugin.SyncDown();
        }

        private async Task DownloadDeploymentAsync(PedmDeploymentOptions options)
        {
            var deploymentIdentifier = options.DeploymentUid ?? options.Name;
            if (string.IsNullOrEmpty(deploymentIdentifier))
            {
                Console.WriteLine("Deployment UID or name is required for 'download' command.");
                return;
            }

            var deployment = ResolveDeployment(deploymentIdentifier);
            if (deployment == null)
            {
                Console.WriteLine($"Deployment '{deploymentIdentifier}' not found.");
                return;
            }

            if (deployment.PrivateKey == null || deployment.PrivateKey.Length == 0)
            {
                Console.WriteLine($"Deployment '{deployment.DeploymentUid}' does not have a private key.");
                return;
            }

            var host = Context.Enterprise?.Auth?.Endpoint?.Server ?? "keepersecurity.com";
            var token = $"{host}:{deployment.DeploymentUid}:{deployment.PrivateKey.Base64UrlEncode()}";

            if (!string.IsNullOrEmpty(options.File))
            {
                File.WriteAllText(options.File, token);
                Console.WriteLine($"Deployment token written to: {options.File}");
                return;
            }

            if (!options.Verbose)
            {
                Console.WriteLine(token);
                return;
            }

            string path = "";
            string windows = "";
            string macos = "";
            string linux = "";

            try
            {
                var hostname = host;
                if (hostname.Contains("."))
                {
                    var parts = hostname.Split('.');
                    if (parts.Length >= 2)
                    {
                        hostname = parts[parts.Length - 2] + "." + parts[parts.Length - 1];
                    }
                }

                var manifestUrl = $"https://{hostname}/pam/pedm/package-manifest.json";
                try
                {
                    using (var httpClient = new HttpClient())
                    {
                        httpClient.Timeout = TimeSpan.FromSeconds(10);
                        var response = await httpClient.GetAsync(manifestUrl);
                        if (response.IsSuccessStatusCode)
                        {
                            var jsonContent = await response.Content.ReadAsStringAsync();
                            var manifest = JsonUtils.ParseJson<Dictionary<string, object>>(Encoding.UTF8.GetBytes(jsonContent));
                            
                            if (manifest != null && manifest.TryGetValue("Core", out var coreObj))
                            {
                                if (coreObj is List<object> coreList && coreList.Count > 0)
                                {
                                    var latest = coreList[0] as Dictionary<string, object>;
                                    if (latest != null)
                                    {
                                        if (latest.TryGetValue("Path", out var pathObj))
                                            path = pathObj?.ToString() ?? "";
                                        if (latest.TryGetValue("WindowsZip", out var windowsObj))
                                            windows = windowsObj?.ToString() ?? "";
                                        if (latest.TryGetValue("MacOsZip", out var macosObj))
                                            macos = macosObj?.ToString() ?? "";
                                        if (latest.TryGetValue("LinuxZip", out var linuxObj))
                                            linux = linuxObj?.ToString() ?? "";
                                    }
                                }
                            }
                        }
                    }
                }
                catch
                {
                    Console.WriteLine($"Failed to fetch manifest from {manifestUrl}");
                }
            }
            catch
            {
                Console.WriteLine($"Failed to fetch manifest from {host}");
            }

            var tab = new Tabulate(2);
            tab.AddHeader("", "");
            tab.MaxColumnWidth = int.MaxValue;
            
            if (!string.IsNullOrEmpty(path))
            {
                if (!string.IsNullOrEmpty(windows))
                {
                    tab.AddRow("Windows download URL", path + windows);
                }
                if (!string.IsNullOrEmpty(macos))
                {
                    tab.AddRow("MacOS download URL", path + macos);
                }
                if (!string.IsNullOrEmpty(linux))
                {
                    tab.AddRow("Linux download URL", path + linux);
                }
                if (!string.IsNullOrEmpty(windows) || !string.IsNullOrEmpty(macos) || !string.IsNullOrEmpty(linux))
                {
                    tab.AddRow("", "");
                }
            }
            
            tab.AddRow("Deployment Token", token);
            tab.Dump();
        }
    }

    internal class PedmDeploymentOptions : EnterpriseGenericOptions
    {
        [Value(0, Required = false, HelpText = "Command: list, view, add, update, remove")]
        public string Command { get; set; }

        [Value(1, Required = false, HelpText = "Deployment UID or name (for view, update, remove)")]
        public string DeploymentUid { get; set; }

        [Option("name", Required = false, HelpText = "Deployment name (for add, update, view, remove)")]
        public string Name { get; set; }

        [Option("disabled", Required = false, HelpText = "true/false: Disable deployment (for update)")]
        public string Disabled { get; set; }

        [Option("spiffe-cert", Required = false, HelpText = "SPIFFE certificate file path (.cer, .der, .pem) or base64url encoded string")]
        public string SpiffeCert { get; set; }

        [Option("file", Required = false, HelpText = "File name to write deployment token (for download)")]
        public string File { get; set; }

        [Option("verbose", Required = false, HelpText = "Verbose output (for download)")]
        public bool Verbose { get; set; }
    }
}

