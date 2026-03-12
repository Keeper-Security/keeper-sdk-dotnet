using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Runtime.Serialization;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Cli;
using CommandLine;
using KeeperSecurity.Plugins.EPM;
using KeeperSecurity.Utils;

namespace Commander.EPM
{
    internal class EpmDeploymentCommand : EpmCommandBase
    {
        public EpmDeploymentCommand(IEnterpriseContext context) : base(context)
        {
        }

        public async Task ExecuteAsync(EpmDeploymentOptions options)
        {
            if (options == null)
                return;
            if (!await EnsurePluginAsync())
                return;

            var command = string.IsNullOrEmpty(options.Command) ? "list" : options.Command.Trim().ToLowerInvariant();

            switch (command)
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
                    Console.WriteLine($"Unsupported command '{command}'. Available commands: list, view, add, update, remove, download");
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

        private EpmDeployment ResolveDeployment(string deploymentIdentifier)
        {
            var id = deploymentIdentifier?.Trim();
            if (string.IsNullOrEmpty(id))
            {
                return null;
            }

            // Try as UID first
            var deployment = Plugin.Deployments.GetEntity(id);
            if (deployment != null)
            {
                return deployment;
            }

            // Try as name (case-insensitive)
            var lName = id.ToLowerInvariant();
            var deployments = Plugin.Deployments.GetAll()
                .Where(x => x.Name != null && x.Name.ToLowerInvariant() == lName)
                .ToList();

            if (deployments.Count == 0)
            {
                return null;
            }

            if (deployments.Count > 1)
            {
                Console.WriteLine($"Deployment name \"{id}\" is not unique. Use Deployment UID.");
                return null;
            }

            return deployments[0];
        }

        private Task ViewDeploymentAsync(EpmDeploymentOptions options)
        {
            if (options == null)
                return Task.CompletedTask;

            var deploymentIdentifier = (options.DeploymentUid ?? options.Name)?.Trim();
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

        private async Task AddDeploymentAsync(EpmDeploymentOptions options)
        {
            if (options == null)
                return;

            var nameValue = options.Name?.Trim();
            if (string.IsNullOrEmpty(nameValue))
            {
                Console.WriteLine("Deployment name is required for 'add' command.");
                return;
            }

            if (!options.Force)
            {
                var lName = nameValue.ToLowerInvariant();
                var hasName = Plugin.Deployments.GetAll()
                    .Any(x => x.Name != null && x.Name.ToLowerInvariant() == lName);
                if (hasName)
                {
                    Console.WriteLine($"Deployment \"{nameValue}\" already exists.");
                    return;
                }
            }

            string spiffeCertBase64 = null;
            var spiffeValue = options.SpiffeCert?.Trim();
            if (!string.IsNullOrEmpty(spiffeValue))
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
                    spiffeCertBase64 = spiffeValue;
                }
            }

            var addDeployment = new DeploymentDataInput
            {
                Name = nameValue,
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
                Console.WriteLine($"Deployment '{nameValue}' added.");
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

        private async Task UpdateDeploymentAsync(EpmDeploymentOptions options)
        {
            if (options == null)
                return;

            var deploymentIdentifier = (options.DeploymentUid ?? options.Name)?.Trim();
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
                Name = options.Name?.Trim() ?? deployment.Name,
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

        private async Task RemoveDeploymentAsync(EpmDeploymentOptions options)
        {
            if (options == null)
                return;

            var deploymentIdentifier = (options.DeploymentUid ?? options.Name)?.Trim();
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

        private async Task DownloadDeploymentAsync(EpmDeploymentOptions options)
        {
            if (options == null)
                return;

            var deploymentIdentifier = (options.DeploymentUid ?? options.Name)?.Trim();
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

            string path = "";
            string windows = "";
            string macos = "";
            string linux = "";
            
            var hostname = host;
            if (hostname.Contains("."))
            {
                var parts = hostname.Split('.');
                if (parts.Length >= 2)
                {
                    hostname = parts[parts.Length - 2] + "." + parts[parts.Length - 1];
                }
            }

            try
            {
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
                            var manifest = JsonUtils.ParseJson<PackageManifest>(Encoding.UTF8.GetBytes(jsonContent));
                            
                            if (manifest?.Core != null && manifest.Core.Count > 0)
                            {
                                var selected = manifest.Core.FirstOrDefault(x => x.Version == "Latest") 
                                    ?? manifest.Core[0];
                                
                                path = selected.Path ?? "";
                                windows = selected.WindowsZip ?? "";
                                macos = selected.MacOsZip ?? "";
                                linux = selected.LinuxZip ?? "";
                            }
                        }
                    }
                }
                catch (Exception)
                {
                    Console.WriteLine($"Failed to fetch manifest from {manifestUrl}");
                }
            }
            catch (Exception)
            {
                Console.WriteLine($"Failed to fetch manifest from {host}");
            }

            var tab = new Tabulate(2);
            tab.AddHeader("", "");
            tab.MaxColumnWidth = int.MaxValue;

            var fileLines = new List<string>();

            if (!string.IsNullOrEmpty(path))
            {
                if (!path.EndsWith("/"))
                {
                    path += "/";
                }

                if (!string.IsNullOrEmpty(windows))
                {
                    var windowsUrl = path + windows;
                    tab.AddRow("Windows download URL", windowsUrl);
                    fileLines.Add($"Windows download URL\t{windowsUrl}");
                }
                if (!string.IsNullOrEmpty(macos))
                {
                    var macosUrl = path + macos;
                    tab.AddRow("MacOS download URL", macosUrl);
                    fileLines.Add($"MacOS download URL\t{macosUrl}");
                }
                if (!string.IsNullOrEmpty(linux))
                {
                    var linuxUrl = path + linux;
                    tab.AddRow("Linux download URL", linuxUrl);
                    fileLines.Add($"Linux download URL\t{linuxUrl}");
                }
                if (!string.IsNullOrEmpty(windows) || !string.IsNullOrEmpty(macos) || !string.IsNullOrEmpty(linux))
                {
                    tab.AddRow("", "");
                    fileLines.Add("");
                }
            }

            tab.AddRow("Deployment Token", token);
            fileLines.Add($"Deployment Token\t{token}");

            if (!string.IsNullOrEmpty(options.File))
            {
                File.WriteAllText(options.File, string.Join(Environment.NewLine, fileLines));
                Console.WriteLine($"Deployment token and download URLs written to: {options.File}");
            }

            tab.Dump();
        }
    }

    internal class EpmDeploymentOptions : EnterpriseGenericOptions
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

    // Manifest structure classes
    [DataContract]
    internal class PackageManifest
    {
        [DataMember(Name = "Core")]
        public List<CorePackage> Core { get; set; }
    }

    [DataContract]
    internal class CorePackage
    {
        [DataMember(Name = "Version")]
        public string Version { get; set; }

        [DataMember(Name = "Path")]
        public string Path { get; set; }

        [DataMember(Name = "WindowsFileName")]
        public string WindowsFileName { get; set; }

        [DataMember(Name = "MacOsFileName")]
        public string MacOsFileName { get; set; }

        [DataMember(Name = "UbuntuLinuxFileName")]
        public string UbuntuLinuxFileName { get; set; }

        [DataMember(Name = "RockyLinuxFileName")]
        public string RockyLinuxFileName { get; set; }

        [DataMember(Name = "WindowsZip")]
        public string WindowsZip { get; set; }

        [DataMember(Name = "MacOsZip")]
        public string MacOsZip { get; set; }

        [DataMember(Name = "LinuxZip")]
        public string LinuxZip { get; set; }

        [DataMember(Name = "WindowsCmdLine")]
        public string WindowsCmdLine { get; set; }

        [DataMember(Name = "MacOsCmdLine")]
        public string MacOsCmdLine { get; set; }

        [DataMember(Name = "UbuntuLinuxCmdLine")]
        public string UbuntuLinuxCmdLine { get; set; }

        [DataMember(Name = "RockyLinuxCmdLine")]
        public string RockyLinuxCmdLine { get; set; }

        [DataMember(Name = "lastDeployCommit")]
        public string LastDeployCommit { get; set; }
    }
}

