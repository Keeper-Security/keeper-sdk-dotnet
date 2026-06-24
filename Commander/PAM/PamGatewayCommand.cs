using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using Cli;
using Commander;
using CommandLine;
using KeeperSecurity.Authentication;
using KeeperSecurity.Plugins.PAM;
using KeeperSecurity.Utils;
using KeeperSecurity.Vault;
using PamProto = PAM;
using ZeroDep;

namespace Commander.PAM
{
    internal class PamGatewayCommand : PamCommandBase
    {
        private const int DefaultTokenExpirationMin = 60;
        private const int MaxTokenExpirationMin = 1440;

        public PamGatewayCommand(IEnterpriseContext context) : base(context)
        {
        }

        public async Task ExecuteAsync(PamGatewayOptions options)
        {
            if (options == null)
            {
                return;
            }

            var command = string.IsNullOrEmpty(options.Command) ? "list" : options.Command.Trim().ToLowerInvariant();
            switch (command)
            {
                case "list":
                case "l":
                    await ListGatewaysAsync(options);
                    break;
                case "new":
                case "n":
                    await NewGatewayAsync(options);
                    break;
                case "edit":
                case "e":
                    await EditGatewayAsync(options);
                    break;
                case "remove":
                case "rm":
                case "delete":
                    await RemoveGatewayAsync(options);
                    break;
                case "set-max-instances":
                case "smi":
                    await SetMaxInstancesAsync(options);
                    break;
                default:
                    Console.WriteLine($"Unsupported command '{command}'. Available commands: list, new, edit, remove, set-max-instances");
                    break;
            }
        }

        private async Task ListGatewaysAsync(PamGatewayOptions options)
        {
            if (!await EnsurePluginAsync())
            {
                return;
            }

            var vault = GetVault();
            var routerDown = false;
            PamProto.PAMOnlineControllers onlineControllers = null;

            try
            {
                onlineControllers = await RouterUtils.GetConnectedGatewaysAsync(Context.Enterprise.Auth);
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or KeeperApiException)
            {
                routerDown = true;
                if (!options.Force)
                {
                    Console.WriteLine("Router is unavailable. Use --force to list registered gateways without online status.");
                    return;
                }

                Console.WriteLine("Router is unavailable. Showing registered gateways with UNKNOWN status.");
            }

            var controllers = Plugin.Controllers.GetAll().ToList();
            if (controllers.Count == 0)
            {
                if (string.Equals(options.Format, "json", StringComparison.OrdinalIgnoreCase))
                {
                    Console.WriteLine(Json.WriteFormatted(new Dictionary<string, object>
                    {
                        ["gateways"] = Array.Empty<object>(),
                        ["message"] = "This Enterprise does not have Gateways yet.",
                    }));
                }
                else
                {
                    Console.WriteLine("This Enterprise does not have Gateways yet. To create a new Gateway, use: pam-gateway --command=new");
                }

                return;
            }

            var summaries = GatewayUtils.BuildGatewaySummaries(controllers, onlineControllers, routerDown, vault);
            if (string.Equals(options.Format, "json", StringComparison.OrdinalIgnoreCase))
            {
                DumpJsonGateways(summaries, options.Verbose);
                return;
            }

            DumpTableGateways(summaries, options.Verbose);
        }

        private void DumpJsonGateways(IList<PamGatewaySummary> summaries, bool verbose)
        {
            var gateways = summaries.Select(summary => BuildGatewayJson(summary, verbose)).ToList();
            var result = new Dictionary<string, object> { ["gateways"] = gateways };
            if (verbose)
            {
                var routerHost = GetRouterHost();
                if (routerHost != null)
                {
                    result["router_host"] = routerHost;
                }
            }

            Console.WriteLine(Json.WriteFormatted(result));
        }

        private static object BuildGatewayJson(PamGatewaySummary summary, bool verbose)
        {
            var item = new Dictionary<string, object>
            {
                ["ksm_app_name"] = summary.KsmAppAccessible ? summary.KsmAppName : null,
                ["ksm_app_uid"] = summary.KsmAppUid,
                ["ksm_app_accessible"] = summary.KsmAppAccessible,
                ["gateway_name"] = summary.Controller.ControllerName,
                ["gateway_uid"] = summary.Controller.ControllerUid,
                ["status"] = summary.Status,
                ["gateway_version"] = summary.GatewayVersion,
            };

            if (summary.OnlineInstanceCount > 1)
            {
                item["instances"] = summary.OnlineInstances.Select((instance, index) =>
                {
                    var instanceItem = new Dictionary<string, object>
                    {
                        ["instance_number"] = index + 1,
                        ["status"] = "ONLINE",
                        ["gateway_version"] = instance.Version,
                        ["ip_address"] = instance.IpAddress,
                        ["connected_on"] = FormatTimestamp(instance.ConnectedOn),
                    };

                    if (verbose)
                    {
                        AddSystemInfoToJson(instanceItem, instance.SystemInfo);
                    }

                    return instanceItem;
                }).ToList();
            }

            if (verbose)
            {
                item["device_name"] = summary.Controller.DeviceName;
                item["device_token"] = summary.Controller.DeviceToken;
                item["created_on"] = FormatTimestamp(summary.Controller.Created);
                item["last_modified"] = FormatTimestamp(summary.Controller.LastModified);
                item["node_id"] = summary.Controller.NodeId;

                if (summary.OnlineInstanceCount <= 1)
                {
                    AddSystemInfoToJson(item, summary.SystemInfo);
                }
            }

            return item;
        }

        private static void AddSystemInfoToJson(IDictionary<string, object> item, PamGatewaySystemInfo systemInfo)
        {
            item["os"] = systemInfo.Os;
            item["os_release"] = systemInfo.OsRelease;
            item["machine_type"] = systemInfo.MachineType;
            item["os_version"] = systemInfo.OsVersion;
        }

        private void DumpTableGateways(IList<PamGatewaySummary> summaries, bool verbose)
        {
            if (verbose)
            {
                var routerHost = GetRouterHost();
                if (routerHost != null)
                {
                    Console.WriteLine();
                    Console.WriteLine($"Router Host: {routerHost}");
                    Console.WriteLine();
                }
            }

            var columnCount = verbose ? 14 : 5;
            var tab = new Tabulate(columnCount);
            if (verbose)
            {
                tab.AddHeader("KSM Application Name (UID)", "Gateway Name", "Gateway UID", "Status", "Gateway Version",
                    "Device Name", "Device Token", "Created On", "Last Modified", "Node ID",
                    "OS", "OS Release", "Machine Type", "OS Version");
            }
            else
            {
                tab.AddHeader("KSM Application Name (UID)", "Gateway Name", "Gateway UID", "Status", "Gateway Version");
            }

            foreach (var summary in summaries)
            {
                var ksmApp = summary.KsmAppAccessible
                    ? $"{summary.KsmAppName} ({summary.KsmAppUid})"
                    : $"[APP NOT ACCESSIBLE OR DELETED] ({summary.KsmAppUid})";

                var isPool = summary.OnlineInstanceCount > 1;
                var gatewayVersion = isPool ? "" : summary.GatewayVersion;

                if (verbose)
                {
                    var systemInfo = isPool ? new PamGatewaySystemInfo() : summary.SystemInfo;
                    tab.AddRow(
                        ksmApp,
                        summary.Controller.ControllerName,
                        summary.Controller.ControllerUid,
                        summary.Status,
                        gatewayVersion,
                        summary.Controller.DeviceName,
                        summary.Controller.DeviceToken,
                        FormatTimestamp(summary.Controller.Created),
                        FormatTimestamp(summary.Controller.LastModified),
                        summary.Controller.NodeId,
                        systemInfo.Os,
                        systemInfo.OsRelease,
                        systemInfo.MachineType,
                        systemInfo.OsVersion);
                }
                else
                {
                    tab.AddRow(
                        ksmApp,
                        summary.Controller.ControllerName,
                        summary.Controller.ControllerUid,
                        summary.Status,
                        gatewayVersion);
                }

                if (summary.OnlineInstanceCount > 1)
                {
                    var index = 1;
                    foreach (var instance in summary.OnlineInstances)
                    {
                        var connectedOn = FormatTimestamp(instance.ConnectedOn);
                        if (verbose)
                        {
                            tab.AddRow(
                                "",
                                $"  |- Instance {index} (connected: {connectedOn})",
                                instance.IpAddress,
                                "ONLINE",
                                instance.Version,
                                "", "",
                                connectedOn,
                                "",
                                "",
                                instance.SystemInfo.Os,
                                instance.SystemInfo.OsRelease,
                                instance.SystemInfo.MachineType,
                                instance.SystemInfo.OsVersion);
                        }
                        else
                        {
                            tab.AddRow(
                                "",
                                $"  |- Instance {index} (connected: {connectedOn})",
                                instance.IpAddress,
                                "ONLINE",
                                instance.Version);
                        }

                        index++;
                    }
                }
            }

            tab.Dump();
        }

        private async Task NewGatewayAsync(PamGatewayOptions options)
        {
            var vault = GetVault();
            if (vault == null)
            {
                Console.WriteLine("Vault is not available. Gateway creation requires a connected vault session.");
                return;
            }

            if (string.IsNullOrWhiteSpace(options.Name))
            {
                Console.WriteLine("--name is required");
                return;
            }

            if (string.IsNullOrWhiteSpace(options.Application))
            {
                Console.WriteLine("--application is required");
                return;
            }

            var tokenExpire = options.TokenExpiresInMin > 0 ? options.TokenExpiresInMin : DefaultTokenExpirationMin;
            if (tokenExpire < 1)
            {
                Console.WriteLine("--token-expires-in-min must be at least 1");
                return;
            }

            if (tokenExpire > MaxTokenExpirationMin)
            {
                Console.WriteLine($"--token-expires-in-min cannot exceed {MaxTokenExpirationMin} minutes");
                return;
            }

            if (!TryResolveKsmApplication(vault, options.Application, out var application))
            {
                return;
            }

            string token;
            try
            {
                token = await GatewayUtils.CreateGatewayAsync(vault, options.Name.Trim(), application.Uid, tokenExpire);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to create gateway: {ex.Message}");
                return;
            }

            if (await EnsurePluginAsync(syncIfNeeded: false))
            {
                await SyncPamAsync();
            }

            if (options.ReturnValue)
            {
                Console.WriteLine(token);
                return;
            }

            Console.WriteLine($"The one time token has been created in application [{options.Application}].");
            Console.WriteLine();
            Console.WriteLine($"The new Gateway named {options.Name} will show up in the gateway list once it is initialized.");
            Console.WriteLine();
            Console.WriteLine($"Following one time token will expire in {tokenExpire} minutes.");
            Console.WriteLine("-----------------------------------------------");
            Console.WriteLine(token);
            Console.WriteLine("-----------------------------------------------");
        }

        private async Task EditGatewayAsync(PamGatewayOptions options)
        {
            if (!await EnsurePluginAsync())
            {
                return;
            }

            if (string.IsNullOrWhiteSpace(options.Gateway))
            {
                Console.WriteLine("--gateway is required");
                return;
            }

            var controller = ResolveGateway(options.Gateway);
            if (controller == null)
            {
                Console.WriteLine($"Gateway '{options.Gateway}' not found");
                return;
            }

            if (string.IsNullOrWhiteSpace(options.Name) && string.IsNullOrWhiteSpace(options.NodeId))
            {
                Console.WriteLine("Nothing to do. Provide --name and/or --node-id to edit the gateway.");
                return;
            }

            long nodeId = controller.NodeId;
            if (!string.IsNullOrWhiteSpace(options.NodeId))
            {
                try
                {
                    var node = Context.EnterpriseData.ResolveNodeName(options.NodeId.Trim());
                    nodeId = node.Id;
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.Message);
                    return;
                }
            }

            var gatewayName = string.IsNullOrWhiteSpace(options.Name) ? controller.ControllerName : options.Name.Trim();
            try
            {
                await GatewayUtils.EditGatewayAsync(Context.Enterprise.Auth, controller.ControllerUid, gatewayName, nodeId);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to edit gateway: {ex.Message}");
                return;
            }

            await SyncPamAsync();
            Console.WriteLine($"Gateway {gatewayName} has been edited.");
        }

        private async Task RemoveGatewayAsync(PamGatewayOptions options)
        {
            if (!await EnsurePluginAsync())
            {
                return;
            }

            if (string.IsNullOrWhiteSpace(options.Gateway))
            {
                Console.WriteLine("--gateway is required");
                return;
            }

            var controller = ResolveGateway(options.Gateway);
            if (controller == null)
            {
                Console.WriteLine($"Gateway '{options.Gateway}' not found");
                return;
            }

            try
            {
                await GatewayUtils.RemoveGatewayAsync(Context.Enterprise.Auth, controller.ControllerUid);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to remove gateway: {ex.Message}");
                return;
            }

            await SyncPamAsync();
            Console.WriteLine($"Gateway {controller.ControllerName} has been removed.");
        }

        private async Task SetMaxInstancesAsync(PamGatewayOptions options)
        {
            if (!await EnsurePluginAsync())
            {
                return;
            }

            if (string.IsNullOrWhiteSpace(options.Gateway))
            {
                Console.WriteLine("--gateway is required");
                return;
            }

            if (options.MaxInstances < 1)
            {
                Console.WriteLine("--max-instances must be at least 1");
                return;
            }

            var controller = ResolveGateway(options.Gateway);
            if (controller == null)
            {
                Console.WriteLine($"Gateway '{options.Gateway}' not found");
                return;
            }

            try
            {
                await GatewayUtils.SetGatewayMaxInstancesAsync(
                    Context.Enterprise.Auth,
                    controller.ControllerUid,
                    options.MaxInstances);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to set max instances: {ex.Message}");
                return;
            }

            await SyncPamAsync();
            Console.WriteLine($"{controller.ControllerName}: max instance count set to {options.MaxInstances}");
        }

        private static bool TryResolveKsmApplication(VaultOnline vault, string identifier, out ApplicationRecord application)
        {
            application = null;
            if (string.IsNullOrWhiteSpace(identifier))
            {
                Console.WriteLine("--application is required");
                return false;
            }

            var trimmed = identifier.Trim();
            var byUid = vault.KeeperRecords.OfType<ApplicationRecord>()
                .FirstOrDefault(x => string.Equals(x.Uid, trimmed, StringComparison.OrdinalIgnoreCase));
            if (byUid != null)
            {
                application = byUid;
                return true;
            }

            var byTitle = vault.KeeperRecords.OfType<ApplicationRecord>()
                .Where(x => string.Equals(x.Title, trimmed, StringComparison.OrdinalIgnoreCase))
                .ToList();
            if (byTitle.Count > 1)
            {
                Console.WriteLine($"Multiple Secret Manager Applications match \"{trimmed}\". Please specify application UID.");
                return false;
            }

            application = byTitle.FirstOrDefault();
            if (application == null)
            {
                Console.WriteLine($"Cannot find Secret Manager Application: {trimmed}");
                return false;
            }

            return true;
        }

        private string GetRouterHost()
        {
            var routerUrl = Environment.GetEnvironmentVariable("ROUTER_URL");
            if (!string.IsNullOrWhiteSpace(routerUrl))
            {
                return routerUrl.TrimEnd('/');
            }

            var server = Context.Enterprise?.Auth?.Endpoint?.Server;
            if (string.IsNullOrWhiteSpace(server))
            {
                return null;
            }

            if (Uri.TryCreate(server, UriKind.Absolute, out var uri))
            {
                server = uri.Host;
            }

            return $"https://connect.{server}";
        }

        private static string FormatTimestamp(long timestampMs)
        {
            if (timestampMs <= 0)
            {
                return "";
            }

            return DateTimeOffset.FromUnixTimeMilliseconds(timestampMs).LocalDateTime.ToString("yyyy-MM-dd HH:mm:ss");
        }
    }

    internal class PamGatewayOptions : EnterpriseGenericOptions
    {
        [Value(0, Required = false, HelpText = "Command: list, new, edit, remove, set-max-instances")]
        public string Command { get; set; }

        [Option('g', "gateway", Required = false, HelpText = "Gateway UID or name")]
        public string Gateway { get; set; }

        [Option('n', "name", Required = false, HelpText = "Gateway name")]
        public string Name { get; set; }

        [Option('a', "application", Required = false, HelpText = "KSM application UID or title")]
        public string Application { get; set; }

        [Option('e', "token-expires-in-min", Required = false, Default = 60, HelpText = "One-time token expiration in minutes (max 1440)")]
        public int TokenExpiresInMin { get; set; }

        [Option('i', "node-id", Required = false, HelpText = "Enterprise node ID or name")]
        public string NodeId { get; set; }

        [Option('m', "max-instances", Required = false, HelpText = "Maximum gateway instances (for set-max-instances)")]
        public int MaxInstances { get; set; }

        [Option('v', "verbose", Required = false, HelpText = "Verbose output")]
        public bool Verbose { get; set; }

        [Option("format", Required = false, Default = "table", HelpText = "Output format: table, json")]
        public string Format { get; set; }

        [Option('r', "return-value", Required = false, HelpText = "Return one-time token only (for new)")]
        public bool ReturnValue { get; set; }
    }
}
