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
               throw new ArgumentNullException(nameof(options), "Invalid pam gateway command arguments. Available commands: list, new, edit, remove, set-max-instances");
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

            var vault = Context.GetVault();
            if (vault == null)
            {
                throw new VaultException("Vault is not available. Gateway listing requires a connected vault session.");
            }

            var routerDown = false;
            PamProto.PAMOnlineControllers onlineControllers = null;

            try
            {
                onlineControllers = await RouterUtils.GetConnectedGatewaysAsync(Context.Enterprise.Auth);
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or KeeperApiException)
            {
                routerDown = true;
                if (!options.IgnoreRouterDown)
                {
                    Console.WriteLine("Router is unavailable. Use --ignore-router to list registered gateways without online status.");
                    return;
                }

                Console.WriteLine("Router is unavailable. Showing registered gateways with UNKNOWN status.");
            }

            var controllers = Plugin.Controllers.GetAll().ToList();
            if (controllers.Count == 0)
            {
                if (options.isFormatOutputJSON)
                {
                    Console.WriteLine(Json.WriteFormatted(new Dictionary<string, object>
                    {
                        ["gateways"] = Array.Empty<object>(),
                        ["message"] = "This Enterprise does not have Gateways yet.",
                    }));
                }
                else
                {
                    Console.WriteLine("This Enterprise does not have Gateways yet. To create a new Gateway, use: pam-gateway new");
                }

                return;
            }

            var allSummaries = GatewayUtils.BuildGatewaySummaries(controllers, onlineControllers, routerDown, vault);
            var counts = ComputeGatewayCounts(allSummaries, routerDown);
            var displaySummaries = options.Online
                ? allSummaries.Where(s => !routerDown && s.OnlineInstanceCount > 0).ToList()
                : allSummaries;

            if (options.isFormatOutputJSON)
            {
                DumpJsonGateways(displaySummaries, options.Verbose, options.Online ? counts : null);
                return;
            }

            DumpTableGateways(displaySummaries, options.Verbose, options.Online ? counts : null);
        }

        private static (int Online, int Offline, int Total) ComputeGatewayCounts(
            IList<PamGatewaySummary> summaries,
            bool routerDown)
        {
            var total = summaries.Count;
            if (routerDown)
            {
                return (0, 0, total);
            }

            var online = summaries.Count(s => s.OnlineInstanceCount > 0);
            return (online, total - online, total);
        }

        private void DumpJsonGateways(
            IList<PamGatewaySummary> summaries,
            bool verbose,
            (int Online, int Offline, int Total)? counts = null)
        {
            var gateways = summaries.Select(summary => BuildGatewayJson(summary, verbose)).ToList();
            var result = new Dictionary<string, object> { ["gateways"] = gateways };
            if (counts.HasValue)
            {
                result["gateway_counts"] = new Dictionary<string, object>
                {
                    ["online"] = counts.Value.Online,
                    ["offline"] = counts.Value.Offline,
                    ["total"] = counts.Value.Total,
                };
            }
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
                        ["status"] = PamGatewayStatus.Online,
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

        private void DumpTableGateways(
            IList<PamGatewaySummary> summaries,
            bool verbose,
            (int Online, int Offline, int Total)? counts = null)
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
                                PamGatewayStatus.Online,
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
                                PamGatewayStatus.Online,
                                instance.Version);
                        }

                        index++;
                    }
                }
            }

            tab.Dump();

            if (counts.HasValue)
            {
                Console.WriteLine();
                Console.WriteLine($"Gateways: Online: {counts.Value.Online}, Offline: {counts.Value.Offline}, Total: {counts.Value.Total}");
            }
        }

        private async Task NewGatewayAsync(PamGatewayOptions options)
        {
            if (!await EnsurePluginAsync())
            {
                return;
            }

            var vault = Context.GetVault();
            if (vault == null)
            {
                throw new VaultException("Vault is not available. Gateway creation requires a connected vault session.");
            }

            if (string.IsNullOrWhiteSpace(options.Name))
            {
                throw new PamGatewayException("--name is required");
            }

            if (string.IsNullOrWhiteSpace(options.Application))
            {
                throw new PamGatewayException("--application is required");
            }

            var tokenExpire = options.TokenExpiresInMin > 0 ? options.TokenExpiresInMin : DefaultTokenExpirationMin;
            if (tokenExpire < 1)
            {
                throw new ArgumentException("--token-expires-in-min must be at least 1");
            }

            if (tokenExpire > MaxTokenExpirationMin)
            {
                throw new PamGatewayException($"--token-expires-in-min cannot exceed {MaxTokenExpirationMin} minutes");
            }

            if (!TryResolveKsmApplication(vault, options.Application, out var application))
            {
                return;
            }

            string token;
            try
            {
                token = await GatewayUtils.CreateGatewayAsync(
                    vault,
                    options.Name.Trim(),
                    application.Uid,
                    tokenExpire,
                    options.ConfigInit);
            }
            catch (PamException ex)
            {
                Console.WriteLine($"Failed to create gateway: {ex.Message}");
                return;
            }

            await SyncPamAsync();

            if (options.ReturnValue)
            {
                Console.WriteLine(token);
                return;
            }

            Console.WriteLine($"The one time token has been created in application [{options.Application}].");
            Console.WriteLine();
            Console.WriteLine($"The new Gateway named {options.Name} will show up in the gateway list once it is initialized.");
            Console.WriteLine();
            if (!string.IsNullOrWhiteSpace(options.ConfigInit))
            {
                Console.WriteLine("Use the following initialized config in the Gateway:");
            }
            else
            {
                Console.WriteLine($"Following one time token will expire in {tokenExpire} minutes:");
            }

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
                throw new ArgumentNullException(nameof(options.Gateway), "--gateway is required");
            }

            var controller = ResolveGateway(options.Gateway);
            if (controller == null)
            {
                throw new PamGatewayNotFoundException(options.Gateway);
            }

            if (string.IsNullOrWhiteSpace(options.Name) && string.IsNullOrWhiteSpace(options.NodeId))
            {
                throw new PamGatewayException("Nothing to do. Provide --name and/or --node-id to edit the gateway.");
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
                    throw new PamGatewayException(ex.Message, ex);
                }
            }

            var gatewayName = string.IsNullOrWhiteSpace(options.Name) ? controller.ControllerName : options.Name.Trim();
            try
            {
                await GatewayUtils.EditGatewayAsync(Context.Enterprise.Auth, controller.ControllerUid, gatewayName, nodeId);
            }
            catch (PamException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw new PamGatewayException($"Failed to edit gateway: {ex.Message}", ex);
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
                throw new ArgumentNullException(nameof(options.Gateway), "--gateway is required");
            }

            var controller = ResolveGateway(options.Gateway);
            if (controller == null)
            {
                throw new PamGatewayNotFoundException(options.Gateway);
            }

            try
            {
                await GatewayUtils.RemoveGatewayAsync(Context.Enterprise.Auth, controller.ControllerUid);
            }
            catch (PamException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw new PamGatewayException($"Failed to remove gateway: {ex.Message}", ex);
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
                throw new ArgumentNullException(nameof(options.Gateway), "--gateway is required");
            }

            if (options.MaxInstances < 1)
            {
                throw new PamGatewayException("--max-instances must be at least 1");
            }

            var controller = ResolveGateway(options.Gateway);
            if (controller == null)
            {
                throw new PamGatewayNotFoundException(options.Gateway);
            }

            try
            {
                await GatewayUtils.SetGatewayMaxInstancesAsync(
                    Context.Enterprise.Auth,
                    controller.ControllerUid,
                    options.MaxInstances);
            }
            catch (PamException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw new PamGatewayException($"Failed to set max instances: {ex.Message}", ex);
            }

            await SyncPamAsync();
            Console.WriteLine($"{controller.ControllerName}: max instance count set to {options.MaxInstances}");
        }

        private static bool TryResolveKsmApplication(VaultOnline vault, string identifier, out ApplicationRecord application)
        {
            application = null;
            if (string.IsNullOrWhiteSpace(identifier))
            {
                throw new PamGatewayException("--application is required");
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
                throw new PamGatewayAmbiguousException(trimmed);
            }

            application = byTitle.FirstOrDefault();
            if (application == null)
            {
                throw new PamApplicationNotFoundException(trimmed);
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

    internal class PamGatewayOptions
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

        [Option('o', "online", Required = false, HelpText = "Show only online gateways (for list)")]
        public bool Online { get; set; }

        [Option("ignore-router", Required = false, HelpText = "List registered gateways when router is unavailable (for list)")]
        public bool IgnoreRouterDown { get; set; }

        [Option('v', "verbose", Required = false, HelpText = "Verbose output")]
        public bool Verbose { get; set; }

        [Option("format", Required = false, Default = "table", HelpText = "Output format: table, json")]
        public string Format { get; set; }

        [Option('r', "return-value", Required = false, HelpText = "Return one-time token only (for new)")]
        public bool ReturnValue { get; set; }

        [Option('c', "config-init", Required = false, HelpText = "Initialize client config and return configuration string: json or b64 (for new)")]
        public string ConfigInit { get; set; }

        internal bool isFormatOutputJSON => string.Equals(Format, "json", StringComparison.OrdinalIgnoreCase);
    }
}
