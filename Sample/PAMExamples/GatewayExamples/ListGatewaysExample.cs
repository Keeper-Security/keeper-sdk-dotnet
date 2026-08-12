using System;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Plugins.PAM;
using KeeperSecurity.Vault;
using PamProto = PAM;

namespace Sample.PAMExamples.GatewayExamples
{
    /// <summary>
    /// Lists PAM gateways with online status (requires enterprise admin).
    /// </summary>
    public static class ListGatewaysExample
    {
        public static async Task ListGateways(
            VaultOnline vault = null,
            bool onlineOnly = false,
            bool ignoreRouterDown = false,
            bool verbose = false)
        {
            try
            {
                var (resolvedVault, plugin) = await PamGatewayHelper.PrepareAsync(vault);
                if (resolvedVault == null || plugin == null)
                {
                    return;
                }

                vault = resolvedVault;

                var routerDown = false;
                PamProto.PAMOnlineControllers onlineControllers = null;
                try
                {
                    onlineControllers = await RouterUtils.GetConnectedGatewaysAsync(vault.Auth);
                }
                catch (Exception)
                {
                    // Router online-status lookup failed; still list registered gateways if requested.
                    routerDown = true;
                    if (!ignoreRouterDown)
                    {
                        Console.WriteLine(
                            "Router is unavailable. Pass ignoreRouterDown: true to list registered gateways without online status.");
                        return;
                    }

                    Console.WriteLine("Router is unavailable. Showing registered gateways with UNKNOWN status.");
                }

                var controllers = plugin.Controllers.GetAll().ToList();
                if (controllers.Count == 0)
                {
                    Console.WriteLine("This Enterprise does not have Gateways yet. Use CreateGatewayExample to create one.");
                    return;
                }

                var summaries = GatewayUtils.BuildGatewaySummaries(
                    controllers,
                    onlineControllers,
                    routerDown,
                    vault);

                if (onlineOnly)
                {
                    summaries = summaries
                        .Where(s => !routerDown && s.OnlineInstanceCount > 0)
                        .ToList();
                }

                Console.WriteLine(
                    $"{"KSM Application",-40}  {"Gateway Name",-25}  {"Gateway UID",-28}  {"Status",-20}  {"Version",-12}");
                Console.WriteLine(new string('-', 130));

                foreach (var summary in summaries)
                {
                    var ksmApp = summary.KsmAppAccessible
                        ? $"{summary.KsmAppName} ({summary.KsmAppUid})"
                        : $"[APP NOT ACCESSIBLE] ({summary.KsmAppUid})";

                    var version = summary.OnlineInstanceCount > 1 ? "" : summary.GatewayVersion;
                    Console.WriteLine(
                        $"{Truncate(ksmApp, 40),-40}  {summary.Controller.ControllerName,-25}  {summary.Controller.ControllerUid,-28}  {summary.Status,-20}  {version,-12}");

                    if (verbose)
                    {
                        Console.WriteLine(
                            $"    Device: {summary.Controller.DeviceName}  Token: {summary.Controller.DeviceToken}  Node: {summary.Controller.NodeId}");
                        Console.WriteLine(
                            $"    Created: {PamGatewayHelper.FormatTimestamp(summary.Controller.Created)}  Modified: {PamGatewayHelper.FormatTimestamp(summary.Controller.LastModified)}");
                        if (summary.OnlineInstanceCount <= 1 && !string.IsNullOrEmpty(summary.SystemInfo.Os))
                        {
                            Console.WriteLine(
                                $"    OS: {summary.SystemInfo.Os} {summary.SystemInfo.OsRelease}  Machine: {summary.SystemInfo.MachineType}  OS Ver: {summary.SystemInfo.OsVersion}");
                        }
                    }

                    if (summary.OnlineInstanceCount > 1)
                    {
                        var index = 1;
                        foreach (var instance in summary.OnlineInstances)
                        {
                            Console.WriteLine(
                                $"    |- Instance {index}: {instance.IpAddress}  {PamGatewayStatus.Online}  {instance.Version}  connected: {PamGatewayHelper.FormatTimestamp(instance.ConnectedOn)}");
                            index++;
                        }
                    }
                }

                if (!routerDown)
                {
                    var online = summaries.Count(s => s.OnlineInstanceCount > 0);
                    Console.WriteLine();
                    Console.WriteLine($"Gateways: Online: {online}, Offline: {summaries.Count - online}, Total: {summaries.Count}");
                }
                else
                {
                    Console.WriteLine();
                    Console.WriteLine($"Total registered gateways: {summaries.Count}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }

        private static string Truncate(string value, int maxLength)
        {
            if (string.IsNullOrEmpty(value) || value.Length <= maxLength)
            {
                return value ?? "";
            }

            return value.Substring(0, maxLength - 3) + "...";
        }
    }
}
