using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Plugins.PAM;
using KeeperSecurity.Utils;
using KeeperSecurity.Vault;
using PamProto = PAM;

namespace Sample.PAMExamples.RotationExamples
{
    /// <summary>
    /// Lists pamUser rotation schedules (requires enterprise admin).
    /// </summary>
    public static class PamRotationListExample
    {
        public static async Task ListRotations(VaultOnline vault = null, bool verbose = false)
        {
            try
            {
                var (resolvedVault, plugin) = await PamHelper.PrepareAsync(vault);
                if (resolvedVault == null || plugin == null)
                {
                    return;
                }

                vault = resolvedVault;

                var schedulesResponse = await RouterUtils.GetRotationSchedulesAsync(vault.Auth);
                var schedules = schedulesResponse?.Schedules?.ToList() ?? new List<PamProto.PAMRotationSchedule>();
                var controllers = plugin.Controllers.GetAll()
                    .ToDictionary(x => x.ControllerUid, x => x, StringComparer.Ordinal);
                var configs = PamVaultHelpers.GetConfigurationRecords(vault);

                var rows = new List<(string Title, string Line)>();
                foreach (var schedule in schedules)
                {
                    var recordUid = schedule.RecordUid?.ToByteArray().Base64UrlEncode() ?? "";
                    if (string.IsNullOrEmpty(recordUid))
                    {
                        continue;
                    }

                    if (!PamVaultHelpers.TryGetUserRecord(vault, recordUid, out var record))
                    {
                        continue;
                    }

                    var controllerUid = schedule.ControllerUid?.ToByteArray().Base64UrlEncode() ?? "";
                    controllers.TryGetValue(controllerUid, out var controller);
                    var configUid = schedule.ConfigurationUid?.ToByteArray().Base64UrlEncode() ?? "";
                    configs.TryGetValue(configUid, out var configRecord);

                    var scheduleText = RotationUtils.FormatScheduleDisplay(schedule.ScheduleData, schedule.NoSchedule);
                    var gatewayName = controller != null && !string.IsNullOrWhiteSpace(controller.ControllerName)
                        ? controller.ControllerName
                        : (string.IsNullOrEmpty(controllerUid) ? "-" : controllerUid);
                    var configText = configRecord != null
                        ? $"{configRecord.Title} ({configRecord.TypeName})"
                        : "[No config found]";

                    string line;
                    if (verbose)
                    {
                        line =
                            $"{recordUid,-28}  {Truncate(record.Title, 24),-24}  {record.TypeName,-12}  {Truncate(scheduleText, 28),-28}  {Truncate(gatewayName, 18),-18}  {Truncate(controllerUid, 22),-22}  {Truncate(configText, 30),-30}  {configUid}";
                    }
                    else
                    {
                        line =
                            $"{recordUid,-28}  {Truncate(record.Title, 24),-24}  {record.TypeName,-12}  {Truncate(scheduleText, 28),-28}  {Truncate(gatewayName, 18),-18}  {Truncate(configText, 36)}";
                    }

                    rows.Add((record.Title ?? "", line));
                }

                if (verbose)
                {
                    Console.WriteLine(
                        $"{"Record UID",-28}  {"Title",-24}  {"Type",-12}  {"Schedule",-28}  {"Gateway",-18}  {"Gateway UID",-22}  {"PAM Config",-30}  Config UID");
                    Console.WriteLine(new string('-', 200));
                }
                else
                {
                    Console.WriteLine(
                        $"{"Record UID",-28}  {"Title",-24}  {"Type",-12}  {"Schedule",-28}  {"Gateway",-18}  PAM Config");
                    Console.WriteLine(new string('-', 160));
                }

                foreach (var row in rows.OrderBy(x => x.Title, StringComparer.OrdinalIgnoreCase))
                {
                    Console.WriteLine(row.Line);
                }

                Console.WriteLine();
                if (rows.Count > 0)
                {
                    Console.WriteLine($"Total: {rows.Count} pamUser rotation schedule(s)");
                    Console.WriteLine("Manual rotation is not supported yet. Coming soon.");
                }
                else
                {
                    Console.WriteLine("No pamUser rotation schedules found.");
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
