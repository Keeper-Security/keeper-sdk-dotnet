using System;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Plugins.PAM;
using KeeperSecurity.Utils;
using KeeperSecurity.Vault;
using RouterProto = Router;

namespace Sample.PAMExamples.RotationExamples
{
    /// <summary>
    /// Shows rotation readiness and settings for a PAM record.
    /// </summary>
    public static class PamRotationInfoExample
    {
        public static async Task ShowRotationInfo(VaultOnline vault, string recordId)
        {
            try
            {
                var (resolvedVault, plugin) = await PamHelper.PrepareAsync(vault);
                if (resolvedVault == null || plugin == null)
                {
                    return;
                }

                vault = resolvedVault;

                if (string.IsNullOrWhiteSpace(recordId))
                {
                    Console.WriteLine("Record UID or title is required.");
                    return;
                }

                TypedRecord record;
                try
                {
                    record = PamVaultHelpers.ResolveRecord(vault, recordId.Trim(), PamRecordTypes.Rotation);
                }
                catch (InvalidOperationException ex)
                {
                    Console.WriteLine(ex.Message);
                    return;
                }

                if (record == null)
                {
                    Console.WriteLine($"Record '{recordId}' not found");
                    return;
                }

                var rotationInfo = await RotationUtils.GetRotationInfoAsync(vault.Auth, record.Uid);
                var statusName = rotationInfo.Status.ToString();
                var isReady = rotationInfo.Status == RouterProto.RouterRotationStatus.RrsOnline;
                var configUid = rotationInfo.ConfigurationUid?.ToByteArray().Base64UrlEncode() ?? "";
                var gatewayUid = rotationInfo.ControllerUid?.Length > 0
                    ? rotationInfo.ControllerUid.ToByteArray().Base64UrlEncode()
                    : "-";

                PamController gateway = null;
                if (!string.Equals(gatewayUid, "-", StringComparison.Ordinal))
                {
                    gateway = plugin.Controllers.GetEntity(gatewayUid)
                              ?? GatewayUtils.FindGateway(plugin.Controllers.GetAll(), gatewayUid);
                }

                var gatewayName = gateway != null && !string.IsNullOrWhiteSpace(gateway.ControllerName)
                    ? gateway.ControllerName
                    : (!string.IsNullOrWhiteSpace(rotationInfo.ControllerName)
                        ? rotationInfo.ControllerName
                        : gatewayUid);

                var adminResourceUid = rotationInfo.ResourceUid?.Length > 0
                    ? rotationInfo.ResourceUid.ToByteArray().Base64UrlEncode()
                    : null;

                byte[] pwdComplexityRaw = null;
                if (!string.IsNullOrEmpty(rotationInfo.PwdComplexity))
                {
                    pwdComplexityRaw = rotationInfo.PwdComplexity.Base64UrlDecode();
                }

                PasswordGenerationOptions pwdComplexityDetail = null;
                var pwdComplexityDecryptFailed = false;
                if (pwdComplexityRaw != null && pwdComplexityRaw.Length > 0
                    && !RotationUtils.TryDecryptPasswordComplexity(pwdComplexityRaw, record.RecordKey, out pwdComplexityDetail))
                {
                    pwdComplexityDecryptFailed = true;
                    pwdComplexityDetail = null;
                }

                string scheduleText = null;
                var schedulesResponse = await RouterUtils.GetRotationSchedulesAsync(vault.Auth);
                var schedule = schedulesResponse?.Schedules?
                    .FirstOrDefault(x => x.RecordUid?.ToByteArray().Base64UrlEncode() == record.Uid);
                if (schedule != null)
                {
                    scheduleText = schedule.NoSchedule
                        ? "Manual Rotation"
                        : RotationUtils.FormatScheduleDisplay(schedule.ScheduleData, false);
                }

                if (isReady)
                {
                    Console.WriteLine($"Rotation Status: Ready to rotate ({statusName})");
                    Console.WriteLine($"Record: {record.Title} ({record.Uid})");
                    Console.WriteLine($"PAM Config UID: {configUid}");
                    Console.WriteLine($"Node ID: {rotationInfo.NodeId}");
                    Console.WriteLine($"Gateway Name: {gatewayName}");
                    Console.WriteLine($"Gateway UID: {gatewayUid}");

                    if (!string.IsNullOrEmpty(adminResourceUid))
                    {
                        Console.WriteLine($"Admin Resource Uid: {adminResourceUid}");
                    }

                    if (pwdComplexityRaw != null && pwdComplexityRaw.Length > 0)
                    {
                        Console.WriteLine($"Password Complexity: {rotationInfo.PwdComplexity}");
                        if (pwdComplexityDecryptFailed)
                        {
                            Console.WriteLine("Password Complexity Data: [decrypt failed]");
                        }
                        else
                        {
                            var complexityDisplay = RotationUtils.FormatPasswordComplexityDisplay(pwdComplexityDetail);
                            if (!string.IsNullOrEmpty(complexityDisplay))
                            {
                                Console.WriteLine($"Password Complexity Data: {complexityDisplay}");
                            }
                        }
                    }
                    else
                    {
                        Console.WriteLine("Password Complexity: [not set]");
                    }

                    Console.WriteLine($"Is Rotation Disabled: {rotationInfo.Disabled}");
                    if (!string.IsNullOrEmpty(scheduleText))
                    {
                        Console.WriteLine($"Schedule: {scheduleText}");
                    }

                    Console.WriteLine();
                    Console.WriteLine("Manual rotation is not supported yet. Coming soon.");
                }
                else
                {
                    Console.WriteLine($"Rotation Status: Not ready to rotate ({statusName})");
                    Console.WriteLine($"Record: {record.Title} ({record.Uid})");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}
