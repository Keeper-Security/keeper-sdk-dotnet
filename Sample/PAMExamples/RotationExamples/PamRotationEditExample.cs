using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Google.Protobuf;
using KeeperSecurity.Plugins.PAM;
using KeeperSecurity.Utils;
using KeeperSecurity.Vault;
using RouterProto = Router;

namespace Sample.PAMExamples.RotationExamples
{
    /// <summary>
    /// Configures rotation for a pamUser record using SDK APIs
    /// (<see cref="PamRotationGraphEdit"/> + <see cref="RouterUtils.SetRecordRotationAsync"/>).
    /// </summary>
    public static class PamRotationEditExample
    {
        /// <param name="vault">Authenticated vault (or null to authenticate).</param>
        /// <param name="recordId">pamUser record UID or title.</param>
        /// <param name="configId">PAM configuration UID or title.</param>
        /// <param name="resourceId">Optional resource UID/title (required for general profile when not already linked).</param>
        /// <param name="scheduleCron">Optional 6-field CRON (e.g. "0 0 4 * * ?").</param>
        /// <param name="scheduleJson">Optional schedule JSON (mutually exclusive with cron/onDemand).</param>
        /// <param name="onDemand">Configure manual / on-demand rotation.</param>
        /// <param name="complexity">Optional complexity: length,upper,lower,digits,symbols[,chars].</param>
        /// <param name="enable">Enable rotation.</param>
        /// <param name="disable">Disable rotation.</param>
        /// <param name="scheduleOnly">Only update schedule (skip graph link).</param>
        public static async Task EditRotation(
            VaultOnline vault,
            string recordId,
            string configId,
            string resourceId = null,
            string scheduleCron = null,
            string scheduleJson = null,
            bool onDemand = false,
            string complexity = null,
            bool enable = false,
            bool disable = false,
            bool scheduleOnly = false)
        {
            try
            {
                var (resolvedVault, _) = await PamHelper.PrepareAsync(vault);
                if (resolvedVault == null)
                {
                    return;
                }

                vault = resolvedVault;
                await vault.SyncDown();

                if (string.IsNullOrWhiteSpace(recordId))
                {
                    Console.WriteLine("Record UID or title is required.");
                    return;
                }

                if (string.IsNullOrWhiteSpace(configId))
                {
                    Console.WriteLine("PAM configuration UID or title is required.");
                    return;
                }

                if (enable && disable)
                {
                    Console.WriteLine("Cannot use both enable and disable at the same time.");
                    return;
                }

                TypedRecord record;
                TypedRecord configRecord;
                try
                {
                    record = PamVaultHelpers.ResolveRecord(vault, recordId.Trim(), new[] { "pamUser" });
                    configRecord = PamVaultHelpers.ResolveRecord(vault, configId.Trim(), PamRecordTypes.Configuration);
                }
                catch (InvalidOperationException ex)
                {
                    Console.WriteLine(ex.Message);
                    return;
                }

                if (record == null)
                {
                    Console.WriteLine($"pamUser record '{recordId}' not found.");
                    return;
                }

                if (configRecord == null)
                {
                    Console.WriteLine($"PAM configuration '{configId}' not found.");
                    return;
                }

                List<object> scheduleData;
                try
                {
                    scheduleData = RotationUtils.ParseScheduleOptions(
                        scheduleJson,
                        scheduleCron,
                        onDemand,
                        scheduleFromConfig: false);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Invalid schedule: {ex.Message}");
                    return;
                }

                PasswordGenerationOptions complexityRules = null;
                if (!string.IsNullOrWhiteSpace(complexity))
                {
                    try
                    {
                        complexityRules = RotationUtils.ParsePasswordComplexityRules(complexity);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Invalid complexity: {ex.Message}");
                        return;
                    }
                }

                string resourceUid = null;
                if (!string.IsNullOrWhiteSpace(resourceId))
                {
                    TypedRecord resource;
                    try
                    {
                        resource = PamVaultHelpers.ResolveRecord(vault, resourceId.Trim(), PamRecordTypes.Resource);
                    }
                    catch (InvalidOperationException ex)
                    {
                        Console.WriteLine(ex.Message);
                        return;
                    }

                    if (resource == null)
                    {
                        Console.WriteLine($"Resource '{resourceId}' not found.");
                        return;
                    }

                    resourceUid = resource.Uid;
                }
                else
                {
                    var cached = vault.GetRecordRotation(record.Uid);
                    if (cached != null && !string.IsNullOrEmpty(cached.ResourceUid)
                        && !string.Equals(cached.ResourceUid, configRecord.Uid, StringComparison.Ordinal))
                    {
                        resourceUid = cached.ResourceUid;
                    }
                }

                if (!scheduleOnly && string.IsNullOrEmpty(resourceUid))
                {
                    Console.WriteLine(
                        "Resource is required for general rotation. Pass resourceId, or link the user to a resource first.");
                    return;
                }

                if (!string.IsNullOrEmpty(resourceUid) && !scheduleOnly)
                {
                    await PamRotationGraphEdit.ConfigureUserAsync(
                        vault.Auth,
                        vault,
                        record,
                        resourceUid,
                        configRecord.Uid,
                        noopRotation: false,
                        scheduleOnly: false);
                }

                var cachedRotation = vault.GetRecordRotation(record.Uid);
                List<object> recordSchedule = scheduleData;
                if (recordSchedule == null)
                {
                    if (cachedRotation != null && !string.IsNullOrEmpty(cachedRotation.Schedule))
                    {
                        try
                        {
                            recordSchedule = RotationUtils.ParseScheduleJsonString(cachedRotation.Schedule);
                        }
                        catch
                        {
                            recordSchedule = new List<object>();
                        }
                    }
                    else
                    {
                        // No explicit schedule and none cached → on-demand.
                        recordSchedule = new List<object>();
                    }
                }

                byte[] pwdComplexity;
                if (complexityRules != null)
                {
                    pwdComplexity = RotationUtils.IsClearedPasswordComplexity(complexityRules)
                        ? Array.Empty<byte>()
                        : RotationUtils.EncryptPasswordComplexity(complexityRules, record.RecordKey);
                }
                else if (cachedRotation != null)
                {
                    pwdComplexity = cachedRotation.PasswordComplexity ?? Array.Empty<byte>();
                }
                else
                {
                    pwdComplexity = Array.Empty<byte>();
                }

                var disabled = cachedRotation?.Disabled ?? false;
                if (enable)
                {
                    disabled = false;
                }
                else if (disable)
                {
                    disabled = true;
                }

                var request = new RouterProto.RouterRecordRotationRequest
                {
                    RecordUid = ByteString.CopyFrom(record.Uid.Base64UrlDecode()),
                    ConfigurationUid = ByteString.CopyFrom(configRecord.Uid.Base64UrlDecode()),
                    Schedule = RotationUtils.BuildSchedulePayload(scheduleJson, onDemand, recordSchedule),
                    PwdComplexity = ByteString.CopyFrom(pwdComplexity ?? Array.Empty<byte>()),
                    Disabled = disabled,
                    Noop = false,
                    Revision = cachedRotation?.Revision ?? 0,
                };

                if (!string.IsNullOrEmpty(resourceUid))
                {
                    request.ResourceUid = ByteString.CopyFrom(resourceUid.Base64UrlDecode());
                }

                Console.WriteLine("Updating rotation:");
                Console.WriteLine($"  Record:        {record.Title} ({record.Uid})");
                Console.WriteLine($"  Configuration: {configRecord.Title} ({configRecord.Uid})");
                Console.WriteLine($"  Resource:      {resourceUid ?? "(none)"}");
                Console.WriteLine($"  Schedule:      {RotationUtils.GetScheduleType(recordSchedule)}");
                Console.WriteLine($"  Enabled:       {!disabled}");

                await RouterUtils.SetRecordRotationAsync(vault.Auth, request);
                await vault.SyncDown();

                Console.WriteLine("Rotation updated successfully.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}
