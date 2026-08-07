using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Cli;
using KeeperSecurity.Authentication;
using Commander;
using Google.Protobuf;
using KeeperSecurity.Plugins.PAM;
using KeeperSecurity.Utils;
using KeeperSecurity.Vault;
using RouterProto = Router;

namespace Commander.PAM
{
    internal sealed class PamRotationEditService
    {
        private readonly IAuthentication _auth;
        private readonly VaultOnline _vault;
        private readonly VaultContext _pathContext;

        public PamRotationEditService(
            IAuthentication auth,
            VaultOnline vault,
            VaultContext pathContext = null)
        {
            _auth = auth;
            _vault = vault;
            _pathContext = pathContext;
        }

        public async Task ExecuteAsync(PamRotationOptions options)
        {
            if (options.Enable && options.Disable)
            {
                throw new InvalidOperationException("Cannot use both --enable and --disable at the same time.");
            }

            if (!string.IsNullOrWhiteSpace(options.Record) && !string.IsNullOrWhiteSpace(options.Folder))
            {
                throw new InvalidOperationException("Cannot use both --record and --folder at the same time.");
            }

            if (!string.IsNullOrWhiteSpace(options.Resource) && !string.IsNullOrWhiteSpace(options.IamAadConfig))
            {
                throw new InvalidOperationException(
                    "Cannot use both --resource and --iam-aad-config at once. "
                    + "--resource configures users on a resource; --iam-aad-config configures IAM/Azure AD users.");
            }

            await _vault.SyncDown();

            PasswordGenerationOptions complexityRules = null;
            if (options.Complexity != null)
            {
                complexityRules = RotationUtils.ParsePasswordComplexityRules(options.Complexity);
            }
            else if (!string.IsNullOrWhiteSpace(options.ComplexityJson))
            {
                try
                {
                    complexityRules = RotationUtils.ParsePasswordComplexityJson(
                        Encoding.UTF8.GetBytes(options.ComplexityJson));
                }
                catch (ArgumentException ex)
                {
                    throw new InvalidOperationException(ex.Message, ex);
                }
            }

            List<object> scheduleData;
            try
            {
                scheduleData = RotationUtils.ParseScheduleOptions(
                    options.ScheduleJson,
                    options.ScheduleCron,
                    options.OnDemand,
                    options.ScheduleConfig);
            }
            catch (ArgumentException ex)
            {
                throw new InvalidOperationException(ex.Message, ex);
            }

            var pamConfigs = PamVaultHelpers.GetConfigurationRecords(_vault);
            TypedRecord configRecord = null;
            if (!string.IsNullOrWhiteSpace(options.Config))
            {
                configRecord = PamVaultHelpers.ResolveRecord(_vault, options.Config, PamRecordTypes.Configuration);
                if (configRecord == null)
                {
                    throw new InvalidOperationException($"Record uid {options.Config} is not a PAM Configuration record.");
                }
            }

            var records = ResolveTargetRecords(options);
            if (records.Count == 0)
            {
                throw new InvalidOperationException(
                    $"No PAM record is found. Valid PAM record types: {string.Join(", ", PamRecordTypes.Rotation)}");
            }

            if (!string.IsNullOrWhiteSpace(options.RotationProfile))
            {
                var allowedProfiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                {
                    "general", "iam_user", "scripts_only", "saas",
                };
                if (!allowedProfiles.Contains(options.RotationProfile.Trim()))
                {
                    throw new InvalidOperationException(
                        "Invalid rotation profile. Allowed values: general, iam_user, scripts_only, saas");
                }
            }

            Console.WriteLine($"Selected {records.Count} PAM record(s) for rotation");

            var skipped = new List<object[]>();
            var valid = new List<object[]>();
            var requests = new List<RouterProto.RouterRecordRotationRequest>();
            var configuredResources = new List<ResourceConfigureSummary>();

            foreach (var record in records)
            {
                if (PamRecordTypes.Resource.Contains(record.TypeName ?? ""))
                {
                    try
                    {
                        await ConfigureResourceRecordAsync(
                            record,
                            options,
                            configRecord,
                            pamConfigs,
                            skipped,
                            configuredResources);
                    }
                    catch (InvalidOperationException ex)
                    {
                        if (!string.IsNullOrWhiteSpace(options.Folder))
                        {
                            skipped.Add(new object[] { record.Uid, record.Title, "Error", ex.Message });
                        }
                        else
                        {
                            throw;
                        }
                    }

                    continue;
                }

                if (!string.Equals(record.TypeName, "pamUser", StringComparison.Ordinal))
                {
                    continue;
                }

                try
                {
                    var editContext = ResolveRecordEditContext(options, record);
                    string resourceUidForDag = null;
                    string configUidForDag = configRecord?.Uid;
                    if (editContext.Profile != "iam_user"
                        && !editContext.Noop
                        && !options.ScheduleOnly)
                    {
                        resourceUidForDag = ResolveResourceUidForDag(record, options, configRecord, pamConfigs);
                        if (string.IsNullOrEmpty(configUidForDag))
                        {
                            var cached = _vault.GetRecordRotation(record.Uid);
                            configUidForDag = cached?.ConfigurationUid;
                        }
                    }

                    if (!string.IsNullOrEmpty(resourceUidForDag) && !string.IsNullOrEmpty(configUidForDag))
                    {
                        await PamRotationGraphEdit.ConfigureUserAsync(
                            _auth,
                            _vault,
                            record,
                            resourceUidForDag,
                            configUidForDag,
                            editContext.Noop,
                            options.ScheduleOnly);
                    }

                    if (TryBuildUserRotationRequest(
                            record,
                            options,
                            configRecord,
                            pamConfigs,
                            scheduleData,
                            complexityRules,
                            editContext,
                            skipped,
                            valid,
                            out var request))
                    {
                        requests.Add(request);
                    }
                }
                catch (InvalidOperationException ex)
                {
                    if (!string.IsNullOrWhiteSpace(options.Folder))
                    {
                        skipped.Add(new object[] { record.Uid, record.Title, "Error", ex.Message });
                    }
                    else
                    {
                        throw;
                    }
                }
            }

            if (skipped.Count > 0)
            {
                var skippedTab = new Tabulate(4);
                skippedTab.AddHeader("Record UID", "Record Title", "Problem", "Description");
                foreach (var row in skipped)
                {
                    skippedTab.AddRow(row);
                }

                Console.WriteLine();
                Console.WriteLine("The following record(s) were skipped:");
                skippedTab.Dump();
            }

            if (configuredResources.Count > 0)
            {
                PrintResourceConfigureSummary(configuredResources);
            }

            if (requests.Count == 0)
            {
                return;
            }

            if (skipped.Count > 0 && !options.Force)
            {
                if (!await NsfHelpers.ConfirmAsync("\nDo you want to cancel password rotation? [Y/n]: ", defaultYes: true))
                {
                    return;
                }
            }

            if (valid.Count > 0)
            {
                var validTab = new Tabulate(7);
                validTab.AddHeader("Record UID", "Record Title", "Enabled", "Configuration UID", "Resource UID", "Schedule", "Complexity");
                foreach (var row in valid)
                {
                    validTab.AddRow(row);
                }

                Console.WriteLine();
                Console.WriteLine("The following record(s) will be updated:");
                validTab.Dump();
            }

            if (!options.Force)
            {
                if (!await NsfHelpers.ConfirmAsync("\nDo you want to update password rotation? [Y/n]: ", defaultYes: true))
                {
                    return;
                }
            }

            var failures = new List<string>();
            foreach (var request in requests)
            {
                var recordUid = request.RecordUid.ToByteArray().Base64UrlEncode();
                try
                {
                    await RouterUtils.SetRecordRotationAsync(
                        _auth,
                        request);
                }
                catch (Exception ex)
                {
                    var message = $"Record \"{recordUid}\": Set rotation error: {ex.Message}";
                    Console.WriteLine(message);
                    failures.Add(message);
                }
            }

            await _vault.SyncDown();
            try
            {
                _pathContext?.EnterpriseContext?.RefreshRecordRotations();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Warning: could not refresh PAM record rotations cache: {ex.Message}");
            }

            if (failures.Count > 0)
            {
                throw new InvalidOperationException(
                    $"{failures.Count} of {requests.Count} record(s) failed to update rotation:"
                    + Environment.NewLine
                    + string.Join(Environment.NewLine, failures));
            }
        }

        private sealed class RecordEditContext
        {
            internal string Profile { get; set; }

            internal bool Noop { get; set; }
        }

        private static RecordEditContext ResolveRecordEditContext(PamRotationOptions options, TypedRecord record)
        {
            var profile = NormalizeProfile(options);
            var noop = profile == "scripts_only" || IsNoopRecord(record);
            if (profile == "saas")
            {
                ValidateSaasConfig(options.SaasConfigUid);
                noop = true;
            }

            return new RecordEditContext
            {
                Profile = profile,
                Noop = noop,
            };
        }

        private bool TryBuildUserRotationRequest(
            TypedRecord record,
            PamRotationOptions options,
            TypedRecord configRecord,
            Dictionary<string, TypedRecord> pamConfigs,
            List<object> scheduleData,
            PasswordGenerationOptions complexityRules,
            RecordEditContext editContext,
            List<object[]> skipped,
            List<object[]> valid,
            out RouterProto.RouterRecordRotationRequest request)
        {
            request = null;
            var cached = _vault.GetRecordRotation(record.Uid);
            var profile = editContext.Profile;
            var noop = editContext.Noop;

            if (options.ScheduleOnly)
            {
                if (!string.IsNullOrWhiteSpace(options.Folder)
                    && (cached == null || cached.Disabled))
                {
                    skipped.Add(new object[] { record.Uid, record.Title, "Rotation not enabled", "Skipped" });
                    return false;
                }

                if (cached == null)
                {
                    skipped.Add(new object[] { record.Uid, record.Title, "No rotation info", "Skipped" });
                    return false;
                }
            }

            var configUid = configRecord?.Uid;
            if (string.IsNullOrEmpty(configUid))
            {
                configUid = ResolveIamConfigUid(options, cached);
            }

            if (string.IsNullOrEmpty(configUid))
            {
                if (cached != null && !string.IsNullOrEmpty(cached.ConfigurationUid))
                {
                    configUid = cached.ConfigurationUid;
                }
            }

            if (string.IsNullOrEmpty(configUid))
            {
                skipped.Add(new object[]
                {
                    record.Uid,
                    record.Title,
                    "No current PAM Configuration",
                    "Specify a configuration UID parameter [--config]",
                });
                return false;
            }

            if (!pamConfigs.ContainsKey(configUid))
            {
                skipped.Add(new object[]
                {
                    record.Uid,
                    record.Title,
                    "PAM Configuration is invalid",
                    "Specify a configuration UID parameter [--config]",
                });
                return false;
            }

            var pamConfig = pamConfigs[configUid];
            var recordSchedule = scheduleData;
            if (recordSchedule == null)
            {
                if (cached != null && !options.ScheduleConfig && !string.IsNullOrEmpty(cached.Schedule))
                {
                    try
                    {
                        recordSchedule = RotationUtils.ParseScheduleJsonString(cached.Schedule);
                    }
                    catch (ArgumentException ex)
                    {
                        Trace.TraceWarning(
                            "PAM: invalid cached schedule for record {0}: {1}",
                            record.Uid,
                            ex.Message);
                        recordSchedule = new List<object>();
                    }
                }
                else if (options.ScheduleConfig)
                {
                    recordSchedule = GetScheduleFromConfig(pamConfig);
                    if (recordSchedule == null)
                    {
                        skipped.Add(new object[]
                        {
                            record.Uid,
                            record.Title,
                            "No defaultRotationSchedule on PAM Configuration",
                            "Set a default rotation schedule on the PAM config, or use --schedule-json/--schedule-cron",
                        });
                        return false;
                    }
                }
            }

            byte[] pwdComplexity;
            if (complexityRules != null)
            {
                pwdComplexity = RotationUtils.IsClearedPasswordComplexity(complexityRules)
                    ? Array.Empty<byte>()
                    : RotationUtils.EncryptPasswordComplexity(complexityRules, record.RecordKey);
            }
            else if (cached != null)
            {
                pwdComplexity = cached.PasswordComplexity ?? Array.Empty<byte>();
            }
            else
            {
                pwdComplexity = Array.Empty<byte>();
            }

            var disabled = cached?.Disabled ?? false;
            if (options.Enable)
            {
                disabled = false;
            }
            else if (options.Disable)
            {
                disabled = true;
            }

            string resourceUid = null;
            if (profile == "iam_user" || !string.IsNullOrWhiteSpace(options.IamAadConfig))
            {
                resourceUid = null;
                noop = false;
            }
            else if (profile == "saas")
            {
                resourceUid = null;
                noop = true;
            }
            else if (noop)
            {
                resourceUid = null;
            }
            else if (!string.IsNullOrWhiteSpace(options.Resource))
            {
                var resource = PamVaultHelpers.ResolveRecord(_vault, options.Resource, null);
                if (resource == null)
                {
                    throw new InvalidOperationException($"Resource '{options.Resource}' not found");
                }

                resourceUid = resource.Uid;
            }
            else if (profile == "general" && string.IsNullOrWhiteSpace(options.Resource))
            {
                throw new InvalidOperationException("General rotation profile requires --resource to be specified.");
            }
            else if (cached != null && !string.IsNullOrEmpty(cached.ResourceUid)
                     && !string.Equals(cached.ResourceUid, configUid, StringComparison.Ordinal))
            {
                resourceUid = cached.ResourceUid;
            }
            else if (!options.ScheduleOnly)
            {
                resourceUid = GetDefaultResourceFromConfig(pamConfig);
                if (string.IsNullOrEmpty(resourceUid) && !noop)
                {
                    throw new InvalidOperationException(
                        $"Record \"{record.Uid}\" is not associated with any resource. "
                            + "Please use pam-rotation edit --record RECORD --resource RESOURCE to associate it.");
                }
            }

            if (!string.IsNullOrEmpty(resourceUid)
                && string.Equals(resourceUid, configUid, StringComparison.Ordinal))
            {
                resourceUid = null;
            }

            var scheduleType = RotationUtils.GetScheduleType(recordSchedule);

            string complexityDisplay;
            if (!RotationUtils.TryDecryptPasswordComplexity(pwdComplexity, record.RecordKey, out var complexityRulesDecoded))
            {
                complexityDisplay = "[decrypt failed]";
            }
            else
            {
                complexityDisplay = RotationUtils.FormatPasswordComplexityDisplay(complexityRulesDecoded);
            }

            valid.Add(new object[]
            {
                record.Uid,
                record.Title,
                !disabled,
                configUid,
                resourceUid ?? "",
                scheduleType,
                complexityDisplay,
            });

            request = new RouterProto.RouterRecordRotationRequest
            {
                RecordUid = ByteString.CopyFrom(record.Uid.Base64UrlDecode()),
                ConfigurationUid = ByteString.CopyFrom(configUid.Base64UrlDecode()),
                Schedule = RotationUtils.BuildSchedulePayload(options.ScheduleJson, options.OnDemand, recordSchedule),
                PwdComplexity = ByteString.CopyFrom(pwdComplexity ?? Array.Empty<byte>()),
                Disabled = disabled,
                Noop = noop,
                Revision = cached?.Revision ?? 0,
            };

            if (!noop && !string.IsNullOrEmpty(resourceUid))
            {
                request.ResourceUid = ByteString.CopyFrom(resourceUid.Base64UrlDecode());
            }

            if (profile == "saas" && !string.IsNullOrWhiteSpace(options.SaasConfigUid))
            {
                request.SaasConfiguration = ByteString.CopyFrom(options.SaasConfigUid.Trim().Base64UrlDecode());
            }

            return true;
        }

        private static string NormalizeProfile(PamRotationOptions options)
        {
            if (string.IsNullOrWhiteSpace(options.RotationProfile))
            {
                if (!string.IsNullOrWhiteSpace(options.IamAadConfig))
                {
                    return "iam_user";
                }

                return null;
            }

            return options.RotationProfile.Trim().ToLowerInvariant();
        }

        private static string ResolveIamConfigUid(PamRotationOptions options, RecordRotationInfo cached)
        {
            if (!string.IsNullOrWhiteSpace(options.IamAadConfig))
            {
                return options.IamAadConfig.Trim();
            }

            if (NormalizeProfile(options) == "iam_user")
            {
                if (!string.IsNullOrWhiteSpace(options.Config))
                {
                    return options.Config.Trim();
                }

                return cached?.ConfigurationUid;
            }

            return null;
        }

        private static void ValidateSaasConfig(string saasConfigUid)
        {
            if (string.IsNullOrWhiteSpace(saasConfigUid))
            {
                throw new InvalidOperationException(
                    "SaaS rotation profile requires --saas-config-uid to be specified.");
            }
        }

        private static bool IsNoopRecord(TypedRecord record)
        {
            var noopField = record.Fields
                .OfType<TypedField<string>>()
                .FirstOrDefault(x => x.FieldName == "NOOP");
            var value = noopField?.Values?.FirstOrDefault();
            return !string.IsNullOrEmpty(value)
                && string.Equals(value.Trim(), "TRUE", StringComparison.OrdinalIgnoreCase);
        }

        private static string GetDefaultResourceFromConfig(TypedRecord config)
        {
            var resourcesField = config.Fields
                .OfType<TypedField<FieldPamResources>>()
                .FirstOrDefault(x => x.FieldName == "pamResources");
            var refs = resourcesField?.Values?.FirstOrDefault()?.ResourceRef;
            if (refs == null || refs.Length == 0)
            {
                return null;
            }

            if (refs.Length > 1)
            {
                return null;
            }

            return refs[0];
        }

        private static List<object> GetScheduleFromConfig(TypedRecord config)
        {
            if (config == null)
            {
                return null;
            }

            // Same as Python: get_typed_field('schedule', 'defaultRotationSchedule')
            var scheduleField = EnumerateTypedFields(config)
                .OfType<TypedField<FieldSchedule>>()
                .FirstOrDefault(x =>
                    string.Equals(x.FieldName, "schedule", StringComparison.Ordinal)
                    && string.Equals(x.FieldLabel, "defaultRotationSchedule", StringComparison.Ordinal));

            var value = scheduleField?.Values?.FirstOrDefault();
            if (value == null)
            {
                return null;
            }

            // On-Demand / empty default => no scheduled entries
            if (string.IsNullOrWhiteSpace(value.Type)
                || string.Equals(value.Type, "On-Demand", StringComparison.OrdinalIgnoreCase))
            {
                return new List<object>();
            }

            var dict = new Dictionary<string, object>
            {
                ["type"] = value.Type,
            };

            if (!string.IsNullOrEmpty(value.Time))
            {
                dict["time"] = value.Time;
                dict["utcTime"] = value.Time;
            }

            if (!string.IsNullOrEmpty(value.Weekday))
            {
                dict["weekday"] = value.Weekday;
            }

            if (!string.IsNullOrEmpty(value.Month))
            {
                dict["month"] = value.Month;
            }

            if (!string.IsNullOrEmpty(value.MonthDay))
            {
                dict["monthDay"] = value.MonthDay;
            }

            if (!string.IsNullOrEmpty(value.IntervalCount))
            {
                dict["intervalCount"] = value.IntervalCount;
            }

            if (!string.IsNullOrEmpty(value.Cron))
            {
                dict["cron"] = value.Cron;
            }

            if (!string.IsNullOrEmpty(value.TimeZone))
            {
                dict["tz"] = value.TimeZone;
            }

            return new List<object> { dict };
        }

        private static IEnumerable<ITypedField> EnumerateTypedFields(TypedRecord config)
        {
            if (config.Fields != null)
            {
                foreach (var field in config.Fields)
                {
                    yield return field;
                }
            }

            if (config.Custom != null)
            {
                foreach (var field in config.Custom)
                {
                    yield return field;
                }
            }
        }

        private List<TypedRecord> ResolveTargetRecords(PamRotationOptions options)
        {
            var recordUids = new HashSet<string>(StringComparer.Ordinal);
            string recordPattern = null;
            var folderUids = new HashSet<string>(StringComparer.Ordinal);

            var recordName = options.EffectiveRecord?.Trim();
            if (!string.IsNullOrWhiteSpace(recordName))
            {
                var resolved = PamVaultHelpers.ResolveRecord(_vault, recordName, PamRecordTypes.Rotation);
                if (resolved != null)
                {
                    recordUids.Add(resolved.Uid);
                }
                else if (TryResolveRecordPath(recordName, out var folderNode, out var title))
                {
                    recordPattern = title;
                    CollectFolderUids(folderNode, folderUids);
                }
                else if (!string.IsNullOrWhiteSpace(options.Folder))
                {
                    recordPattern = recordName;
                }
                else
                {
                    Console.WriteLine($"Record \"{recordName}\" not found.");
                }
            }

            if (!string.IsNullOrWhiteSpace(options.Folder))
            {
                var folderName = options.Folder.Trim();
                if (_vault.TryGetFolder(folderName, out var folderByUid))
                {
                    CollectFolderUids(folderByUid, folderUids);
                }
                else if (_pathContext != null
                         && _pathContext.TryResolvePath(folderName, out var folderByPath, out var title)
                         && string.IsNullOrEmpty(title))
                {
                    CollectFolderUids(folderByPath, folderUids);
                }
                else
                {
                    Console.WriteLine($"Folder \"{folderName}\" not found. Skipping.");
                }
            }

            if (folderUids.Count > 0)
            {
                Regex matcher = null;
                if (!string.IsNullOrEmpty(recordPattern))
                {
                    var pattern = Regex.Escape(recordPattern).Replace("\\*", ".*").Replace("\\?", ".");
                    matcher = new Regex($"^{pattern}$", RegexOptions.IgnoreCase);
                }

                foreach (var folderUid in folderUids)
                {
                    if (!_vault.TryGetFolder(folderUid, out var folder))
                    {
                        continue;
                    }

                    foreach (var uid in EnumerateFolderRecordUids(folder))
                    {
                        if (recordUids.Contains(uid))
                        {
                            continue;
                        }

                        var typed = PamVaultHelpers.ResolveRecord(_vault, uid, PamRecordTypes.Rotation);
                        if (typed == null)
                        {
                            continue;
                        }

                        if (matcher != null && !matcher.IsMatch(typed.Title ?? ""))
                        {
                            continue;
                        }

                        recordUids.Add(uid);
                    }
                }
            }

            var records = new List<TypedRecord>();
            foreach (var uid in recordUids)
            {
                var record = PamVaultHelpers.ResolveRecord(_vault, uid, PamRecordTypes.Rotation);
                if (record != null)
                {
                    records.Add(record);
                }
            }

            return records;
        }

        private IEnumerable<string> EnumerateFolderRecordUids(FolderNode folder)
        {
            if (folder == null)
            {
                yield break;
            }

            foreach (var recordUid in folder.Records ?? Array.Empty<string>())
            {
                yield return recordUid;
            }

            foreach (var subfolderUid in folder.Subfolders ?? Array.Empty<string>())
            {
                if (_vault.TryGetFolder(subfolderUid, out var child))
                {
                    foreach (var uid in EnumerateFolderRecordUids(child))
                    {
                        yield return uid;
                    }
                }
            }
        }

        private void CollectFolderUids(FolderNode folder, ISet<string> folderUids)
        {
            if (folder == null)
            {
                return;
            }

            if (!string.IsNullOrEmpty(folder.FolderUid))
            {
                folderUids.Add(folder.FolderUid);
            }

            foreach (var subfolderUid in folder.Subfolders ?? Array.Empty<string>())
            {
                if (_vault.TryGetFolder(subfolderUid, out var child))
                {
                    CollectFolderUids(child, folderUids);
                }
            }
        }

        private sealed class ResourceConfigureSummary
        {
            public string RecordUid { get; set; }
            public string RecordTitle { get; set; }
            public string ConfigUid { get; set; }
            public string AdminUserUid { get; set; }
            public bool? RotationEnabled { get; set; }
        }

        private static void PrintResourceConfigureSummary(IReadOnlyList<ResourceConfigureSummary> summaries)
        {
            Console.WriteLine();
            foreach (var summary in summaries)
            {
                Console.WriteLine(
                    $"Resource \"{summary.RecordTitle}\" ({summary.RecordUid}) configured for PAM rotation.");
                Console.WriteLine($"  PAM Configuration: {summary.ConfigUid}");
                if (!string.IsNullOrEmpty(summary.AdminUserUid))
                {
                    Console.WriteLine($"  Admin user linked: {summary.AdminUserUid}");
                }

                if (summary.RotationEnabled == true)
                {
                    Console.WriteLine("  Rotation: Enabled");
                }
                else if (summary.RotationEnabled == false)
                {
                    Console.WriteLine("  Rotation: Disabled");
                }
            }
        }

        private async Task<bool> ConfigureResourceRecordAsync(
            TypedRecord resourceRecord,
            PamRotationOptions options,
            TypedRecord configRecord,
            Dictionary<string, TypedRecord> pamConfigs,
            List<object[]> skipped,
            List<ResourceConfigureSummary> configuredResources)
        {
            var configUid = configRecord?.Uid;
            if (string.IsNullOrEmpty(configUid) && !string.IsNullOrWhiteSpace(options.Config))
            {
                configUid = PamVaultHelpers.ResolveRecord(_vault, options.Config, PamRecordTypes.Configuration)?.Uid;
            }

            if (string.IsNullOrEmpty(configUid))
            {
                skipped.Add(new object[]
                {
                    resourceRecord.Uid,
                    resourceRecord.Title,
                    "No PAM Configuration",
                    "Specify a configuration UID parameter [--config]",
                });
                return false;
            }

            if (!pamConfigs.ContainsKey(configUid))
            {
                skipped.Add(new object[]
                {
                    resourceRecord.Uid,
                    resourceRecord.Title,
                    "PAM Configuration is invalid",
                    "Specify a configuration UID parameter [--config]",
                });
                return false;
            }

            try
            {
                await PamRotationGraphEdit.ConfigureResourceAsync(
                    _auth,
                    _vault,
                    resourceRecord,
                    configUid,
                    options.AdminUser,
                    options.Enable,
                    options.Disable);

                string adminUserUid = null;
                if (!string.IsNullOrWhiteSpace(options.AdminUser))
                {
                    var adminUser = PamVaultHelpers.ResolveRecord(
                        _vault,
                        options.AdminUser.Trim(),
                        new[] { "pamUser" });
                    adminUserUid = adminUser?.Uid;
                }

                var rotationEnabled = RotationUtils.ResolveRotationEnabled(options.Enable, options.Disable);

                configuredResources.Add(new ResourceConfigureSummary
                {
                    RecordUid = resourceRecord.Uid,
                    RecordTitle = resourceRecord.Title,
                    ConfigUid = configUid,
                    AdminUserUid = adminUserUid,
                    RotationEnabled = rotationEnabled,
                });
                return true;
            }
            catch (InvalidOperationException ex)
            {
                skipped.Add(new object[]
                {
                    resourceRecord.Uid,
                    resourceRecord.Title,
                    "Resource graph linking",
                    ex.Message,
                });
                return false;
            }
        }

        private string ResolveResourceUidForDag(
            TypedRecord record,
            PamRotationOptions options,
            TypedRecord configRecord,
            Dictionary<string, TypedRecord> pamConfigs)
        {
            if (!string.IsNullOrWhiteSpace(options.Resource))
            {
                var resource = PamVaultHelpers.ResolveRecord(_vault, options.Resource, null);
                return resource?.Uid;
            }

            var configUid = configRecord?.Uid;
            if (string.IsNullOrEmpty(configUid))
            {
                var cached = _vault.GetRecordRotation(record.Uid);
                configUid = cached?.ConfigurationUid;
            }

            if (string.IsNullOrEmpty(configUid) || !pamConfigs.TryGetValue(configUid, out var pamConfig))
            {
                return null;
            }

            var cachedRotation = _vault.GetRecordRotation(record.Uid);
            if (cachedRotation != null
                && !string.IsNullOrEmpty(cachedRotation.ResourceUid)
                && !string.Equals(cachedRotation.ResourceUid, configUid, StringComparison.Ordinal))
            {
                return cachedRotation.ResourceUid;
            }

            return GetDefaultResourceFromConfig(pamConfig);
        }


        private bool TryResolveRecordPath(string recordName, out FolderNode folderNode, out string title)
        {
            folderNode = null;
            title = null;
            if (_pathContext == null)
            {
                return false;
            }

            if (!_pathContext.TryResolvePath(recordName, out folderNode, out title) || string.IsNullOrEmpty(title))
            {
                return false;
            }

            var hasPathDelimiter = recordName.IndexOf('/') >= 0 || recordName.IndexOf('\\') >= 0;
            if (!hasPathDelimiter && string.Equals(title, recordName, StringComparison.Ordinal))
            {
                return false;
            }

            return true;
        }
    }
}
