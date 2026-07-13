using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Cli;
using Commander;
using CommandLine;
using Google.Protobuf;
using KeeperSecurity.Plugins.PAM;
using KeeperSecurity.Utils;
using KeeperSecurity.Vault;
using PamProto = PAM;
using RouterProto = Router;

namespace Commander.PAM
{
    internal class PamRotationCommand : PamCommandBase
    {
        public PamRotationCommand(IEnterpriseContext context) : base(context)
        {
        }

        public async Task ExecuteAsync(PamRotationOptions options)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options), "Invalid pam Rotation command arguments. Available commands: list, info, edit, script");
            }

            var command = string.IsNullOrEmpty(options.Command) ? "list" : options.Command.Trim().ToLowerInvariant();
            if (command == "script")
            {
                await ExecuteScriptAsync(options);
                return;
            }

            switch (command)
            {
                case "list":
                case "l":
                    await ListRotationsAsync(options);
                    break;
                case "info":
                case "i":
                    await RotationInfoAsync(options);
                    break;
                case "edit":
                case "new":
                case "n":
                case "e":
                    await EditRotationAsync(options);
                    break;
                default:
                    Console.WriteLine("Unsupported command. Available: list, info, edit, script");
                    break;
            }
        }

        private async Task ListRotationsAsync(PamRotationOptions options)
        {
            if (!await EnsurePluginAsync())
            {
                return;
            }

            var vault = Context.GetVault();
            var auth = Context.Enterprise.Auth;
            var schedulesResponse = await RouterUtils.GetRotationSchedulesAsync(auth);
            var schedules = schedulesResponse?.Schedules?.ToList() ?? new List<PamProto.PAMRotationSchedule>();

            var controllers = Plugin.Controllers.GetAll().ToDictionary(x => x.ControllerUid, x => x, StringComparer.Ordinal);
            var configs = vault != null ? PamVaultHelpers.GetConfigurationRecords(vault) : new Dictionary<string, TypedRecord>();

            var tab = new Tabulate(options.Verbose ? 8 : 6);
            if (options.Verbose)
            {
                tab.AddHeader("Record UID", "Record Title", "Record Type", "Schedule", "Gateway", "Gateway UID",
                    "PAM Configuration (Type)", "PAM Configuration UID");
            }
            else
            {
                tab.AddHeader("Record UID", "Record Title", "Record Type", "Schedule", "Gateway", "PAM Configuration (Type)");
            }

            var rows = new List<(string Title, object[] Row)>();
            foreach (var schedule in schedules.OrderBy(x => GetRecordTitle(vault, x.RecordUid?.ToByteArray().Base64UrlEncode())))
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
                var gatewayName = controller?.ControllerName ?? "[Does not exist]";
                var configText = configRecord != null
                    ? $"{configRecord.Title} ({configRecord.TypeName})"
                    : "[No config found]";

                object[] row;
                if (options.Verbose)
                {
                    row = new object[]
                    {
                        recordUid,
                        record.Title,
                        record.TypeName,
                        scheduleText,
                        gatewayName,
                        controllerUid,
                        configText,
                        configUid,
                    };
                }
                else
                {
                    row = new object[]
                    {
                        recordUid,
                        record.Title,
                        record.TypeName,
                        scheduleText,
                        gatewayName,
                        configText,
                    };
                }

                rows.Add((record.Title ?? "", row));
            }

            foreach (var row in rows.OrderBy(x => x.Title, StringComparer.OrdinalIgnoreCase).Select(x => x.Row))
            {
                tab.AddRow(row);
            }

            tab.Dump();
            if (rows.Count > 0)
            {
                Console.WriteLine();
                Console.WriteLine("To manually rotate a record (Phase 7): pam-action --command rotate --record-uid [RECORD UID]");
            }
            else
            {
                Console.WriteLine("No pamUser rotation schedules found.");
            }
        }

        private async Task RotationInfoAsync(PamRotationOptions options)
        {
            var recordId = options.EffectiveRecord;
            if (string.IsNullOrWhiteSpace(recordId))
            {
                Console.WriteLine("--record or --record-uid is required");
                return;
            }

            var vault = Context.GetVault();
            if (vault == null)
            {
                Console.WriteLine("Vault is not available.");
                return;
            }

            var record = TryResolvePamRecord(vault, recordId, PamRecordTypes.Rotation);
            if (record == null)
            {
                Console.WriteLine($"Record '{recordId}' not found");
                return;
            }

            var rotationInfo = await RotationUtils.GetRotationInfoAsync(Context.Enterprise.Auth, record.Uid);
            var statusName = rotationInfo.Status.ToString();
            var isReady = rotationInfo.Status == RouterProto.RouterRotationStatus.RrsOnline;
            var configUid = rotationInfo.ConfigurationUid?.ToByteArray().Base64UrlEncode() ?? "";
            var gatewayName = string.IsNullOrEmpty(rotationInfo.ControllerName) ? "-" : rotationInfo.ControllerName;
            var gatewayUid = rotationInfo.ControllerUid?.Length > 0
                ? rotationInfo.ControllerUid.ToByteArray().Base64UrlEncode()
                : "-";
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
            if (pwdComplexityRaw?.Length > 0
                && !RotationUtils.TryDecryptPasswordComplexity(pwdComplexityRaw, record.RecordKey, out pwdComplexityDetail))
            {
                pwdComplexityDecryptFailed = true;
                pwdComplexityDetail = null;
            }

            string scheduleType = null;
            string scheduleData = null;
            var schedulesResponse = await RouterUtils.GetRotationSchedulesAsync(Context.Enterprise.Auth);
            var schedule = schedulesResponse?.Schedules?
                .FirstOrDefault(x => x.RecordUid?.ToByteArray().Base64UrlEncode() == record.Uid);
            if (schedule != null)
            {
                scheduleType = schedule.NoSchedule ? "manual" : "scheduled";
                scheduleData = schedule.ScheduleData;
            }

            if (string.Equals(options.Format, "json", StringComparison.OrdinalIgnoreCase))
            {
                var result = new Dictionary<string, object>
                {
                    ["status"] = statusName,
                    ["ready_to_rotate"] = isReady,
                    ["pam_config_uid"] = configUid,
                    ["node_id"] = rotationInfo.NodeId,
                    ["gateway_name"] = gatewayName,
                    ["gateway_uid"] = gatewayUid,
                    ["admin_resource_uid"] = adminResourceUid,
                    ["password_complexity"] = pwdComplexityRaw?.Length > 0
                        ? rotationInfo.PwdComplexity
                        : null,
                    ["password_complexity_detail"] = pwdComplexityDecryptFailed
                        ? "[decrypt failed]"
                        : RotationUtils.PasswordComplexityToDetail(pwdComplexityDetail),
                    ["schedule_type"] = scheduleType,
                    ["schedule_data"] = scheduleData,
                    ["disabled"] = rotationInfo.Disabled,
                };
                Console.WriteLine(Encoding.UTF8.GetString(JsonUtils.DumpJson(result, indent: true)));
                return;
            }

            if (isReady)
            {
                Console.WriteLine($"Rotation Status: Ready to rotate ({statusName})");
                Console.WriteLine($"PAM Config UID: {configUid}");
                Console.WriteLine($"Node ID: {rotationInfo.NodeId}");
                Console.WriteLine($"Gateway Name: {gatewayName}");
                Console.WriteLine($"Gateway UID: {gatewayUid}");

                if (!string.IsNullOrEmpty(adminResourceUid))
                {
                    Console.WriteLine($"Admin Resource Uid: {adminResourceUid}");
                }

                if (pwdComplexityRaw?.Length > 0)
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

                if (schedule != null)
                {
                    var scheduleText = schedule.NoSchedule
                        ? "Manual Rotation"
                        : RotationUtils.FormatScheduleDisplay(schedule.ScheduleData, false);
                    Console.WriteLine($"Schedule: {scheduleText}");
                }

                Console.WriteLine();
                Console.WriteLine($"Command to manually rotate: pam-action --command rotate --record {record.Uid}");
            }
            else
            {
                Console.WriteLine($"Rotation Status: Not ready to rotate ({statusName})");
            }
        }

        private async Task EditRotationAsync(PamRotationOptions options)
        {
            if (!await EnsurePluginAsync())
            {
                return;
            }

            var vault = Context.GetVault();
            if (vault == null)
            {
                throw new VaultException("Vault is not available. Rotation edit requires a connected vault session.");
            }

            if (string.IsNullOrWhiteSpace(options.Record) && string.IsNullOrWhiteSpace(options.Folder))
            {
                Console.WriteLine("--record or --folder is required");
                return;
            }

            var pathContext = Context is ConnectedContext connected ? connected._vaultContext : null;
            var service = new PamRotationEditService(Plugin, Context.Enterprise.Auth, vault, pathContext);
            await service.ExecuteAsync(options);
        }

        private async Task ExecuteScriptAsync(PamRotationOptions options)
        {
            var scriptCommand = ResolveScriptSubcommand(options);
            switch (scriptCommand)
            {
                case "list":
                case "l":
                    ListScripts(options);
                    break;
                case "add":
                case "new":
                case "n":
                case "a":
                    await AddScriptAsync(options);
                    break;
                case "edit":
                case "e":
                    await EditScriptAsync(options);
                    break;
                case "delete":
                case "d":
                    await DeleteScriptAsync(options);
                    break;
                default:
                    Console.WriteLine("Unsupported script command. Available: list, new, add, edit, delete");
                    break;
            }
        }

        private async Task AddScriptAsync(PamRotationOptions options)
        {
            var recordId = ResolveScriptRecord(options);
            if (string.IsNullOrWhiteSpace(recordId))
            {
                Console.WriteLine("--record is required (or provide record UID as a positional argument)");
                return;
            }

            if (string.IsNullOrWhiteSpace(options.Script))
            {
                Console.WriteLine("--script is required");
                return;
            }

            var vault = Context.GetVault();
            if (vault == null)
            {
                Console.WriteLine("Vault is not available.");
                return;
            }

            var record = TryResolvePamRecord(vault, recordId, PamRecordTypes.Script);
            if (record == null)
            {
                Console.WriteLine($"Record '{recordId}' not found");
                return;
            }

            var filePath = Environment.ExpandEnvironmentVariables(options.Script.Trim());
            if (!File.Exists(filePath))
            {
                Console.WriteLine($"File \"{options.Script}\" not found.");
                return;
            }

            var scriptField = GetOrCreateScriptField(record);
            var facade = new TypedRecordFacade<TypedRecordFileRef>(record);
            var preRefs = GetFileRefUids(facade.Fields.FileRef);

            using (var uploadTask = new FileAttachmentUploadTask(filePath, isScript: true))
            {
                await vault.UploadAttachment(record, uploadTask);
            }

            var postRefs = GetFileRefUids(facade.Fields.FileRef);
            var newUids = postRefs.Except(preRefs).ToList();
            if (newUids.Count != 1)
            {
                Console.WriteLine(
                    "Failed to determine uploaded script file UID. "
                    + "Only the record owner can attach post-rotation scripts.");
                return;
            }

            facade.Fields.FileRef?.Values.Remove(newUids[0]);

            var scriptValue = new FieldScript
            {
                FileRef = newUids[0],
                RecordRef = ResolveCredentialUids(vault, options.AddCredential),
                Command = options.EffectiveRunCommand ?? "",
            };

            scriptField.Values.Add(scriptValue);
            await vault.UpdateRecord(record);
            Console.WriteLine($"Script added to record '{record.Title}' ({record.Uid}).");
        }

        private async Task EditScriptAsync(PamRotationOptions options)
        {
            var recordId = ResolveScriptRecord(options);
            if (string.IsNullOrWhiteSpace(recordId))
            {
                Console.WriteLine("--record is required (or provide record UID as a positional argument)");
                return;
            }

            if (string.IsNullOrWhiteSpace(options.Script))
            {
                Console.WriteLine("--script is required");
                return;
            }

            var vault = Context.GetVault();
            if (vault == null)
            {
                Console.WriteLine("Vault is not available.");
                return;
            }

            var record = TryResolvePamRecord(vault, recordId, PamRecordTypes.Script);
            if (record == null)
            {
                Console.WriteLine($"Record '{recordId}' not found");
                return;
            }

            var scriptValue = FindScriptValue(vault, record, options.Script.Trim(), out var scriptField);
            if (scriptField == null)
            {
                Console.WriteLine($"Record '{record.Title}' has no rotation scripts.");
                return;
            }

            if (scriptValue == null)
            {
                Console.WriteLine($"Record '{record.Title}' does not have script '{options.Script}'.");
                return;
            }

            var modified = false;
            var refs = new HashSet<string>(scriptValue.RecordRef ?? Array.Empty<string>(), StringComparer.Ordinal);
            if (options.RemoveCredential != null)
            {
                foreach (var cred in ResolveCredentialUids(vault, options.RemoveCredential))
                {
                    if (refs.Remove(cred))
                    {
                        modified = true;
                    }
                }
            }

            if (options.AddCredential != null)
            {
                foreach (var cred in ResolveCredentialUids(vault, options.AddCredential))
                {
                    if (refs.Add(cred))
                    {
                        modified = true;
                    }
                }
            }

            if (modified)
            {
                scriptValue.RecordRef = refs.ToArray();
            }

            if (!string.IsNullOrWhiteSpace(options.EffectiveRunCommand))
            {
                scriptValue.Command = options.EffectiveRunCommand;
                modified = true;
            }

            if (!modified)
            {
                Console.WriteLine("Nothing to do");
                return;
            }

            await vault.UpdateRecord(record);
            Console.WriteLine($"Script updated on record '{record.Title}' ({record.Uid}).");
        }

        private async Task DeleteScriptAsync(PamRotationOptions options)
        {
            var recordId = ResolveScriptRecord(options);
            if (string.IsNullOrWhiteSpace(recordId))
            {
                Console.WriteLine("--record is required (or provide record UID as a positional argument)");
                return;
            }

            if (string.IsNullOrWhiteSpace(options.Script))
            {
                Console.WriteLine("--script is required");
                return;
            }

            var vault = Context.GetVault();
            if (vault == null)
            {
                Console.WriteLine("Vault is not available.");
                return;
            }

            var record = TryResolvePamRecord(vault, recordId, PamRecordTypes.Script);
            if (record == null)
            {
                Console.WriteLine($"Record '{recordId}' not found");
                return;
            }

            var scriptValue = FindScriptValue(vault, record, options.Script.Trim(), out var scriptField);
            if (scriptField == null)
            {
                Console.WriteLine($"Record '{record.Title}' has no rotation scripts.");
                return;
            }

            if (scriptValue == null)
            {
                Console.WriteLine($"Record '{record.Title}' does not have script '{options.Script}'.");
                return;
            }

            scriptField.Values.Remove(scriptValue);
            await vault.UpdateRecord(record);
            Console.WriteLine($"Script removed from record '{record.Title}' ({record.Uid}).");
        }

        private static bool IsRotationScriptField(TypedField<FieldScript> field)
        {
            return string.Equals(field.FieldName, "script", StringComparison.Ordinal)
                   || string.Equals(field.FieldLabel, "rotationScripts", StringComparison.Ordinal);
        }

        private static string ResolveScriptSubcommand(PamRotationOptions options)
        {
            if (!string.IsNullOrWhiteSpace(options.ScriptSubCommand))
            {
                return options.ScriptSubCommand.Trim().ToLowerInvariant();
            }

            if (!string.IsNullOrWhiteSpace(options.ScriptCommand)
                && PamRotationOptions.ScriptVerbs.Contains(options.ScriptCommand.Trim()))
            {
                return options.ScriptCommand.Trim().ToLowerInvariant();
            }

            return "list";
        }

        private static string ResolveScriptRecord(PamRotationOptions options)
        {
            if (!string.IsNullOrWhiteSpace(options.Record))
            {
                return options.Record.Trim();
            }

            if (!string.IsNullOrWhiteSpace(options.RecordUid))
            {
                return options.RecordUid.Trim();
            }

            return options.ScriptArgument?.Trim();
        }

        private static string ResolveScriptPattern(PamRotationOptions options)
        {
            if (!string.IsNullOrWhiteSpace(options.Pattern))
            {
                return options.Pattern.Trim();
            }

            return options.ScriptArgument?.Trim();
        }

        private static TypedField<FieldScript> GetOrCreateScriptField(TypedRecord record)
        {
            var scriptField = record.Fields
                .OfType<TypedField<FieldScript>>()
                .FirstOrDefault(IsRotationScriptField);
            if (scriptField == null)
            {
                scriptField = new TypedField<FieldScript>("script", "rotationScripts");
                record.Fields.Add(scriptField);
            }

            return scriptField;
        }

        private static HashSet<string> GetFileRefUids(TypedField<string> fileRef)
        {
            if (fileRef == null)
            {
                return new HashSet<string>(StringComparer.Ordinal);
            }

            return fileRef.Values
                .Where(x => !string.IsNullOrEmpty(x))
                .ToHashSet(StringComparer.Ordinal);
        }

        private static FieldScript FindScriptValue(
            VaultOnline vault,
            TypedRecord record,
            string scriptName,
            out TypedField<FieldScript> scriptField)
        {
            scriptField = record.Fields
                .OfType<TypedField<FieldScript>>()
                .FirstOrDefault(IsRotationScriptField);
            if (scriptField == null)
            {
                return null;
            }

            foreach (var scriptValue in scriptField.Values)
            {
                if (scriptValue != null && scriptValue.FileRef == scriptName)
                {
                    return scriptValue;
                }
            }

            var scriptNameFolded = scriptName.ToLowerInvariant();
            foreach (var scriptValue in scriptField.Values)
            {
                if (string.IsNullOrEmpty(scriptValue?.FileRef))
                {
                    continue;
                }

                if (!vault.TryGetKeeperRecord(scriptValue.FileRef, out var keeperRecord)
                    || keeperRecord is not FileRecord fileRecord)
                {
                    continue;
                }

                if (string.Equals(fileRecord.Uid, scriptName, StringComparison.OrdinalIgnoreCase)
                    || string.Equals(fileRecord.Title, scriptName, StringComparison.OrdinalIgnoreCase)
                    || string.Equals(fileRecord.Title, scriptNameFolded, StringComparison.OrdinalIgnoreCase))
                {
                    return scriptValue;
                }
            }

            return null;
        }

        private static string[] ResolveCredentialUids(VaultOnline vault, IEnumerable<string> credentials)
        {
            if (credentials == null)
            {
                return Array.Empty<string>();
            }

            var refs = new List<string>();
            foreach (var credential in credentials.Where(x => !string.IsNullOrWhiteSpace(x)))
            {
                var cred = credential.Trim();
                if (vault.TryGetKeeperRecord(cred, out var record))
                {
                    refs.Add(record.Uid);
                }
            }

            return refs.ToArray();
        }

        private void ListScripts(PamRotationOptions options)
        {
            var vault = Context.GetVault();
            if (vault == null)
            {
                Console.WriteLine("Vault is not available.");
                return;
            }

            var pattern = ResolveScriptPattern(options);
            var tab = new Tabulate(7);
            tab.AddHeader("Record UID", "Title", "Record Type", "Script UID", "Script Name", "Records", "Command");

            foreach (var record in vault.KeeperRecords.OfType<TypedRecord>().Where(MatchesScriptRecord))
            {
                if (!MatchesPattern(record, pattern))
                {
                    continue;
                }

                foreach (var scriptField in record.Fields.OfType<TypedField<FieldScript>>().Where(IsRotationScriptField))
                {
                    foreach (var script in scriptField.Values)
                    {
                        if (string.IsNullOrEmpty(script?.FileRef))
                        {
                            continue;
                        }

                        vault.TryGetKeeperRecord(script.FileRef, out var fileRecord);
                        var recordRefs = script.RecordRef != null ? string.Join(", ", script.RecordRef) : "";
                        tab.AddRow(
                            record.Uid,
                            record.Title,
                            record.TypeName,
                            script.FileRef,
                            fileRecord?.Title ?? "[inaccessible]",
                            recordRefs,
                            script.Command ?? "");
                    }
                }
            }

            tab.Dump();
        }

        private static bool MatchesScriptRecord(TypedRecord record)
        {
            return PamRecordTypes.Script.Contains(record.TypeName ?? "");
        }

        private static bool MatchesPattern(KeeperRecord record, string pattern)
        {
            if (string.IsNullOrEmpty(pattern))
            {
                return true;
            }

            if (string.Equals(record.Uid, pattern, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            return record.Title != null
                && record.Title.IndexOf(pattern, StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private static string GetRecordTitle(VaultOnline vault, string recordUid)
        {
            if (vault != null && vault.TryGetKeeperRecord(recordUid, out var record))
            {
                return record.Title ?? recordUid;
            }

            return recordUid ?? "";
        }
    }

    internal class PamRotationOptions
    {
        internal static readonly HashSet<string> ScriptVerbs = new(StringComparer.OrdinalIgnoreCase)
        {
            "list", "l", "add", "new", "n", "a", "edit", "e", "delete", "d",
        };

        [Value(0, Required = false, HelpText = "Command: list, info, edit, script")]
        public string Command { get; set; }

        [Value(1, Required = false, HelpText = "Script subcommand when Command is script: list, add, edit, delete")]
        public string ScriptSubCommand { get; set; }

        [Value(2, Required = false, HelpText = "Record UID/title (script add/edit/delete) or filter pattern (script list)")]
        public string ScriptArgument { get; set; }

        [Option('f', "force", Required = false, Default = false, HelpText = "Skip confirmation prompts (edit command)")]
        public bool Force { get; set; }

        [Option('r', "record", Required = false, HelpText = "Record UID, name, or pattern")]
        public string Record { get; set; }

        [Option("record-uid", Required = false, HelpText = "Record UID (info command alias)")]
        public string RecordUid { get; set; }

        [Option("folder", Required = false, HelpText = "Folder UID or name for bulk rotation setup (-fd in Python Commander)")]
        public string Folder { get; set; }

        [Option('c', "config", Required = false, HelpText = "PAM configuration UID or title")]
        public string Config { get; set; }

        [Option("iam-aad-config", Required = false, HelpText = "IAM/Azure AD PAM configuration UID (-iac in Python Commander)")]
        public string IamAadConfig { get; set; }

        [Option("rotation-profile", Required = false,
            HelpText = "Rotation profile: general, iam_user, scripts_only, saas (-rp in Python Commander)")]
        public string RotationProfile { get; set; }

        [Option("saas-config-uid", Required = false, HelpText = "SaaS configuration UID for saas profile")]
        public string SaasConfigUid { get; set; }

        [Option("resource", Required = false, HelpText = "Admin resource record UID or title (-rs in Python Commander)")]
        public string Resource { get; set; }

        [Option("schedule-json", Required = false, HelpText = "Rotation schedule JSON array (-sj/--schedulejson in Python Commander)")]
        public string ScheduleJson { get; set; }

        [Option("schedule-cron", Required = false, HelpText = "Rotation schedule CRON expression (-sc/--schedulecron in Python Commander)")]
        public string ScheduleCron { get; set; }

        [Option("on-demand", Required = false, HelpText = "Configure manual (on-demand) rotation (-od in Python Commander)")]
        public bool OnDemand { get; set; }

        [Option("schedule-config", Required = false, HelpText = "Inherit schedule from PAM configuration (-sf in Python Commander)")]
        public bool ScheduleConfig { get; set; }

        [Option("schedule-only", Required = false, HelpText = "Only update rotation schedule (-so in Python Commander)")]
        public bool ScheduleOnly { get; set; }

        [Option('x', "complexity", Required = false,
            HelpText = "Password complexity: length,upper,lower,digits,symbols[,chars]. Ex: 32,5,5,5,5")]
        public string Complexity { get; set; }

        [Option("complexity-json", Required = false, HelpText = "Password complexity rules as JSON")]
        public string ComplexityJson { get; set; }

        [Option('a', "admin-user", Required = false, HelpText = "PAM user record UID to set as admin credential on resource")]
        public string AdminUser { get; set; }

        [Option('e', "enable", Required = false, HelpText = "Enable rotation")]
        public bool Enable { get; set; }

        [Option('d', "disable", Required = false, HelpText = "Disable rotation")]
        public bool Disable { get; set; }

        [Option('v', "verbose", Required = false, HelpText = "Verbose output")]
        public bool Verbose { get; set; }

        [Option("format", Required = false, HelpText = "Output format: table, json (info command)")]
        public string Format { get; set; }

        [Option("script-command", Required = false, HelpText = "Script run command or subcommand if list/add/edit/delete")]
        public string ScriptCommand { get; set; }

        [Option("script", Required = false, HelpText = "Script file path (add) or script UID/name (edit/delete)")]
        public string Script { get; set; }

        [Option("run-command", Required = false, HelpText = "Script command line to run (Python: --script-command)")]
        public string RunCommand { get; set; }

        [Option("add-credential", Required = false, HelpText = "Record UID with rotation credential (add/edit, -ac in Python Commander)")]
        public IEnumerable<string> AddCredential { get; set; }

        [Option("remove-credential", Required = false, HelpText = "Remove rotation credential record UID (edit, -rc in Python Commander)")]
        public IEnumerable<string> RemoveCredential { get; set; }

        [Option("pattern", Required = false, HelpText = "Record UID or title filter for script list")]
        public string Pattern { get; set; }

        public string EffectiveRecord => !string.IsNullOrWhiteSpace(Record) ? Record : RecordUid;

        public string EffectiveRunCommand
        {
            get
            {
                if (!string.IsNullOrWhiteSpace(RunCommand))
                {
                    return RunCommand;
                }

                if (!string.IsNullOrWhiteSpace(ScriptCommand)
                    && !PamRotationOptions.ScriptVerbs.Contains(ScriptCommand.Trim()))
                {
                    return ScriptCommand.Trim();
                }

                return null;
            }
        }
    }
}
