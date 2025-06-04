using Cli;
using CommandLine;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Vault;
using KeeperSecurity.Utils;
using System.Reflection;
using System.Runtime.Serialization;
using System.Globalization;
using System.Text.RegularExpressions;
using System.IO;
using System.Text;

namespace Commander
{
    internal partial class VaultContext
    {

        private const string FieldPattern = @"^([^\[\.]+)(\.[^\[]+)?(\[.*\])?\s*=\s*(.*)$";

        public static IEnumerable<CmdLineRecordField> ParseRecordFields(IEnumerable<string> inputs)
        {
            var rx = new Regex(FieldPattern);
            foreach (var f in inputs)
            {
                var field = f;
                var crf = new CmdLineRecordField();
                var match = rx.Match(field);
                if (!match.Success || match.Groups.Count < 5)
                {
                    throw new Exception($"Invalid field parameter: {f}");
                }

                crf.FieldName = match.Groups[1].Value.Trim();
                crf.FieldLabel = match.Groups[2].Value.Trim('.').Trim();
                crf.FieldIndex = match.Groups[3].Value.Trim('[', ']').Trim();
                crf.Value = match.Groups[4].Value.Trim();
                if (crf.Value.Length >= 2 && crf.Value.StartsWith("\"") && crf.Value.EndsWith("\""))
                {
                    crf.Value = crf.Value.Trim('"').Replace("\\\"", "\"");
                }

                yield return crf;
            }
        }

        public void AssignRecordFields(KeeperRecord record, CmdLineRecordField[] fields)
        {
            if (record is PasswordRecord password)
            {
                foreach (var field in fields)
                {
                    switch (field.FieldName.ToLowerInvariant())
                    {
                        case "login":
                            password.Login = field.Value;
                            break;
                        case "password":
                            password.Password = field.Value;
                            break;
                        case "notes":
                            password.Notes = field.Value;
                            break;
                        default:
                            password.SetCustomField(field.FieldName, field.Value);
                            break;
                    }
                }
            }
            else if (record is TypedRecord typed)
            {
                if (Vault.TryGetRecordTypeByName(typed.TypeName, out var recordType))
                {
                    VerifyTypedFields(fields, recordType);
                }

                var indexes = new Dictionary<string, int>(StringComparer.InvariantCultureIgnoreCase);
                foreach (var f in typed.Fields.Concat(typed.Custom))
                {
                    if (f.Count <= 1) continue;
                    var fullName = f.GetTypedFieldName();
                    for (var i = 1; i < f.Count; i++)
                    {
                        indexes.Add($"{fullName}[{i}]", i);
                    }
                }

                var fieldSet = fields.Where(x => !string.IsNullOrEmpty(x.Value)).ToArray();
                var fieldDelete = fields.Where(x => string.IsNullOrEmpty(x.Value)).ToArray();
                foreach (var field in fieldSet.Concat(fieldDelete))
                {
                    if (string.Equals(field.FieldName, "notes", StringComparison.InvariantCultureIgnoreCase))
                    {
                        if (string.IsNullOrEmpty(typed.Notes))
                        {
                            typed.Notes = "";
                        }
                        else
                        {
                            typed.Notes += "\n";
                        }
                        typed.Notes += field.Value;
                    }
                    else
                    {
                        if (!typed.FindTypedField(field, out var typedField))
                        {
                            if (string.IsNullOrEmpty(field.Value)) continue;
                            typedField = field.CreateTypedField();
                            typed.Custom.Add(typedField);
                        }


                        if (string.IsNullOrEmpty(field.Value))
                        {
                            if (string.IsNullOrEmpty(field.FieldIndex))
                            {
                                while (typedField.Count > 0)
                                {
                                    typedField.DeleteValueAt(0);
                                }
                            }
                            else
                            {
                                var fullName = field.GetTypedFieldName();
                                var valuePath = $"{fullName}[{field.FieldIndex}]";
                                if (!indexes.TryGetValue(valuePath, out var idx))
                                {
                                    if (idx >= 0 && idx < typedField.Count)
                                    {
                                        typedField.DeleteValueAt(idx);
                                    }
                                    indexes.Remove(valuePath);
                                }
                            }
                        }
                        else
                        {
                            var idx = 0;
                            if (!string.IsNullOrEmpty(field.FieldIndex))
                            {
                                var fullName = field.GetTypedFieldName();
                                var valuePath = $"{fullName}[{field.FieldIndex}]";
                                if (!indexes.TryGetValue(valuePath, out idx))
                                {
                                    typedField.AppendValue();
                                    idx = typedField.Count - 1;
                                    indexes.Add(valuePath, idx);
                                }
                            }

                            if (typedField.Count == 0)
                            {
                                typedField.AppendValue();
                            }

                            if (typedField is TypedField<string> tfs)
                            {
                                tfs.Values[idx] = field.Value;
                            }
                            else if (typedField is TypedField<long> tfl)
                            {
                                if (!long.TryParse(field.Value, out var lv))
                                {
                                    if (DateTimeOffset.TryParse(field.Value, CultureInfo.CurrentCulture, DateTimeStyles.AssumeUniversal, out var dto))
                                    {
                                        lv = dto.ToUnixTimeMilliseconds();
                                    }
                                    else
                                    {
                                        throw new Exception($"Field \"{field.FieldName}\": invalid value \"{field.Value}\"");
                                    }
                                }
                                tfl.Values[idx] = lv;
                            }
                            else
                            {
                                if (typedField.GetValueAt(idx) is IFieldTypeSerialize typedValue)
                                {
                                    typedValue.SetValueAsString(field.Value);
                                }
                                else
                                {
                                    throw new Exception($"Field type {field.FieldName}: Value serialization is not supported.");
                                }
                            }
                        }
                    }
                }
            }
        }

        private void VerifyTypedFields(CmdLineRecordField[] fields, RecordType recordType)
        {
            foreach (var field in fields)
            {
                if (string.Equals(field.FieldName, "notes", StringComparison.InvariantCultureIgnoreCase))
                {
                    continue;
                }

                if (string.IsNullOrEmpty(field.Value)) continue;

                if (!RecordTypesConstants.TryGetRecordField(field.FieldName, out var recordField))
                {
                    if (string.IsNullOrEmpty(field.FieldLabel))
                    {
                        field.FieldLabel = field.FieldName;
                        field.FieldName = "text";
                    }
                    else
                    {
                        throw new Exception($"Record field \"{field.FieldName}\" is not supported.");
                    }
                }

                if (string.IsNullOrEmpty(field.FieldIndex)) continue;

                if (recordField.Multiple != RecordFieldMultiple.Always)
                {
                    throw new Exception($"Record field \"{field.FieldName}\" does not support multiple values");
                }
            }
        }
    }

    internal static class RecordCommandExtensions
    {
        public static Task RecordTypeInfoCommand(this VaultContext context, RecordTypeInfoOptions options)
        {
            Tabulate table;
            if (string.IsNullOrEmpty(options.Name))
            {
                if (options.ShowFields)
                {
                    table = new Tabulate(4);
                    table.AddHeader("Field Type ID", "Type", "Multiple", "Description");
                    foreach (var f in RecordTypesConstants.RecordFields)
                    {
                        table.AddRow(f.Name, f.Type?.Name,
                            f.Multiple == RecordFieldMultiple.Optional
                                ? "optional"
                                : (f.Multiple == RecordFieldMultiple.Always ? "default" : ""),
                            f.Type?.Description ?? "");
                    }
                }
                else
                {
                    table = new Tabulate(3)
                    {
                        LeftPadding = 4
                    };
                    table.SetColumnRightAlign(0, true);
                    table.AddHeader("Record Type ID", "Type Name", "Scope", "Description");
                    foreach (var rt in context.Vault.RecordTypes)
                    {
                        table.AddRow(rt.Id, rt.Name, rt.Scope.ToText(), rt.Description);
                    }

                    table.Sort(0);
                }
            }
            else
            {
                if (options.ShowFields)
                {
                    if (!RecordTypesConstants.TryGetRecordField(options.Name, out var fieldInfo))
                    {
                        Console.WriteLine($"Error - Unknown field type: {options.Name}");
                        return Task.FromResult(false);
                    }

                    table = new Tabulate(2)
                    {
                        LeftPadding = 4
                    };
                    table.SetColumnRightAlign(0, true);
                    table.AddRow("Field Type ID:", fieldInfo.Name);
                    table.AddRow("Type:", fieldInfo.Type.Name);
                    var valueType = "";
                    if (fieldInfo.Type != null)
                    {
                        if (fieldInfo.Type?.Type == typeof(string))
                        {
                            valueType = "string";
                        }
                        else if (fieldInfo.Type?.Type == typeof(long))
                        {
                            valueType = "integer";
                        }
                        else
                        {
                            valueType = "object";
                        }
                    }

                    table.AddRow("Value Type:", valueType);
                    if (fieldInfo.Type != null)
                    {
                        if (typeof(IFieldTypeSerialize).IsAssignableFrom(fieldInfo.Type.Type))
                        {
                            var elements = new List<string>();
                            var properties = fieldInfo.Type.Type.GetProperties();
                            foreach (var prop in properties)
                            {
                                var attribute = prop.GetCustomAttribute<DataMemberAttribute>(true);
                                if (attribute != null)
                                {
                                    elements.Add(attribute.Name);
                                }
                            }

                            table.AddRow("Value Elements:", string.Join(", ", elements.Select(x => $"\"{x}\"")));
                        }
                    }
                }
                else
                {
                    if (!context.Vault.TryGetRecordTypeByName(options.Name, out var recordInfo))
                    {
                        Console.WriteLine($"Error - Unknown record type: {options.Name}");
                        return Task.FromResult(false);
                    }

                    table = new Tabulate(2)
                    {
                        LeftPadding = 4
                    };
                    table.SetColumnRightAlign(0, true);
                    table.AddRow("Record Type ID:", recordInfo.Id);
                    table.AddRow("Type Name:", recordInfo.Name);
                    table.AddRow("Scope:", recordInfo.Scope.ToText());
                    table.AddRow("Description:", recordInfo.Description);
                    var fields = recordInfo.Fields
                        .Select(x =>
                            $"{x.FieldLabel ?? ""} ({(string.IsNullOrEmpty(x.FieldName) ? "text" : x.FieldName)})"
                                .Trim())
                        .ToArray();
                    for (var i = 0; i < Math.Max(fields.Length, 1); i++)
                    {
                        table.AddRow(i == 0 ? "Fields:" : "", i < fields.Length ? fields[i] : "");
                    }
                }
            }

            table.Dump();
            return Task.FromResult(true);
        }

        public static async Task AddRecordCommand(this VaultContext context, AddRecordOptions options)
        {
            if (!context.TryResolvePath(options.Folder, out var node))
            {
                Console.WriteLine($"Cannot resolve folder {options.Folder}");
                return;
            }
            if (string.IsNullOrEmpty(options.Title))
            {
                Console.WriteLine($"\"Title\" parameter is missing.");
                return;
            }
            var fields = VaultContext.ParseRecordFields(options.Fields).ToArray();

            KeeperRecord record;
            if (string.Equals(options.RecordType, "general", StringComparison.InvariantCultureIgnoreCase) ||
                string.Equals(options.RecordType, "legacy", StringComparison.InvariantCultureIgnoreCase))
            {
                record = new PasswordRecord
                {
                    Title = options.Title
                };
            }
            else
            {
                var typedRecord = new TypedRecord(options.RecordType)
                {
                    Title = options.Title
                };

                if (context.Vault.TryGetRecordTypeByName(options.RecordType, out var rt))
                {
                    foreach (var rtf in rt.Fields)
                    {
                        try
                        {
                            var field = rtf.CreateTypedField();
                            typedRecord.Fields.Add(field);
                        }
                        catch { /* ignored */ }
                    }
                }

                record = typedRecord;
            }
            if (options.Generate)
            {
                context.Vault.RotateRecordPassword(record);
            }

            context.AssignRecordFields(record, fields);
            await context.Vault.CreateRecord(record, node.FolderUid);
        }


        public static async Task UpdateRecordCommand(this VaultContext context, UpdateRecordOptions options)
        {
            if (context.Vault.TryGetKeeperRecord(options.RecordId, out var record))
            {
            }
            else if (context.TryResolvePath(options.RecordId, out var node, out var title))
            {
                foreach (var uid in node.Records)
                {
                    if (!context.Vault.TryGetKeeperRecord(uid, out var r)) continue;
                    if (string.CompareOrdinal(title, r.Title) != 0) continue;

                    record = r;
                    break;
                }
            }

            if (record == null)
            {
                Console.WriteLine($"Cannot resolve record {options.RecordId}");
                return;
            }
            if (!string.IsNullOrEmpty(options.RecordType))
            {
                if (record is TypedRecord typed)
                {
                    if (context.Vault.TryGetRecordTypeByName(options.RecordType, out var rt))
                    {
                        typed.TypeName = rt.Name;
                    }
                }
                else
                {
                    Console.WriteLine($"{options.RecordId} is a legacy record. Record type is not supported.");
                    return;
                }
            }

            if (!string.IsNullOrEmpty(options.Title))
            {
                record.Title = options.Title;
            }

            if (options.Generate)
            {
                context.Vault.RotateRecordPassword(record);
            }

            var fields = VaultContext.ParseRecordFields(options.Fields).ToArray();
            context.AssignRecordFields(record, fields);
            await context.Vault.UpdateRecord(record);
        }

        public static async Task DownloadAttachmentCommand(this VaultContext context, DownloadAttachmentOptions options)
        {
            if (context.Vault.TryGetKeeperRecord(options.RecordName, out var record))
            {
            }
            else if (context.TryResolvePath(options.RecordName, out var node, out var title))
            {
                foreach (var uid in node.Records)
                {
                    if (!context.Vault.TryGetKeeperRecord(uid, out var r)) continue;
                    if (string.CompareOrdinal(title, r.Title) != 0) continue;

                    record = r;
                    break;
                }
            }

            if (record == null)
            {
                Console.WriteLine($"Cannot resolve record {options.RecordName}");
                return;
            }

            if (string.IsNullOrEmpty(options.OutputDirectory))
            {
                options.OutputDirectory = Directory.GetCurrentDirectory();
            }
            else
            {
                var dirEntry = Directory.CreateDirectory(options.OutputDirectory);
                options.OutputDirectory = dirEntry.FullName;
            }

            var attas = context.Vault.RecordAttachments(record)
                .Where(x =>
                {
                    if (string.IsNullOrEmpty(options.FileName))
                    {
                        return true;
                    }

                    if (string.Equals(options.FileName, x.Id))
                    {
                        return true;
                    }

                    if (string.Equals(options.FileName, x.Title, StringComparison.InvariantCultureIgnoreCase))
                    {
                        return true;
                    }

                    if (string.Equals(options.FileName, x.Name, StringComparison.InvariantCultureIgnoreCase))
                    {
                        return true;
                    }

                    return false;
                }).ToArray();

            if (attas.Length > 0)
            {
                foreach (var atta in attas)
                {
                    Console.Write($"Downloading {atta.Name} ...");
                    try
                    {
                        using (var stream = File.OpenWrite(Path.Combine(options.OutputDirectory, atta.Name)))
                        {
                            switch (atta)
                            {
                                case AttachmentFile af:
                                    await context.Vault.DownloadAttachmentFile(record.Uid, af, stream);
                                    break;
                                case FileRecord fr:
                                    await context.Vault.DownloadFile(fr, stream);
                                    break;
                            }
                        }

                        Console.WriteLine(" Done.");
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine($"Failed: {e.Message}");
                    }
                }
            }
            else
            {
                Console.WriteLine($"Attachment not found: {(options.FileName ?? "")}");
            }
        }

        public static async Task UploadAttachmentCommand(this VaultContext context, UploadAttachmentOptions options)
        {
            if (context.Vault.TryGetKeeperRecord(options.RecordName, out var record))
            {
            }
            else if (context.TryResolvePath(options.RecordName, out var node, out var title))
            {
                foreach (var uid in node.Records)
                {
                    if (!context.Vault.TryGetKeeperRecord(uid, out var r)) continue;
                    if (string.CompareOrdinal(title, r.Title) != 0) continue;

                    record = r;
                    break;
                }
            }

            if (record == null)
            {
                Console.WriteLine($"Cannot resolve record {options.RecordName}");
                return;
            }

            if (!File.Exists(options.FileName))
            {
                Console.WriteLine($"File {options.FileName} not found.");
                return;
            }

            var uploadTask = new FileAttachmentUploadTask(options.FileName);
            await context.Vault.UploadAttachment(record, uploadTask);
        }

        public static async Task RemoveRecordCommand(this VaultContext context, RemoveRecordOptions options)
        {
            if (string.IsNullOrEmpty(options.RecordName))
            {
                return;
            }

            if (context.Vault.TryGetKeeperRecord(options.RecordName, out var record))
            {
                var folders = Enumerable.Repeat(context.Vault.RootFolder, 1).Concat(context.Vault.Folders)
                    .Where(x => x.Records.Contains(record.Uid)).ToArray();
                if (folders.Length == 0)
                {
                    Console.WriteLine("not expected");
                    return;
                }

                var folder = folders.Length == 1
                    ? folders[0]
                    : folders.FirstOrDefault(x => x.FolderUid == context.CurrentFolder)
                      ?? folders.FirstOrDefault(x => string.IsNullOrEmpty(x.FolderUid))
                      ?? folders.FirstOrDefault(x => x.FolderType == FolderType.UserFolder)
                      ?? folders[0];

                await context.Vault.DeleteRecords(new[]
                    {new RecordPath {FolderUid = folder.FolderUid, RecordUid = record.Uid,}});
            }
            else
            {
                if (!context.TryResolvePath(options.RecordName, out var folder, out string recordTitle))
                {
                    Console.WriteLine($"Invalid record path: {options.RecordName}");
                    return;
                }

                var sb = new StringBuilder();
                sb.Append(recordTitle);
                sb = sb.Replace("*", ".*");
                sb = sb.Replace("?", @".");
                sb = sb.Replace("#", @"[0-9]");
                sb.Insert(0, "^");
                sb.Append("$");
                var pattern = sb.ToString();

                var records = new List<RecordPath>();
                foreach (var recordUid in folder.Records)
                {
                    if (!context.Vault.TryGetKeeperRecord(recordUid, out record)) continue;

                    var m = Regex.Match(record.Title, pattern, RegexOptions.IgnoreCase);
                    if (m.Success)
                    {
                        records.Add(new RecordPath { FolderUid = folder.FolderUid, RecordUid = recordUid });
                    }
                }

                await context.Vault.DeleteRecords(records.ToArray());
            }
        }

        public static async Task ShareRecordShareCommand(this VaultContext context, ShareRecordShareOptions options)
        {
            var record = ResolveKeeperRecord(context, options.RecordName);
            try
            {
                var shareOptions = new SharedFolderRecordOptions
                {
                    CanEdit = options.CanEdit,
                    CanShare = options.CanShare,
                };
                if (!string.IsNullOrEmpty(options.ExpireAt))
                {
                    shareOptions.Expiration = DateTimeOffset.ParseExact(options.ExpireAt, "yyyy-MM-dd hh:mm:ss", CultureInfo.InvariantCulture);
                }
                else if (!string.IsNullOrEmpty(options.ExpireIn))
                {
                    var ts = ParseUtils.ParseTimePeriod(options.ExpireIn);
                    shareOptions.Expiration = DateTimeOffset.Now + ts;
                }
                await context.Vault.ShareRecordWithUser(record.Uid, options.Email, shareOptions);
            }
            catch (NoActiveShareWithUserException e)
            {
                Console.WriteLine(e.Message);
                Console.Write(
                    $"Do you want to send share invitation request to \"{e.Username}\"? (Yes/No) : ");
                var answer = await Program.GetInputManager().ReadLine();
                if (string.Equals("y", answer, StringComparison.InvariantCultureIgnoreCase))
                {
                    answer = "yes";
                }
                if (string.Equals(answer, "yes", StringComparison.InvariantCultureIgnoreCase))
                {
                    await context.Vault.SendShareInvitationRequest(e.Username);
                    Console.WriteLine($"Invitation has been sent to {e.Username}\nPlease repeat this command when your invitation is accepted.");
                }
            }
        }

        public static async Task ShareRecordCancelCommand(this VaultContext context, ShareRecordCancelOptions options)
        {
            Console.Write(
                $"Do you want to cancel all shares with user \"{options.Email}\"? (Yes/No) : ");
            var answer = await Program.GetInputManager().ReadLine();
            if (string.Compare("y", answer, StringComparison.InvariantCultureIgnoreCase) == 0)
            {
                answer = "yes";
            }

            if (string.Compare(answer, "yes", StringComparison.InvariantCultureIgnoreCase) != 0) return;
            await context.Vault.CancelSharesWithUser(options.Email);
        }

        public static async Task ShareRecordRevokeCommand(this VaultContext context, ShareRecordRevokeOptions options)
        {
            var record = ResolveKeeperRecord(context, options.RecordName);
            await context.Vault.RevokeShareFromUser(record.Uid, options.Email);
        }
        public static async Task ShareRecordTransferCommand(this VaultContext context, ShareRecordTransferOptions options)
        {
            var record = ResolveKeeperRecord(context, options.RecordName);
            await context.Vault.TransferRecordToUser(record.Uid, options.Email);
        }

        public static async Task RecordTypeAddCommand(this VaultContext context, RecordTypeAddOptions recordTypeData)
        {
            var data = recordTypeData.data;
            if (string.IsNullOrEmpty(data))
            {
                throw new Exception("\"record-type-add\" command requires data parameter");
            }
            if (data.StartsWith("@"))
            {
                data = ExtractDataFromFile(data);
            }
            var createdRecordTypeID = await context.Vault.AddRecordType(data);
            Console.WriteLine($"Created Record Type ID: {createdRecordTypeID}");
        }

        public static async Task RecordTypeUpdateCommand(this VaultContext context, RecordTypeUpdateOptions recordTypeData)
        {
            if (string.IsNullOrEmpty(recordTypeData.recordTypeId))
            {
                throw new Exception("\"record-type-update\" command requires recordTypeId parameter");
            }
            var data = recordTypeData.data;
            if (string.IsNullOrEmpty(data))
            {
                throw new Exception("\"record-type-update\" command requires data parameter");
            }
            if (data.StartsWith("@"))
            {
                data = ExtractDataFromFile(data);
            }
            var updatedRecordTypeID = await context.Vault.UpdateRecordTypeAsync(recordTypeData.recordTypeId, data);
            Console.WriteLine($"Updated Record Type ID: {updatedRecordTypeID}");
        }

        public static async Task RecordTypeDeleteCommand(this VaultContext context, RecordTypeDeleteOptions recordTypeData)
        {
            if (string.IsNullOrEmpty(recordTypeData.recordTypeId))
            {
                throw new Exception("\"record-type-delete\" command requires recordTypeId parameter");
            }

            var deletedRecordTypeID = await context.Vault.DeleteRecordTypeAsync(recordTypeData.recordTypeId);
            Console.WriteLine($"Deleted Record Type ID: {deletedRecordTypeID}");
        }

        public static async Task RecordTypeLoadCommand(this VaultContext context, RecordTypeLoadOptions recordTypeData)
        {          
            var createdRecordTypeIDs = await context.Vault.LoadRecordTypesAsync(recordTypeData.filePath);
            Console.WriteLine($"Created Record Type IDs: {string.Join(", ",createdRecordTypeIDs)}");
        }

        private static string ExtractDataFromFile(string filePath)
        {
            var path = filePath.Substring(1).Trim('"', '(', ')', '\'');

            try
            {
                path = Path.GetFullPath(path);
            }
            catch (Exception error)
            {
                Console.Error.WriteLine($"Error reading the file at path: {error}");
            }

            if (!File.Exists(path))
            {
                throw new FileNotFoundException($"File not found: {path}");
            }

            return File.ReadAllText(path);
        }

        private static KeeperRecord ResolveKeeperRecord(VaultContext context, string recordName)
        {
            if (string.IsNullOrEmpty(recordName))
            {
                throw new CommandError("Record parameter cannot be empty");
            }

            if (context.Vault.TryGetKeeperRecord(recordName, out var record))
            {
            }
            else if (context.TryResolvePath(recordName, out var node, out var title))
            {
                foreach (var uid in node.Records)
                {
                    if (!context.Vault.TryGetKeeperRecord(uid, out var r)) continue;
                    if (string.CompareOrdinal(title, r.Title) != 0) continue;

                    record = r;
                    break;
                }
            }

            if (record == null)
            {
                throw new CommandError($"Cannot resolve record \"{recordName}\"");
            }
            return record;
        }
    }

    class RecordTypeInfoOptions
    {
        [Option('f', "field", Required = false, HelpText = "Show field. ")]
        public bool ShowFields { get; set; }

        [Value(0, Required = false, HelpText = "record or field type name")]
        public string Name { get; set; }
    }

    class AddRecordOptions
    {
        [Option("folder", Required = false, HelpText = "folder")]
        public string Folder { get; set; }

        [Option('t', "type", Required = true, HelpText = "record type.")]
        public string RecordType { get; set; }

        [Option("title", Required = true, HelpText = "record title.")]
        public string Title { get; set; }

        [Option('g', "generate", Required = false, Default = false, HelpText = "generate random password")]
        public bool Generate { get; set; }

        [Value(0, Required = false, MetaName = "Record fields", HelpText = "Record fields")]
        public IEnumerable<string> Fields { get; set; }
    }

    class UpdateRecordOptions
    {
        [Option("title", Required = false, HelpText = "title")]
        public string Title { get; set; }

        [Option('t', "type", Required = false, HelpText = "record type. typed records only.")]
        public string RecordType { get; set; }

        [Option('g', "generate", Required = false, Default = false, HelpText = "generate random password")]
        public bool Generate { get; set; }

        [Value(0, Required = true, MetaName = "record", HelpText = "record path or UID")]
        public string RecordId { get; set; }

        [Value(1, Required = false, MetaName = "Record fields", HelpText = "Record fields")]
        public IEnumerable<string> Fields { get; set; }
    }

    class DownloadAttachmentOptions
    {
        [Option('o', "output-dir", Required = false, Default = null, HelpText = "Output directory")]
        public string OutputDirectory { get; set; }

        [Option('f', "file", Required = false, Default = null, HelpText = "Attachment UID, name, or title")]
        public string FileName { get; set; }


        [Value(0, Required = true, MetaName = "record path or uid", HelpText = "Keeper Record")]
        public string RecordName { get; set; }
    }

    class UploadAttachmentOptions
    {
        [Option('f', "file", Required = true, Default = null, HelpText = "File path")]
        public string FileName { get; set; }


        [Value(0, Required = true, MetaName = "record path or uid", HelpText = "Keeper Record")]
        public string RecordName { get; set; }
    }

    class RemoveRecordOptions
    {
        [Value(0, Required = true, MetaName = "record title, uid, or pattern", HelpText = "remove records")]
        public string RecordName { get; set; }
    }

    [Verb("cancel", HelpText = "Cancels all shares with a user")]
    class ShareRecordCancelOptions
    {
        [Value(0, Required = true, MetaName = "email", HelpText = "peer account email")]
        public string Email { get; set; }
    }

    [Verb("revoke", HelpText = "Revokes a record share")]
    class ShareRecordRevokeOptions
    {
        [Option('e', "email", Required = true, HelpText = "peer account email")]
        public string Email { get; set; }

        [Value(0, Required = true, MetaName = "record", HelpText = "record path or UID")]
        public string RecordName { get; set; }
    }

    [Verb("transfer", HelpText = "Transfer a record / change record ownership")]
    class ShareRecordTransferOptions
    {
        [Option('e', "email", Required = true, HelpText = "peer account email")]
        public string Email { get; set; }

        [Value(0, Required = true, MetaName = "record", HelpText = "record path or UID")]
        public string RecordName { get; set; }
    }


    [Verb("share", HelpText = "Share a record with a user")]
    class ShareRecordShareOptions
    {
        [Option('s', "share", Required = false, Default = null, HelpText = "can re-share record")]
        public bool? CanShare { get; set; }

        [Option('w', "write", Required = false, Default = null, HelpText = "can modify record")]
        public bool? CanEdit { get; set; }

        [Option("expire-at", Required = false, Default = null, HelpText = "expire share at ISO time: YYYY-MM-DD HH:mm:SS")]
        public string ExpireAt { get; set; }

        [Option("expire-in", Required = false, Default = null, HelpText = "expire share in period: [N]mi|h|d|mo|y")]
        public string ExpireIn { get; set; }

        [Option('e', "email", Required = true, HelpText = "peer account email")]
        public string Email { get; set; }

        [Value(0, Required = true, MetaName = "record", HelpText = "record path or UID")]
        public string RecordName { get; set; }
    }


    class ShareRecordOptions
    {
        [Option('a', "action", Required = false, Default = "share", HelpText = "user share action: \'share\' (default), \'revoke\', \'transfer\', \'cancel\'")]
        public string Action { get; set; }

        [Option('s', "share", Required = false, Default = null, HelpText = "can re-share record")]
        public bool? CanShare { get; set; }

        [Option('w', "write", Required = false, Default = null, HelpText = "can modify record")]
        public bool? CanEdit { get; set; }

        [Option("expire-at", Required = false, Default = null, HelpText = "expire share at time")]
        public string ExpireAt { get; set; }

        [Option("expire-in", Required = false, Default = null, HelpText = "expire share in period")]
        public string ExpireIn { get; set; }

        [Option('e', "email", Required = true, HelpText = "peer account email")]
        public string Email { get; set; }
        [Value(0, Required = false, MetaName = "record", HelpText = "record path or UID")]
        public string RecordName { get; set; }
    }

    class CmdLineRecordField : IRecordTypeField
    {
        public string FieldName { get; set; }
        public string FieldLabel { get; set; }
        public string FieldIndex { get; set; }
        public string Value { get; set; }
    }

    class RecordTypeAddOptions
    {
        [Value(0, Required = true, Default = false, HelpText = "Adds a new record type with given data. Needs a Serialized JSON string. example- record-type-add {\"$id\":\"myCustomType_dotnet_test6\",\"description\":\"My custom record\",\"categories\":[\"note\"],\"fields\":[{\"$ref\":\"login\"},{\"$ref\":\"password\"}]} ")]
        public string data { get; set; }
    }

    class RecordTypeUpdateOptions
    {
        [Value(0, Required = true, Default = false, HelpText = "RecordTypeId of record type to be updated")]
        public string recordTypeId { get; set; }
        [Value(1, Required = true, Default = false, HelpText = "update a new record type with given data. Needs a Serialized JSON string. example- record-type-update <record_type_id> {\"$id\":\"myCustomType_dotnet_test\",\"description\":\"My custom record\",\"categories\":[\"note\"],\"fields\":[{\"$ref\":\"login\"}]} ")]
        public string data { get; set; }
    }

    class RecordTypeDeleteOptions
    {
        [Value(0, Required = true, Default = false, HelpText = "RecordTypeId of record type to be deleted")]
        public string recordTypeId { get; set; }
    }

    class RecordTypeLoadOptions
    {
        [Value(0, Required = true, Default = false, HelpText = "File path to load record type from")]
        public string filePath { get; set; }
    }
}
