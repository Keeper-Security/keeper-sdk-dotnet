using Cli;
using KeeperSecurity.Vault;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using KeeperSecurity.Utils;
using CommandLine;
using KeeperSecurity.BreachWatch;

namespace Commander
{
    internal partial class VaultContext
    {
        internal readonly VaultOnline Vault;
        internal string CurrentFolder;

        public VaultContext(VaultOnline vault)
        {
            Vault = vault;
        }

        public void PrintTree(FolderNode folder, string indent, bool last)
        {
            var isRoot = string.IsNullOrEmpty(indent);
            Console.WriteLine(indent + (isRoot ? "" : "+-- ") + folder.Name);
            indent += isRoot ? " " : (last ? "    " : "|   ");

            var subfolders = new List<FolderNode>();
            foreach (var t in folder.Subfolders)
            {
                if (Vault.TryGetFolder(t, out var node))
                {
                    subfolders.Add(node);
                }
            }

            subfolders.Sort((x, y) => string.Compare(x.Name, y.Name, StringComparison.CurrentCultureIgnoreCase));
            for (var i = 0; i < subfolders.Count; i++)
            {
                var node = subfolders[i];
                PrintTree(node, indent, i == subfolders.Count - 1);
            }
        }

        public bool TryResolvePath(string path, out FolderNode node)
        {
            var res = TryResolvePath(path, out node, out var text);
            if (res)
            {
                res = string.IsNullOrEmpty(text);
            }

            return res;
        }

        public bool TryResolvePath(string path, out FolderNode node, out string text)
        {
            node = null;
            text = null;
            if (string.IsNullOrEmpty(CurrentFolder) || CurrentFolder == Vault.RootFolder.FolderUid)
            {
                node = Vault.RootFolder;
            }
            else
            {
                Vault.TryGetFolder(CurrentFolder, out node);
            }

            if (string.IsNullOrEmpty(path)) return true;
            path = path.Trim();
            if (string.IsNullOrEmpty(path))
            {
                return node != null;
            }

            if (path[0] == '/')
            {
                path = path.Substring(1);
                node = Vault.RootFolder;
            }

            foreach (var folder in path.TokenizeArguments(CommandExtensions.IsPathDelimiter))
            {
                if (folder == "..")
                {
                    if (!string.IsNullOrEmpty(node.ParentUid))
                    {
                        if (!Vault.TryGetFolder(node.ParentUid, out node))
                        {
                            return false;
                        }
                    }
                    else if (!string.IsNullOrEmpty(node.FolderUid))
                    {
                        node = Vault.RootFolder;
                    }
                    else
                    {
                        return false;
                    }
                }
                else
                {
                    var found = false;
                    foreach (var subFolder in node.Subfolders)
                    {
                        if (!Vault.TryGetFolder(subFolder, out var subNode)) return false;

                        if ((string.Compare(folder, subNode.Name, StringComparison.CurrentCultureIgnoreCase) != 0) && (string.Compare(folder, subNode.FolderUid, StringComparison.CurrentCultureIgnoreCase) != 0))
                            continue;
                        found = true;
                        node = subNode;
                        break;
                    }

                    if (found) continue;
                    if (string.IsNullOrEmpty(text))
                    {
                        text = folder;
                    }
                    else
                    {
                        return false;
                    }
                }
            }

            return true;
        }
    }

    internal static class VaultCommandExtensions
    {
        internal static void AppendVaultCommands(this VaultContext context, CliCommands cli)
        {
            cli.Commands.Add("search",
                new ParseableCommand<SearchCommandOptions>
                {
                    Order = 10,
                    Description = "Search the vault. Can use a regular expression",
                    Action = context.SearchCommand
                });

            cli.Commands.Add("ls",
                new ParseableCommand<ListCommandOptions>
                {
                    Order = 11,
                    Description = "List folder content",
                    Action = context.ListCommand
                });

            cli.Commands.Add("cd",
                new SimpleCommand
                {
                    Order = 12,
                    Description = "Change current folder",
                    Action = context.ChangeDirectoryCommand
                });

            cli.Commands.Add("tree",
                new ParseableCommand<TreeCommandOptions>
                {
                    Order = 13,
                    Description = "Display folder structure",
                    Action = context.TreeCommand
                });


            cli.Commands.Add("record-history",
                new SimpleCommand
                {
                    Order = 15,
                    Description = "Display record history",
                    Action = context.RecordHistoryCommand
                });

            cli.Commands.Add("record-type-info",
                new ParseableCommand<RecordTypeInfoOptions>
                {
                    Order = 20,
                    Description = "Get record type info",
                    Action = context.RecordTypeInfoCommand
                }
            );
            cli.Aliases.Add("rti", "record-type-info");

            cli.Commands.Add("add-record",
                new ParseableCommand<AddRecordOptions>
                {
                    Order = 21,
                    Description = "Add record",
                    Action = context.AddRecordCommand
                });

            cli.Commands.Add("update-record",
                new ParseableCommand<UpdateRecordOptions>
                {
                    Order = 22,
                    Description = "Update record",
                    Action = context.UpdateRecordCommand
                });

            cli.Commands.Add("download-attachment",
                new ParseableCommand<DownloadAttachmentOptions>
                {
                    Order = 23,
                    Description = "Download Attachment(s)",
                    Action = context.DownloadAttachmentCommand
                });

            cli.Commands.Add("upload-attachment",
                new ParseableCommand<UploadAttachmentOptions>
                {
                    Order = 24,
                    Description = "Upload file attachment",
                    Action = context.UploadAttachmentCommand
                });
            
            cli.Commands.Add("delete-attachment",
                new ParseableCommand<DeleteAttachmentOptions>
                {
                    Order = 25,
                    Description = "Delete attachment",
                    Action = context.DeleteAttachmentCommand
                });

            cli.Commands.Add("delete-attachment",
                new ParseableCommand<DeleteAttachmentOptions>
                {
                    Order = 25,
                    Description = "Delete attachment",
                    Action = context.DeleteAttachmentCommand
                });

            cli.Commands.Add("mkdir",
                new ParseableCommand<MakeFolderOptions>
                {
                    Order = 25,
                    Description = "Make folder",
                    Action = context.MakeFolderCommand
                });

            cli.Commands.Add("rmdir",
                new ParseableCommand<FolderOptions>
                {
                    Order = 26,
                    Description = "Remove folder",
                    Action = context.RemoveFolderCommand
                });

            cli.Commands.Add("update-dir",
                new ParseableCommand<UpdateFolderOptions>
                {
                    Order = 27,
                    Description = "Update folder",
                    Action = context.UpdateFolderCommand
                });

            cli.Commands.Add("mv",
                new ParseableCommand<MoveOptions>
                {
                    Order = 28,
                    Description = "Move record or folder",
                    Action = context.MoveCommand
                });

            cli.Commands.Add("rm",
                new ParseableCommand<RemoveRecordOptions>
                {
                    Order = 29,
                    Description = "Remove record(s)",
                    Action = context.RemoveRecordCommand
                });

            cli.Commands.Add("sf-list",
                new SimpleCommand
                {
                    Order = 30,
                    Description = "List shared folders",
                    Action = context.ListSharedFoldersCommand
                });

            cli.Commands.Add("sf-user",
                new ParseableCommand<ShareFolderUserPermissionOptions>
                {
                    Order = 31,
                    Description = "Change shared folder user permissions",
                    Action = context.ShareFolderUserPermissionCommand
                });

            cli.Commands.Add("sf-record",
                new ParseableCommand<ShareFolderRecordPermissionOptions>
                {
                    Order = 32,
                    Description = "Change shared folder record permissions",
                    Action = context.ShareFolderRecordPermissionCommand
                });

            var cmd = new ParsebleVerbCommand
            {
                Order = 33,
                Description = "Change the sharing permissions of an individual record",
            };
            cmd.AddVerb<ShareRecordShareOptions>(context.ShareRecordShareCommand);
            cmd.AddVerb<ShareRecordCancelOptions>(context.ShareRecordCancelCommand);
            cmd.AddVerb<ShareRecordRevokeOptions>(context.ShareRecordRevokeCommand);
            cmd.AddVerb<ShareRecordTransferOptions>(context.ShareRecordTransferCommand);

            cli.Commands.Add("share-record", cmd);

            cli.Commands.Add("import",
                new ParseableCommand<ImportCommandOptions>
                {
                    Order = 33,
                    Description = "Imports records from JSON file",
                    Action = context.ImportCommand
                });

            cli.Commands.Add("password-report", new ParseableCommand<PasswordReportOptions>
            {
                Order = 39,
                Description = "Generate comprehensive password security report",
                Action = context.GetPasswordReport
            });

            if (context.Vault.Auth.AuthContext.Enforcements.TryGetValue("allow_secrets_manager", out var value))
            {
                if (value is bool b && b)
                {
                    cli.Commands.Add("ksm",
                        new ParseableCommand<SecretManagerOptions>
                        {
                            Order = 40,
                            Description = "Keeper Secret Manager commands",
                            Action = context.SecretManagerCommand
                        });
                }
            }

            cli.Commands.Add("one-time-share",
                new ParseableCommand<OneTimeShareOptions>
                {
                    Order = 41,
                    Description = "Manage One Time Shares",
                    Action = context.OneTimeShareCommand
                });

            cli.Commands.Add("sync-down",
                new ParseableCommand<SyncDownOptions>
                {
                    Order = 100,
                    Description = "Download & decrypt data",
                    Action = async (options) =>
                    {
                        var s = context.Vault.Storage.VaultSettings.Load();
                        var fullSync = options.Reset || s == null;
                        Console.WriteLine("Syncing...");
                        await context.Vault.SyncDown(fullSync: fullSync);
                        if (fullSync)
                        {
                            Console.WriteLine($"Decrypted {context.Vault.RecordCount} record(s)");
                        }
                    }
                });
            cli.Commands.Add("record-type-add",
                new ParseableCommand<RecordTypeAddOptions>
                {
                    Order = 81,
                    Description = "Add a new Record Type",
                    Action = context.RecordTypeAddCommand
                });
            cli.Commands.Add("record-type-update",
                new ParseableCommand<RecordTypeUpdateOptions>
                {
                    Order = 82,
                    Description = "updates a Record Type of given ID",
                    Action = context.RecordTypeUpdateCommand
                });
            cli.Commands.Add("record-type-delete",
                new ParseableCommand<RecordTypeDeleteOptions>
                {
                    Order = 83,
                    Description = "deletes a Record Type of given ID",
                    Action = context.RecordTypeDeleteCommand
                });
            cli.Commands.Add("load-record-types",
                new ParseableCommand<RecordTypeLoadOptions>
                {
                    Order = 84,
                    Description = "loads Record Types to keeper from given file",
                    Action = context.RecordTypeLoadCommand
                });
            cli.Commands.Add("breachwatch",
                new ParseableCommand<BreachWatchOptions>
                {
                    Order = 85,
                    Description = "BreachWatch commands",
                    Action = context.BreachWatchCommand
                });
            cli.Aliases.Add("list", "search");
            cli.Aliases.Add("d", "sync-down");
            cli.Aliases.Add("add", "add-record");
            cli.Aliases.Add("edit", "update-record");

        }

        private static Task SearchCommand(this VaultContext context, SearchCommandOptions options)
        {
            if (options.Limit <= 0)
            {
                options.Limit = 100;
            }
            else if (options.Limit > 1000)
            {
                options.Limit = 1000;
            }

            Regex pattern = string.IsNullOrEmpty(options.Pattern)
                ? null
                : new Regex(options.Pattern, RegexOptions.Compiled | RegexOptions.IgnoreCase);

            var matchedRecords = context.Vault.KeeperRecords
                .Where(x => options.Verbose || x.Version == 2 || x.Version == 3)
                .Where(record =>
                {
                    if (pattern == null)
                    {
                        return true;
                    }

                    if (record.Uid == options.Pattern)
                    {
                        return true;
                    }

                    if (pattern.IsMatch(record.Title))
                    {
                        return true;
                    }

                    if (record is PasswordRecord legacy)
                    {
                        return new[] { legacy.Notes, legacy.Login, legacy.Password, legacy.Notes }
                            .Where(x => !string.IsNullOrEmpty(x))
                            .Any(x => pattern.IsMatch(x));
                    }

                    if (record is TypedRecord typed)
                    {

                        var matched = new[] { typed.Notes, typed.TypeName }
                            .Where(x => !string.IsNullOrEmpty(x))
                            .Any(x => pattern.IsMatch(x));

                        if (matched)
                        {
                            return true;
                        }

                        matched = typed.Fields
                            .Any(x => x.GetTypedFieldValues().Any(y => pattern.IsMatch(y)));
                        if (matched)
                        {
                            return true;
                        }

                        return typed.Custom
                            .Any(x => x.GetTypedFieldValues().Any(y => pattern.IsMatch(y)));
                    }

                    return false;
                })
                .Take(options.Limit)
                .ToArray();

            if (matchedRecords.Length > 0)
            {
                var tab = new Tabulate(4)
                {
                    DumpRowNo = true
                };
                tab.AddHeader("Record UID", "Title", "Type", "Info");
                foreach (var r in matchedRecords)
                {
                    tab.AddRow(r.Uid, r.Title, r.KeeperRecordType(), r.KeeperRecordPublicInformation());
                }

                tab.Sort(1);
                tab.Dump();

                if (matchedRecords.Length == options.Limit)
                {
                    Console.WriteLine($"First {options.Limit} found records are shown.");
                }
            }
            else
            {
                Console.WriteLine("No records found");
            }

            return Task.FromResult(true);
        }

        private static Task ListCommand(this VaultContext context, ListCommandOptions options)
        {
            FolderNode node = null;
            if (!string.IsNullOrEmpty(context.CurrentFolder))
            {
                context.Vault.TryGetFolder(context.CurrentFolder, out node);
            }

            if (node == null)
            {
                node = context.Vault.RootFolder;
            }

            if (options.Details)
            {
                if (node.Subfolders.Count > 0)
                {
                    var tab = new Tabulate(2)
                    {
                        DumpRowNo = true
                    };
                    tab.AddHeader("Folder UID", "Name");
                    foreach (var uid in node.Subfolders)
                    {
                        if (context.Vault.TryGetFolder(uid, out var f))
                        {
                            tab.AddRow(f.FolderUid, f.Name);
                        }
                    }

                    tab.Sort(1);
                    tab.Dump();
                }

                if (node.Records.Count > 0)
                {
                    var tab = new Tabulate(4)
                    {
                        DumpRowNo = true
                    };
                    tab.AddHeader("Record UID", "Title", "Type", "Info");
                    foreach (var uid in node.Records)
                    {
                        if (context.Vault.TryGetKeeperRecord(uid, out var r))
                        {
                            tab.AddRow(r.Uid, r.Title, r.KeeperRecordType(), r.KeeperRecordPublicInformation());
                        }
                    }

                    tab.Sort(1);
                    tab.Dump();
                }
            }
            else
            {
                var names = new List<string>();
                foreach (var uid in node.Subfolders)
                {
                    if (context.Vault.TryGetFolder(uid, out var subNode))
                    {
                        names.Add(subNode.Name + "/");
                    }
                }

                names.Sort(StringComparer.InvariantCultureIgnoreCase);

                var len = names.Count;
                foreach (var uid in node.Records)
                {
                    if (context.Vault.TryGetKeeperRecord(uid, out var r))
                    {
                        if (r.Version == 2 || r.Version == 3)
                        {
                            names.Add(string.IsNullOrEmpty(r.Title) ? r.Uid : r.Title);
                        }
                    }
                }

                if (names.Count <= 0) return Task.FromResult(true);
                names.Sort(len, names.Count - len, StringComparer.InvariantCultureIgnoreCase);

                len = names.Select(x => x.Length).Max();
                if (len < 16)
                {
                    len = 16;
                }

                len += 2;
                var columns = Console.BufferWidth / len;
                if (columns < 1)
                {
                    columns = 1;
                }

                var columnWidth = Console.BufferWidth / columns;
                var colNo = 0;
                foreach (var t in names)
                {
                    Console.Write(t.PadRight(columnWidth - 1));
                    colNo++;
                    if (colNo < columns) continue;
                    Console.WriteLine();
                    colNo = 0;
                }
            }

            return Task.FromResult(true);
        }

        private static Task ChangeDirectoryCommand(this VaultContext context, string name)
        {
            if (context.TryResolvePath(name, out var node))
            {
                context.CurrentFolder = node.FolderUid;
            }
            else
            {
                Console.WriteLine($"Invalid folder name: {name}");
            }

            return Task.FromResult(true);
        }

        private static Task TreeCommand(this VaultContext context, TreeCommandOptions options)
        {
            context.PrintTree(context.Vault.RootFolder, "", true);
            return Task.FromResult(true);
        }


        private static IEnumerable<string> ToRecordChangeNames(this RecordChange changes)
        {
            if ((changes & RecordChange.RecordType) != 0)
            {
                yield return "Record Type";
            }

            if ((changes & RecordChange.Title) != 0)
            {
                yield return "Title";
            }

            if ((changes & RecordChange.Login) != 0)
            {
                yield return "Login";
            }

            if ((changes & RecordChange.Password) != 0)
            {
                yield return "Password";
            }

            if ((changes & RecordChange.Url) != 0)
            {
                yield return "URL";
            }

            if ((changes & RecordChange.Notes) != 0)
            {
                yield return "Notes";
            }

            if ((changes & RecordChange.Totp) != 0)
            {
                yield return "Totp";
            }

            if ((changes & RecordChange.Hostname) != 0)
            {
                yield return "Hostname";
            }

            if ((changes & RecordChange.Address) != 0)
            {
                yield return "Address";
            }

            if ((changes & RecordChange.PaymentCard) != 0)
            {
                yield return "Payment Card";
            }

            if ((changes & RecordChange.CustomField) != 0)
            {
                yield return "Custom Field";
            }

            if ((changes & RecordChange.File) != 0)
            {
                yield return "File";
            }
        }

        private static async Task RecordHistoryCommand(this VaultContext context, string recordUid)
        {
            if (string.IsNullOrEmpty(recordUid))
            {
                throw new Exception("\"record-history\" command requires <RECORD UID> parameter");
            }

            var tab = new Tabulate(4);
            tab.AddHeader("Version", "Modification Date", "Username", "Changed");
            var history = await context.Vault.GetRecordHistory(recordUid);
            for (var i = 0; i < history.Length; i++)
            {
                var h = history[i];

                var changes = string.Join(", ", h.RecordChange.ToRecordChangeNames());
                tab.AddRow($"V.{history.Length - i}", h.KeeperRecord.ClientModified.ToString("G"), h.Username, changes);
            }

            tab.Dump();
        }

        private static Task GetPasswordReport(this VaultContext context, PasswordReportOptions options)
        {
            var policyString = "12,2,2,2,0";
            var filterToFailingOnly = false;

            if (!string.IsNullOrEmpty(options.PolicyFlag))
            {
                policyString = options.PolicyFlag;
                filterToFailingOnly = true;
            }
            else if (options.Length > 0 || options.Lower > 0 || options.Upper > 0 || options.Digits > 0 || options.Special > 0)
            {
                var length = options.Length > 0 ? options.Length : 12;
                policyString = $"{length},{options.Lower},{options.Upper},{options.Digits},{options.Special}";
                filterToFailingOnly = true;
            }
            else if (!string.IsNullOrEmpty(options.Policy))
            {
                policyString = options.Policy;
                filterToFailingOnly = false;
            }

            var strength = passwordStrength(policyString);

            Console.WriteLine($"     Password Length: {strength.Length}");
            Console.WriteLine($"Lowercase characters: {strength.Lower}");
            Console.WriteLine($"Uppercase characters: {strength.Upper}");
            Console.WriteLine($"              Digits: {strength.Digits}");
            if (strength.Symbols > 0)
            {
                Console.WriteLine($"    Special characters: {strength.Symbols}");
            }
            Console.WriteLine();

            var records = new List<KeeperRecord>();

            if (!string.IsNullOrEmpty(options.Folder))
            {
                if (context.TryResolvePath(options.Folder, out var folder))
                {
                    foreach (var recordId in folder.Records)
                    {
                        if (context.Vault.TryGetKeeperRecord(recordId, out var rec))
                        {
                            records.Add(rec);
                        }
                    }
                }
                else
                {
                    Console.WriteLine($"Invalid folder: {options.Folder}");
                    return Task.CompletedTask;
                }
            }
            else
            {
                records.AddRange(context.Vault.KeeperRecords.Where(r => r.Version == 2 || r.Version == 3));
            }

            var recordsWithPasswords = new List<(KeeperRecord record, string password)>();
            foreach (var rec in records)
            {
                try
                {
                    var password = ExtractPassword(rec);
                    if (!string.IsNullOrWhiteSpace(password) && password.Trim().Length > 0)
                    {
                        recordsWithPasswords.Add((rec, password.Trim()));
                    }
                }
                catch (Exception)
                {
                    continue;
                }
            }

            if (recordsWithPasswords.Count == 0)
            {
                Console.WriteLine("No records with passwords found.");
                return Task.CompletedTask;
            }

            var tab = new Tabulate(8)
            {
                DumpRowNo = true
            };
            tab.AddHeader("Record UID", "Title", "Description", "Length", "Lower", "Upper", "Digits", "Special");

            foreach (var (rec, password) in recordsWithPasswords)
            {
                try
                {
                    //skip empties
                    if (string.IsNullOrWhiteSpace(password))
                    {
                        continue;
                    }

                    var description = rec.KeeperRecordPublicInformation();
                    var length = password.Length;
                    var lower = password.Count(char.IsLower);
                    var upper = password.Count(char.IsUpper);
                    var digits = password.Count(char.IsDigit);
                    var special = password.Count(c => "!@#$%()+;<>=?[]{}^.,".Contains(c));

                    if (filterToFailingOnly)
                    {
                        var meetsPolicy = length >= strength.Length &&
                                         lower >= strength.Lower &&
                                         upper >= strength.Upper &&
                                         digits >= strength.Digits &&
                                         special >= strength.Symbols;

                        if (meetsPolicy)
                        {
                            continue;
                        }
                    }

                    tab.AddRow(rec.Uid, rec.Title, description, length.ToString(), lower.ToString(),
                              upper.ToString(), digits.ToString(), special.ToString());
                }
                catch (Exception ex)
                {
                    if (options.Verbose)
                    {
                        Console.WriteLine($"Skipping record {rec.Uid} due to error: {ex.Message}");
                    }
                }
            }

            tab.Dump();

            return Task.CompletedTask;
        }

        private static string ExtractPassword(KeeperRecord record)
        {
            switch (record)
            {
                case PasswordRecord passwordRecord:
                    return passwordRecord.Password;
                case TypedRecord typed:
                    var passwordField = typed.Fields.FirstOrDefault(x => x.FieldName == "password");
                    if (passwordField is TypedField<string> stringField && stringField.Count > 0)
                    {
                        return stringField.Values.FirstOrDefault();
                    }
                    break;
                case FileRecord:
                    // File records don't have passwords
                    return null;
            }
            return null;
        }

        public class PasswordStrength
        {
            public int Length { get; set; }
            public int Lower { get; set; }
            public int Upper { get; set; }
            public int Digits { get; set; }
            public int Symbols { get; set; }

            private const int DEFAULT_PASSWORD_LENGTH = 20;
            private static readonly List<char> PW_SPECIAL_CHARACTERS = "!@#$%()+;<>=?[]{}^.,".ToCharArray().ToList();

            public override string ToString()
            {
                return $"Length: {Length}, Lower: {Lower}, Upper: {Upper}, Digits: {Digits}, Symbols: {Symbols}";
            }

            public PasswordStrength(string policy)
            {
                if (string.IsNullOrWhiteSpace(policy))
                {
                    throw new ArgumentException("Policy string cannot be null or empty.");
                }

                var parts = policy.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 5)
                {
                    throw new ArgumentException("Policy must contain at least 5 comma-separated integers.");
                }

                if (!int.TryParse(parts[0].Trim(), out int length) ||
                    !int.TryParse(parts[1].Trim(), out int lower) ||
                    !int.TryParse(parts[2].Trim(), out int upper) ||
                    !int.TryParse(parts[3].Trim(), out int digits) ||
                    !int.TryParse(parts[4].Trim(), out int symbols))
                {
                    throw new ArgumentException("Policy string contains non-integer values.");
                }

                Length = length;
                Lower = lower;
                Upper = upper;
                Digits = digits;
                Symbols = symbols;
            }

            public bool MeetsPolicy(PasswordStrength desiredPolicy)
            {
                var properties = typeof(PasswordStrength)
                        .GetProperties()
                        .Where(p => p.PropertyType == typeof(int)); // Only consider int-based fields

                foreach (var prop in properties)
                {
                    int currentValue = (int) (prop.GetValue(this) ?? 0);
                    int requiredValue = (int) (prop.GetValue(desiredPolicy) ?? 0);

                    if (currentValue < requiredValue)
                    {
                        return false;
                    }
                }

                return true;
            }

            public bool ValidateCurrentPassword(string password)
            {
                if (string.IsNullOrEmpty(password))
                {
                    return false;
                }

                if (password.Length < Length)
                {
                    return false;
                }

                int lowerCount = password.Count(char.IsLower);
                int upperCount = password.Count(char.IsUpper);
                int digitCount = password.Count(char.IsDigit);
                int symbolCount = password.Count(c => PW_SPECIAL_CHARACTERS.Contains(c));
                int length = password.Length;

                var currentPolicy = new PasswordStrength($"{length},{lowerCount},{upperCount},{digitCount},{symbolCount}");
                return currentPolicy.MeetsPolicy(this);
            }

        }

        public static PasswordStrength passwordStrength(string policy)
        {
            var policyList = new List<int>();

            foreach (var item in policy.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries))
            {
                if (int.TryParse(item.Trim(), out int value))
                {
                    policyList.Add(value);
                }
                else
                {
                    throw new ArgumentException($"Invalid policy value: {item}, only comma seperated numbers as a string is supported for policy");
                }
            }

            if (policyList.Count < 5)
            {
                throw new ArgumentException("Policy must contain at least 5 comma-separated integers.");
            }

            return new PasswordStrength($"{policyList[0]},{policyList[1]},{policyList[2]},{policyList[3]},{policyList[4]}");
        }
    }
        

    class SearchCommandOptions
    {
        [Option('v', "verbose", Required = false, Default = false, HelpText = "show all records")]
        public bool Verbose { get; set; }

        [Option("limit", Required = false, Default = 0, HelpText = "limit output")]
        public int Limit { get; set; }

        [Value(0, Required = false, MetaName = "pattern", HelpText = "search pattern")]
        public string Pattern { get; set; }
    }

    class ListCommandOptions
    {
        [Option('l', "list", Required = false, Default = false, HelpText = "detailed output")]
        public bool Details { get; set; }
    }

    internal class TreeCommandOptions
    {
        [Value(0, Required = false, MetaName = "folder", HelpText = "folder path or UID")]
        public string Folder { get; set; }
    }

    class SyncDownOptions
    {
        [Option("reset", Required = false, Default = false, HelpText = "resets on-disk storage")]
        public bool Reset { get; set; }
    }

    class PasswordReportOptions
    {
        [Value(0, Required = false, MetaName = "policy", HelpText = "Password complexity policy. Length,Lower,Upper,Digits,Special. Default is 12,2,2,2,0")]
        public string Policy { get; set; }

        [Option("policy", Required = false, HelpText = "Password complexity policy (filter to failing records only). Length,Lower,Upper,Digits,Special.")]
        public string PolicyFlag { get; set; }

        [Option("length", Required = false, Default = 0, HelpText = "Minimum password length.")]
        public int Length { get; set; }

        [Option("upper", Required = false, Default = 0, HelpText = "Minimum uppercase characters.")]
        public int Upper { get; set; }

        [Option("lower", Required = false, Default = 0, HelpText = "Minimum lowercase characters.")]
        public int Lower { get; set; }

        [Option("digits", Required = false, Default = 0, HelpText = "Minimum digits count.")]
        public int Digits { get; set; }

        [Option("special", Required = false, Default = 0, HelpText = "Minimum special characters.")]
        public int Special { get; set; }

        [Option("verbose", Required = false, Default = false, HelpText = "Display verbose information.")]
        public bool Verbose { get; set; }

        [Option("folder", Required = false, HelpText = "folder path or UID.")]
        public string Folder { get; set; }
    }

}