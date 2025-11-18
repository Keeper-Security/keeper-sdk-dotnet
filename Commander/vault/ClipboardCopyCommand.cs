using Cli;
using CommandLine;
using KeeperSecurity.Utils;
using KeeperSecurity.Vault;
using System;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace Commander
{
    internal static class ClipboardCopyCommandExtensions
    {
        public static async Task ClipboardCopyCommand(this VaultContext context, ClipboardCopyCommandOptions options)
        {
            if (string.IsNullOrEmpty(options.Record))
            {
                Console.WriteLine("Error: Record name or UID is required");
                return;
            }

            // Find the record
            var recordUid = FindRecordUid(context, options.Record, options.Username);
            if (string.IsNullOrEmpty(recordUid))
            {
                Console.WriteLine($"Record not found: {options.Record}");
                return;
            }

            // Load record with optional revision
            KeeperRecord record;
            if (options.Revision.HasValue && options.Revision.Value > 0)
            {
                var history = await context.Vault.GetRecordHistory(recordUid);
                if (history == null || options.Revision.Value >= history.Length)
                {
                    Console.WriteLine($"Invalid revision: {options.Revision.Value}");
                    return;
                }
                record = history[options.Revision.Value].KeeperRecord;
            }
            else
            {
                if (!context.Vault.TryGetKeeperRecord(recordUid, out record))
                {
                    Console.WriteLine($"Record not found: {recordUid}");
                    return;
                }
            }

            // Extract the requested data
            string itemName;
            string value;

            if (options.CopyUid)
            {
                itemName = "UID";
                value = recordUid;
            }
            else if (options.Login)
            {
                itemName = "Login";
                value = ExtractLogin(record);
            }
            else if (options.Totp)
            {
                itemName = "TOTP";
                value = ExtractTotp(record);
            }
            else if (!string.IsNullOrEmpty(options.Field))
            {
                itemName = options.Field;
                value = ExtractField(record, options.Field);
            }
            else
            {
                itemName = "Password";
                value = ExtractPassword(record);
            }

            if (string.IsNullOrEmpty(value))
            {
                Console.WriteLine($"Error: {itemName} not found in record");
                return;
            }

            // Output to destination
            switch (options.Output.ToLower())
            {
                case "clipboard":
                    OutputToClipboard(itemName, value);
                    break;

                case "stdout":
                    Console.WriteLine(value);
                    break;

                case "stdouthidden":
                    OutputToStdoutHidden(value);
                    break;

                case "variable":
                    OutputToVariable(itemName, value, options.Name);
                    break;

                default:
                    Console.WriteLine($"Unknown output destination: {options.Output}");
                    break;
            }

            // Audit log for password copies
            if (itemName == "Password" && !string.IsNullOrEmpty(value))
            {
                try
                {
                    context.Vault.Auth.ScheduleAuditEventLogging("copy_password",
                        new KeeperSecurity.Commands.AuditEventInput { RecordUid = recordUid });
                }
                catch
                {
                    // Ignore audit log errors
                }
            }
        }

        private static string FindRecordUid(VaultContext context, string recordName, string username)
        {
            // Check if it's already a UID
            if (context.Vault.TryGetKeeperRecord(recordName, out _))
            {
                return recordName;
            }

            // Find by title
            var matches = context.Vault.KeeperRecords
                .Where(r => string.Equals(r.Title, recordName, StringComparison.OrdinalIgnoreCase))
                .ToList();

            // Filter by username if provided
            if (!string.IsNullOrEmpty(username))
            {
                matches = matches.Where(r =>
                {
                    var login = ExtractLogin(r);
                    return string.Equals(login, username, StringComparison.OrdinalIgnoreCase);
                }).ToList();
            }

            if (matches.Count == 1)
            {
                return matches[0].Uid;
            }

            if (matches.Count > 1)
            {
                Console.WriteLine($"Multiple records found with title '{recordName}'. Use --username or UID.");
                return null;
            }

            // Try partial match
            matches = context.Vault.KeeperRecords
                .Where(r => r.Title.IndexOf(recordName, StringComparison.OrdinalIgnoreCase) >= 0)
                .ToList();

            if (matches.Count == 1)
            {
                return matches[0].Uid;
            }

            return null;
        }

        private static string ExtractPassword(KeeperRecord record)
        {
            return record switch
            {
                PasswordRecord pr => pr.Password ?? "",
                TypedRecord tr => ExtractTypedField(tr, "password"),
                _ => ""
            };
        }

        private static string ExtractLogin(KeeperRecord record)
        {
            return record switch
            {
                PasswordRecord pr => pr.Login ?? "",
                TypedRecord tr => ExtractTypedField(tr, "login"),
                _ => ""
            };
        }

        private static string ExtractTotp(KeeperRecord record)
        {
            var totpUrl = record switch
            {
                PasswordRecord pr => pr.Totp,
                TypedRecord tr => ExtractTypedField(tr, "oneTimeCode"),
                _ => null
            };

            if (string.IsNullOrEmpty(totpUrl))
                return "";

            try
            {
                var totpCode = CryptoUtils.GetTotpCode(totpUrl);
                return totpCode?.Item1 ?? "";
            }
            catch
            {
                return "";
            }
        }

        private static string ExtractField(KeeperRecord record, string fieldName)
        {
            // Handle special fields
            if (fieldName.Equals("notes", StringComparison.OrdinalIgnoreCase))
            {
                return record switch
                {
                    PasswordRecord pr => pr.Notes ?? "",
                    TypedRecord tr => tr.Notes ?? "",
                    _ => ""
                };
            }

            // Handle custom fields
            switch (record)
            {
                case PasswordRecord pr:
                    var customField = pr.Custom?.FirstOrDefault(c =>
                        string.Equals(c.Name, fieldName, StringComparison.OrdinalIgnoreCase));
                    return customField?.Value ?? "";

                case TypedRecord tr:
                    return ExtractTypedField(tr, fieldName);

                default:
                    return "";
            }
        }

        private static string ExtractTypedField(TypedRecord record, string fieldName)
        {
            // Try to find in standard fields
            var field = record.Fields?.FirstOrDefault(f =>
                string.Equals(f.FieldName, fieldName, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(f.FieldLabel, fieldName, StringComparison.OrdinalIgnoreCase));

            if (field != null)
            {
                return GetFieldValueAsString(field);
            }

            // Try custom fields
            var customField = record.Custom?.FirstOrDefault(f =>
                string.Equals(f.FieldName, fieldName, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(f.FieldLabel, fieldName, StringComparison.OrdinalIgnoreCase));

            return customField != null ? GetFieldValueAsString(customField) : "";
        }

        private static string GetFieldValueAsString(ITypedField field)
        {
            if (field == null) return "";

            var value = field.ObjectValue;
            if (value == null) return "";

            if (value is string str)
            {
                return str;
            }
            else if (value is System.Collections.IEnumerable enumerable && !(value is string))
            {
                var items = new System.Collections.Generic.List<string>();
                foreach (var item in enumerable)
                {
                    if (item != null)
                    {
                        items.Add(item.ToString());
                    }
                }
                return string.Join(", ", items);
            }

            return value.ToString();
        }

        private static void OutputToClipboard(string itemName, string value)
        {
            try
            {
#if NET472
                var thread = new Thread(() => { System.Windows.Clipboard.SetText(value); });
                thread.SetApartmentState(ApartmentState.STA);
                thread.Start();
                thread.Join();
                Console.WriteLine($"{itemName} copied to clipboard");
#else
                if (TryCopyToClipboardCrossPlatform(value))
                {
                    Console.WriteLine($"{itemName} copied to clipboard");
                }
                else
                {
                    Console.WriteLine("Clipboard not available on this platform. Value:");
                    Console.WriteLine(value);
                }
#endif
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to copy to clipboard: {ex.Message}");
                Console.WriteLine($"Value: {value}");
            }
        }

#if !NET472
        private static bool TryCopyToClipboardCrossPlatform(string text)
        {
            try
            {
                if (OperatingSystem.IsLinux())
                {
                    var process = new Process
                    {
                        StartInfo = new ProcessStartInfo
                        {
                            FileName = "xclip",
                            Arguments = "-selection clipboard",
                            RedirectStandardInput = true,
                            UseShellExecute = false,
                            CreateNoWindow = true
                        }
                    };
                    process.Start();
                    process.StandardInput.Write(text);
                    process.StandardInput.Close();
                    process.WaitForExit();
                    return process.ExitCode == 0;
                }
                else if (OperatingSystem.IsMacOS())
                {
                    var process = new Process
                    {
                        StartInfo = new ProcessStartInfo
                        {
                            FileName = "pbcopy",
                            RedirectStandardInput = true,
                            UseShellExecute = false,
                            CreateNoWindow = true
                        }
                    };
                    process.Start();
                    process.StandardInput.Write(text);
                    process.StandardInput.Close();
                    process.WaitForExit();
                    return process.ExitCode == 0;
                }
                return false;
            }
            catch
            {
                return false;
            }
        }
#endif

        private static void OutputToStdoutHidden(string value)
        {
            var originalFg = Console.ForegroundColor;
            var originalBg = Console.BackgroundColor;

            try
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.BackgroundColor = ConsoleColor.Red;
                Console.WriteLine(value);
            }
            finally
            {
                Console.ForegroundColor = originalFg;
                Console.BackgroundColor = originalBg;
            }
        }

        private static void OutputToVariable(string itemName, string value, string variableName)
        {
            if (string.IsNullOrEmpty(variableName))
            {
                Console.WriteLine("Error: --name parameter is required when output is set to 'variable'");
                return;
            }

            Environment.SetEnvironmentVariable(variableName, value);
            Console.WriteLine($"{itemName} is set to variable \"{variableName}\"");
        }
    }

    class ClipboardCopyCommandOptions
    {
        [Value(0, Required = false, MetaName = "record",
            HelpText = "Record path or UID")]
        public string Record { get; set; }

        [Option("username", Required = false,
            HelpText = "Match login name (optional)")]
        public string Username { get; set; }

        [Option("output", Required = false, Default = "clipboard",
            HelpText = "Output destination: clipboard, stdout, stdouthidden, variable")]
        public string Output { get; set; }

        [Option("name", Required = false,
            HelpText = "Variable name if output is set to variable")]
        public string Name { get; set; }

        [Option("copy-uid", Required = false, Default = false,
            HelpText = "Output UID instead of password")]
        public bool CopyUid { get; set; }

        [Option('l', "login", Required = false, Default = false,
            HelpText = "Output login name")]
        public bool Login { get; set; }

        [Option('t', "totp", Required = false, Default = false,
            HelpText = "Output TOTP code")]
        public bool Totp { get; set; }

        [Option("field", Required = false,
            HelpText = "Output custom field (use 'field:property' for nested values)")]
        public string Field { get; set; }

        [Option('r', "revision", Required = false,
            HelpText = "Use specific record revision")]
        public int? Revision { get; set; }
    }
}
