using KeeperSecurity.Vault;
using System;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;

namespace Sample.RecordsExamples
{
    public static class ClipboardCopyExample
    {
        public static async Task CopyToClipboard(string recordUid, string fieldName = "password")
        {
            var vault = await AuthenticateAndGetVault.GetVault();
            if (vault == null)
            {
                Console.WriteLine("Failed to authenticate.");
                return;
            }

            if (!vault.TryGetKeeperRecord(recordUid, out var record))
            {
                Console.WriteLine($"Record not found: {recordUid}");
                return;
            }

            var value = fieldName.ToLowerInvariant() switch
            {
                "password" => record.ExtractPassword(),
                "login" => record.ExtractLogin(),
                "url" => record.ExtractUrl(),
                "notes" => record.ExtractNotes(),
                "totp" => record.ExtractTotp(),
                _ => ExtractCustomField(record, fieldName)
            };

            if (string.IsNullOrEmpty(value))
            {
                Console.WriteLine($"Field '{fieldName}' not found or empty in record '{record.Title}'.");
                return;
            }

            CopyTextToClipboard(fieldName, value);
        }

        private static string ExtractCustomField(KeeperRecord record, string fieldName)
        {
            switch (record)
            {
                case TypedRecord tr:
                    var field = tr.Fields?.FirstOrDefault(f =>
                        string.Equals(f.FieldName, fieldName, StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(f.FieldLabel, fieldName, StringComparison.OrdinalIgnoreCase));
                    if (field != null) return GetFieldValue(field);

                    var custom = tr.Custom?.FirstOrDefault(f =>
                        string.Equals(f.FieldName, fieldName, StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(f.FieldLabel, fieldName, StringComparison.OrdinalIgnoreCase));
                    if (custom != null) return GetFieldValue(custom);
                    break;

                case PasswordRecord pr:
                    var customField = pr.Custom?.FirstOrDefault(c =>
                        string.Equals(c.Name, fieldName, StringComparison.OrdinalIgnoreCase));
                    if (customField != null) return customField.Value ?? "";
                    break;
            }
            return "";
        }

        private static string GetFieldValue(ITypedField field)
        {
            var value = field?.ObjectValue;
            if (value == null) return "";

            if (value is string str) return str;

            if (value is System.Collections.IEnumerable enumerable)
            {
                var items = enumerable.Cast<object>().Where(x => x != null).Select(x => x.ToString());
                return string.Join(", ", items);
            }

            return value.ToString() ?? "";
        }

        private static void CopyTextToClipboard(string fieldName, string value)
        {
            try
            {
                using var process = CreateClipboardProcess();
                if (process == null)
                {
                    Console.WriteLine("Clipboard not supported on this platform.");
                    return;
                }

                process.Start();

                if (process.StartInfo.RedirectStandardInput)
                {
                    process.StandardInput.Write(value);
                    process.StandardInput.Close();
                }

                process.WaitForExit();

                if (process.ExitCode == 0)
                    Console.WriteLine($"{fieldName} copied to clipboard.");
                else
                    Console.WriteLine($"Failed to copy {fieldName} to clipboard.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Clipboard error: {ex.Message}");
            }
        }

        private static Process CreateClipboardProcess()
        {
            if (OperatingSystem.IsWindows())
            {
                return new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "powershell",
                        Arguments = "-NoProfile -Command \"$input | Set-Clipboard\"",
                        RedirectStandardInput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };
            }
            else if (OperatingSystem.IsMacOS())
            {
                return new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "pbcopy",
                        RedirectStandardInput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };
            }
            else if (OperatingSystem.IsLinux())
            {
                return new Process
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
            }
            return null;
        }
    }
}
