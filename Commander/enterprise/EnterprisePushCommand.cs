using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using CommandLine;
using KeeperSecurity.Commands;
using KeeperSecurity.Enterprise;
using ZeroDep;

namespace Commander
{
    [Verb("enterprise-push", HelpText = "Populate user and team vaults with predetermined records")]
    internal class EnterprisePushCommandOptions : EnterpriseGenericOptions
    {
        [Value(0, Required = false, HelpText = "JSON template file")]
        public string File { get; set; }

        // Kept as an option as well so existing scripts using --file continue to work.
        [Option("file", Required = false, HelpText = "JSON template file")]
        public string FileOption { get; set; }

        [Option("email", Required = false, HelpText = "Target user email or enterprise user ID")]
        public string Email { get; set; }

        [Option("team", Required = false, HelpText = "Target team name or UID")]
        public string Team { get; set; }

        [Option("users", Required = false, HelpText = "Comma-separated target user emails or IDs")]
        public string Users { get; set; }

        [Option("teams", Required = false, HelpText = "Comma-separated target team names or UIDs")]
        public string Teams { get; set; }

        [Option("dry-run", Required = false, Default = false, HelpText = "Report planned pushes without changing the vault")]
        public bool DryRun { get; set; }

        [Option("format", Required = false, Default = "table", HelpText = "Dry-run output format: table, csv, or json")]
        public string Format { get; set; }

        [Option("output", Required = false, HelpText = "Dry-run output file for csv or json")]
        public string Output { get; set; }
    }

    internal static class EnterprisePushCommandExtensions
    {
        public static async Task EnterprisePushCommand(this IEnterpriseContext context, EnterprisePushCommandOptions arguments)
        {
            var fileName = string.IsNullOrWhiteSpace(arguments.FileOption) ? arguments.File : arguments.FileOption;
            if (string.IsNullOrWhiteSpace(fileName))
            {
                Console.WriteLine("Error: template file is required");
                return;
            }

            if (!File.Exists(fileName))
            {
                Console.WriteLine($"Error: File \"{fileName}\" not found");
                return;
            }

            ImportRecord[] templateRecords;
            try
            {
                templateRecords = ParseTemplateRecords(File.ReadAllText(fileName));
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error parsing JSON file: {ex.Message}");
                return;
            }

            if (templateRecords.Length == 0)
            {
                Console.WriteLine("No records found in template file");
                return;
            }

            var users = SplitTargets(arguments.Email, arguments.Users);
            var teams = SplitTargets(arguments.Team, arguments.Teams);
            if (users.Length == 0 && teams.Length == 0)
            {
                Console.WriteLine("Error: either --email/--users or --team/--teams is required");
                return;
            }

            if (!TryResolveDryRunFormat(arguments.Format, out var format)) return;

            var vault = context.GetVault();
            if (vault == null)
            {
                Console.WriteLine("Error: Cannot access vault");
                return;
            }

            if (context.EnterpriseData == null)
            {
                Console.WriteLine("Error: Enterprise data is not available. Connect as an enterprise administrator and try again.");
                return;
            }

            var result = await context.EnterpriseData.PushEnterpriseRecords(vault, templateRecords, new EnterprisePushOptions
            {
                Users = users,
                Teams = teams,
                DryRun = arguments.DryRun,
                Warnings = Console.WriteLine,
            });

            if (arguments.DryRun)
            {
                WriteDryRunOutput(arguments.Output, format, result.Actions);
                return;
            }

            Console.WriteLine($"Records created: {result.RecordsCreated}; transfers completed: {result.TransfersCompleted}; failures: {result.RecordsFailed + result.TransfersFailed}");
        }

        private static string[] SplitTargets(string single, string multiple)
        {
            var values = new List<string>();
            if (!string.IsNullOrWhiteSpace(single)) values.Add(single.Trim());
            if (!string.IsNullOrWhiteSpace(multiple)) values.AddRange(multiple.Split(','));
            return values.Select(x => x.Trim()).Where(x => x.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        }

        private static ImportRecord[] ParseTemplateRecords(string json)
        {
            var root = Json.Deserialize(json);
            object records = root;
            if (root is IDictionary<string, object> rootObject)
            {
                rootObject.TryGetValue("records", out records);
            }

            if (!(records is IList recordList)) return Array.Empty<ImportRecord>();
            return recordList.Cast<object>()
                .Select(ParseTemplateRecord)
                .Where(x => x != null)
                .ToArray();
        }

        private static ImportRecord ParseTemplateRecord(object value)
        {
            if (!(value is IDictionary<string, object> element)) return null;
            return new ImportRecord
            {
                Title = GetString(element, "title"),
                RecordType = GetString(element, "$type"),
                Login = GetString(element, "login"),
                Password = GetString(element, "password"),
                LoginUrl = GetString(element, "login_url"),
                Notes = GetString(element, "notes"),
                CustomFields = ParseCustomFields(element)
            };
        }

        private static ImportCustomField[] ParseCustomFields(IDictionary<string, object> record)
        {
            if (!record.TryGetValue("custom_fields", out var value) || !(value is IDictionary<string, object> fields))
                return null;

            var result = new List<ImportCustomField>();
            foreach (var field in fields)
            {
                if (field.Value is string)
                {
                    result.Add(new ImportCustomField { Name = field.Key, TextValue = (string)field.Value });
                }
                else if (field.Value is IDictionary<string, object> objectValue)
                {
                    result.Add(new ImportCustomField
                    {
                        Name = field.Key,
                        Elements = objectValue
                            .Where(x => x.Value is string || x.Value is ValueType)
                            .Select(x => new ImportCustomFieldElement { Name = x.Key, Value = Convert.ToString(x.Value) })
                            .ToArray()
                    });
                }
            }
            return result.ToArray();
        }

        private static string GetString(IDictionary<string, object> element, string name)
        {
            return element.TryGetValue(name, out var value) ? Convert.ToString(value) : null;
        }

        private static bool TryResolveDryRunFormat(string requested, out string format)
        {
            format = (requested ?? "table").ToLowerInvariant();
            if (format != "table" && format != "csv" && format != "json")
            {
                Console.WriteLine($"Invalid value for --format: \"{requested}\". Use table, csv, or json.");
                return false;
            }
            return true;
        }

        private static void WriteDryRunOutput(string output, string format, IReadOnlyList<EnterprisePushAction> actions)
        {
            var headers = new[] { "Action", "Record", "Target", "TargetType" };
            var rows = actions.Select(a => new object[] { a.Action, a.RecordTitle, a.Target, a.TargetType }).ToList();
            var json = actions.Select(a => new Dictionary<string, object>
            {
                ["action"] = a.Action,
                ["record"] = a.RecordTitle,
                ["target"] = a.Target,
                ["target_type"] = a.TargetType,
            }).ToList();

            if (!string.IsNullOrWhiteSpace(output) && format != "table")
            {
                using var writer = new StreamWriter(output);
                EnterpriseExtensions.WriteFormattedOutput(writer, format, headers, rows, json);
                Console.WriteLine($"Output written to {output}");
            }
            else
            {
                EnterpriseExtensions.WriteFormattedOutput(Console.Out, format, headers, rows, json);
            }
        }
    }
}
