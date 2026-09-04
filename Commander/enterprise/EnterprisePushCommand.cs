using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using CommandLine;
using KeeperSecurity.Commands;
using KeeperSecurity.Enterprise;
using KeeperSecurity.Vault;
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

        [Option("email", Required = false, HelpText = "Target user email, display name, or enterprise user ID; repeatable")]
        public IEnumerable<string> Email { get; set; }

        [Option("team", Required = false, HelpText = "Target team name or UID; repeatable")]
        public IEnumerable<string> Team { get; set; }

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

        [Option("syntax-help", Required = false, Default = false, HelpText = "Show enterprise-push template syntax help")]
        public bool SyntaxHelp { get; set; }
    }

    internal static class EnterprisePushCommandExtensions
    {
        public static async Task EnterprisePushCommand(this IEnterpriseContext context, EnterprisePushCommandOptions arguments)
        {
            if (arguments.SyntaxHelp)
            {
                Console.WriteLine(TemplateSyntaxHelp);
                return;
            }

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

            var format = arguments.Format;
            if (arguments.DryRun && !TryResolveDryRunFormat(arguments.Format, out format)) return;

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

        private const string TemplateSyntaxHelp = "enterprise-push template syntax:\n"
            + "  Use Keeper JSON import format with a root object containing a records array.\n"
            + "  Supported substitutions: ${user_email}, ${user_name}, ${generate_password}.\n"
            + "  uid and folders are ignored because records are generated and delivered per target.\n"
            + "  Example: { \"records\": [{ \"title\": \"Welcome ${user_name}\", \"login\": \"${user_email}\" }] }";

        private static string[] SplitTargets(IEnumerable<string> singles, string multiple)
        {
            var values = new List<string>();
            if (singles != null) values.AddRange(singles.Where(x => !string.IsNullOrWhiteSpace(x)).Select(x => x.Trim()));
            if (!string.IsNullOrWhiteSpace(multiple)) values.AddRange(multiple.Split(','));
            return values.Select(x => x.Trim()).Where(x => x.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        }

        private static ImportRecord[] ParseTemplateRecords(string json)
        {
            var root = Json.Deserialize(json);
            IDictionary<string, object> document;
            if (root is IDictionary<string, object> rootObject)
            {
                document = new Dictionary<string, object>(rootObject, StringComparer.OrdinalIgnoreCase);
            }
            else if (root is IEnumerable<object> recordList)
            {
                document = new Dictionary<string, object>
                {
                    ["records"] = recordList.ToArray(),
                };
            }
            else
            {
                return Array.Empty<ImportRecord>();
            }

            var import = KeeperImport.LoadJsonDictionary(document);
            foreach (var record in import.Records ?? Array.Empty<ImportRecord>())
            {
                record.Uid = null;
                record.Folders = null;
            }

            return import.Records ?? Array.Empty<ImportRecord>();
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
                try
                {
                    using var writer = new StreamWriter(output);
                    EnterpriseExtensions.WriteFormattedOutput(writer, format, headers, rows, json);
                    Console.WriteLine($"Output written to {output}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Failed to write output to \"{output}\": {ex.Message}");
                }
                return;
            }

            EnterpriseExtensions.WriteFormattedOutput(Console.Out, format, headers, rows, json);
        }
    }
}
