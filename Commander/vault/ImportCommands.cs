using Cli;
using CommandLine;
using KeeperSecurity.Vault;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;

using System.Threading.Tasks;

namespace Commander
{
    internal static class ImportCommandExtensions
    {
        public static async Task ImportCommand(this VaultContext context, ImportCommandOptions options)
        {
            void Logger(Severity severity, string message)
            {
                if (severity == Severity.Warning || severity == Severity.Error)
                {
                    Console.WriteLine(message);
                }
                Debug.WriteLine(message);
            }

            if (!File.Exists(options.FileName))
            {
                throw new Exception($"File \"{options.FileName}\" does not exist");
            }
            var json = File.ReadAllText(options.FileName);
            var j_options = new ZeroDep.JsonOptions
            {
                DateTimeStyles = DateTimeStyles.None,
            };
            j_options.SerializationOptions &= ~ZeroDep.JsonSerializationOptions.AutoParseDateTime;
            var j = ZeroDep.Json.Deserialize<Dictionary<string, object>>(json, j_options);
            var import = KeeperImport.LoadJsonDictionary(j);
            var result = await context.Vault.ImportJson(import, Logger);
            var table = new Tabulate(2)
            {
                LeftPadding = 4
            };
            table.SetColumnRightAlign(0, true);
            if (result.SharedFolderCount > 0)
            {
                table.AddRow("Shared Folders:", result.SharedFolderCount);
            }
            if (result.FolderCount > 0)
            {
                table.AddRow("Folders:", result.FolderCount);
            }
            if (result.TypedRecordCount > 0)
            {
                table.AddRow("Records:", result.TypedRecordCount);
            }
            if (result.LegacyRecordCount > 0)
            {
                table.AddRow("Legacy Records:", result.LegacyRecordCount);
            }
            if (result.UpdatedRecordCount > 0)
            {
                table.AddRow("Updated Records:", result.UpdatedRecordCount);
            }
            table.Dump();
        }
    }
    class ImportCommandOptions
    {
        [Value(0, Required = true, HelpText = "JSON import filename")]
        public string FileName { get; set; }
    }
}
