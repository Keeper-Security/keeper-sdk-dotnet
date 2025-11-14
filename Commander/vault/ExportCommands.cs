using Cli;
using CommandLine;
using KeeperSecurity.Vault;
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace Commander
{
    internal static class ExportCommandExtensions
    {
        public static async Task ExportCommand(this VaultContext context, ExportCommandOptions options)
        {
            void Logger(Severity severity, string message)
            {
                if (severity == Severity.Warning || severity == Severity.Error)
                {
                    Console.WriteLine(message);
                }
                Debug.WriteLine(message);
            }

            var filename = options.FileName;
            
            if (!filename.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
            {
                filename += ".json";
            }

            if (File.Exists(filename) && !options.Force)
            {
                Console.Write($"File \"{filename}\" already exists. Overwrite? (y/n): ");
                var response = Console.ReadLine()?.Trim().ToLower();
                if (response != "y" && response != "yes")
                {
                    Console.WriteLine("Export cancelled.");
                    return;
                }
            }

            Console.WriteLine("Exporting vault data...");
            
            var excludeSharedFolders = options.ExcludeSharedFolders;
            
            await context.Vault.ExportVaultToFile(
                filename,
                recordUids: null,
                includeSharedFolders: !excludeSharedFolders,
                logger: Logger);

            var fileInfo = new FileInfo(filename);
            var table = new Tabulate(2)
            {
                LeftPadding = 4
            };
            table.SetColumnRightAlign(0, true);
            
            var recordCount = context.Vault.KeeperRecords.Count(r => r.Version == 2 || r.Version == 3);
            var sharedFolderCount = excludeSharedFolders ? 0 : context.Vault.SharedFolders.Count();
            
            table.AddRow("Records Exported:", recordCount);
            if (!excludeSharedFolders)
            {
                table.AddRow("Shared Folders:", sharedFolderCount);
            }
            table.AddRow("File Size:", $"{fileInfo.Length:N0} bytes");
            table.AddRow("Output File:", filename);
            
            table.Dump();
            
            Console.WriteLine();
            Console.WriteLine("Export completed successfully.");
        }
    }
    
    class ExportCommandOptions
    {
        [Value(0, Required = true, HelpText = "JSON export filename")]
        public string FileName { get; set; }

        [Option('f', "force", Required = false, Default = false, 
            HelpText = "Overwrite existing file without prompting")]
        public bool Force { get; set; }

        [Option('x', "exclude-shared-folders", Required = false, Default = false,
            HelpText = "Exclude shared folders from export")]
        public bool ExcludeSharedFolders { get; set; }
    }
}

