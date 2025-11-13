using Cli;
using CommandLine;
using KeeperSecurity.Commands;
using KeeperSecurity.Vault;
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace Commander
{
    internal static class DownloadMembershipCommandExtensions
    {
        public static async Task DownloadMembershipCommand(this VaultContext context, DownloadMembershipCommandOptions options)
        {
            void Logger(Severity severity, string message)
            {
                if (severity == Severity.Warning || severity == Severity.Error)
                {
                    Console.WriteLine(message);
                }
                Debug.WriteLine(message);
            }

            if (string.IsNullOrEmpty(options.Source))
            {
                throw new Exception("--source parameter is required. Valid values: keeper, lastpass, thycotic");
            }
            
            var source = options.Source.ToLower();
            if (source != "keeper" && source != "lastpass" && source != "thycotic")
            {
                throw new Exception($"Invalid source '{options.Source}'. Valid values: keeper, lastpass, thycotic");
            }
            
            if (source != "keeper")
            {
                throw new NotImplementedException($"Membership download source '{source}' is not supported");
            }

            var filename = string.IsNullOrEmpty(options.FileName) 
                ? "shared_folder_membership.json" 
                : options.FileName;
            
            if (!filename.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
            {
                filename += ".json";
            }

            if (File.Exists(filename) && options.Force)
            {
                Console.WriteLine($"File \"{filename}\" will be overwritten (--force flag is set).");
            }

            Console.WriteLine($"Downloading shared folder membership from {source}...");
            
            var downloadOptions = new DownloadMembershipOptions
            {
                FoldersOnly = options.FoldersOnly,
                SubFolderHandling = options.SubFolder
            };

            if (!string.IsNullOrEmpty(options.Permissions))
            {
                var perms = options.Permissions.ToLower();
                if (perms.Contains("u"))
                {
                    downloadOptions.ForceManageUsers = true;
                }
                if (perms.Contains("r"))
                {
                    downloadOptions.ForceManageRecords = true;
                }
            }
            
            if (!string.IsNullOrEmpty(options.Restrictions))
            {
                var restrictions = options.Restrictions.ToLower();
                if (restrictions.Contains("u"))
                {
                    downloadOptions.ForceManageUsers = false;
                }
                if (restrictions.Contains("r"))
                {
                    downloadOptions.ForceManageRecords = false;
                }
            }

            ExportFile exportFile;
            if (File.Exists(filename) && !options.Force)
            {
                await context.Vault.MergeMembershipToFile(filename, downloadOptions, Logger);
                exportFile = await context.Vault.DownloadMembership(downloadOptions, Logger);
            }
            else
            {
                await context.Vault.DownloadMembershipToFile(filename, downloadOptions, Logger);
                exportFile = await context.Vault.DownloadMembership(downloadOptions, Logger);
            }

            var table = new Tabulate(2)
            {
                LeftPadding = 4
            };
            table.SetColumnRightAlign(0, true);
            
            var sharedFolderCount = exportFile.SharedFolders?.Length ?? 0;
            var teamCount = exportFile.Teams?.Length ?? 0;
            
            table.AddRow("Shared Folders:", sharedFolderCount);
            if (!options.FoldersOnly)
            {
                table.AddRow("Teams:", teamCount);
            }
            table.AddRow("Output File:", filename);
            
            table.Dump();
            
            Console.WriteLine();
            Console.WriteLine("Download membership completed successfully.");
        }
    }
    
    class DownloadMembershipCommandOptions
    {
        [Option("source", Required = true,
            HelpText = "Shared folder membership source: keeper, lastpass, thycotic")]
        public string Source { get; set; }

        [Value(0, Required = false, HelpText = "Output JSON filename (default: shared_folder_membership.json)")]
        public string FileName { get; set; }

        [Option('f', "force", Required = false, Default = false,
            HelpText = "Overwrite existing file without merging")]
        public bool Force { get; set; }

        [Option("folders-only", Required = false, Default = false,
            HelpText = "Download shared folders only, skip teams")]
        public bool FoldersOnly { get; set; }

        [Option('p', "permissions", Required = false,
            HelpText = "Force shared folder permissions: manage (U)sers, manage (R)ecords")]
        public string Permissions { get; set; }

        [Option('r', "restrictions", Required = false,
            HelpText = "Force shared folder restrictions: manage (U)sers, manage (R)ecords")]
        public string Restrictions { get; set; }

        [Option("sub-folder", Required = false,
            HelpText = "Shared sub-folder handling: 'ignore' or 'flatten'")]
        public string SubFolder { get; set; }
    }
}
