using CommandLine;
using KeeperSecurity.Commands;
using KeeperSecurity.Utils;
using KeeperSecurity.Vault;
using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace Commander
{
    [Verb("apply-membership", HelpText = "Loads shared folder membership from JSON file into Keeper")]
    internal class ApplyMembershipCommandOptions
    {
        [Option("full-sync", Required = false, Default = false,
            HelpText = "Update and remove membership also")]
        public bool FullSync { get; set; }

        [Value(0, Required = false, MetaName = "filename",
            HelpText = "Input file name. \"shared_folder_membership.json\" if omitted")]
        public string FileName { get; set; }
    }

    internal static class ApplyMembershipCommandExtensions
    {
        private const string DefaultFileName = "shared_folder_membership.json";
        private const long MaxFileSizeBytes = 50 * 1024 * 1024; // 50 MB limit

        public static async Task ApplyMembershipCommand(this VaultContext context, ApplyMembershipCommandOptions options)
        {
            var fileName = options.FileName ?? DefaultFileName;

            if (!File.Exists(fileName))
            {
                Console.WriteLine($"Error: Shared folder membership file \"{fileName}\" not found");
                return;
            }

            var fileInfo = new FileInfo(fileName);
            if (fileInfo.Length > MaxFileSizeBytes)
            {
                Console.WriteLine($"Error: File size ({fileInfo.Length / (1024 * 1024)} MB) exceeds maximum allowed size ({MaxFileSizeBytes / (1024 * 1024)} MB)");
                return;
            }

            ImportFile importFile;
            try
            {
                var jsonBytes = File.ReadAllBytes(fileName);
                importFile = JsonUtils.ParseJson<ImportFile>(jsonBytes);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error reading membership file: {ex.Message}");
                return;
            }

            Console.WriteLine($"Processing {importFile.SharedFolders?.Length ?? 0} shared folder(s)...");

            try
            {
                var summary = await context.Vault.ApplyMembership(importFile, new ApplyMembershipOptions { FullSync = options.FullSync });
                PrintSummary(summary);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error applying membership: {ex.Message}");
            }
        }

        private static void PrintSummary(MembershipSummary summary)
        {
            var messages = new (int count, string message)[]
            {
                (summary.TeamsAdded, "team(s) added to shared folders"),
                (summary.UsersAdded, "user(s) added to shared folders"),
                (summary.TeamsUpdated, "team(s) updated in shared folders"),
                (summary.UsersUpdated, "user(s) updated in shared folders"),
                (summary.TeamsRemoved, "team(s) removed from shared folders"),
                (summary.UsersRemoved, "user(s) removed from shared folders")
            };

            foreach (var (count, message) in messages.Where(m => m.count > 0))
                Console.WriteLine($"{count} {message}");

            if (messages.All(m => m.count == 0))
                Console.WriteLine("No changes applied. All memberships are up to date.");
        }
    }
}
