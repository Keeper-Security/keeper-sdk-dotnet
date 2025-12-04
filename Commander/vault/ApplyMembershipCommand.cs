using CommandLine;
using KeeperSecurity.Commands;
using KeeperSecurity.Vault;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
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

        public static async Task ApplyMembershipCommand(this VaultContext context, ApplyMembershipCommandOptions options)
        {
            var fileName = options.FileName ?? DefaultFileName;

            if (!File.Exists(fileName))
            {
                Console.WriteLine($"Error: Shared folder membership file \"{fileName}\" not found");
                return;
            }

            ImportFile importFile;
            try
            {
                using var jsonDoc = JsonDocument.Parse(File.ReadAllText(fileName));
                importFile = ParseMembershipJson(jsonDoc.RootElement);
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

        private static ImportFile ParseMembershipJson(JsonElement root)
        {
            if (!root.TryGetProperty("shared_folders", out var sfArray))
                return new ImportFile();

            var sharedFolders = sfArray.EnumerateArray()
                .Select(ParseSharedFolder)
                .ToArray();

            return new ImportFile { SharedFolders = sharedFolders };
        }

        private static ImportSharedFolder ParseSharedFolder(JsonElement element)
        {
            var sf = new ImportSharedFolder
            {
                Uid = GetStringProperty(element, "uid"),
                Path = GetStringProperty(element, "path"),
                CanEdit = GetBoolProperty(element, "can_edit") ?? false,
                CanShare = GetBoolProperty(element, "can_share") ?? false,
                ManageRecords = GetBoolProperty(element, "manage_records") ?? false,
                ManageUsers = GetBoolProperty(element, "manage_users") ?? false
            };

            if (element.TryGetProperty("permissions", out var permsArray))
            {
                sf.Permissions = permsArray.EnumerateArray()
                    .Select(ParsePermission)
                    .ToArray();
            }

            return sf;
        }

        private static ImportSharedFolderPermissions ParsePermission(JsonElement element) => new ImportSharedFolderPermissions
        {
            Uid = GetStringProperty(element, "uid"),
            Name = GetStringProperty(element, "name"),
            ManageRecords = GetBoolProperty(element, "manage_records"),
            ManageUsers = GetBoolProperty(element, "manage_users")
        };

        private static string GetStringProperty(JsonElement element, string name)
            => element.TryGetProperty(name, out var prop) ? prop.GetString() : null;

        private static bool? GetBoolProperty(JsonElement element, string name)
            => element.TryGetProperty(name, out var prop) ? prop.GetBoolean() : (bool?)null;
    }
}
