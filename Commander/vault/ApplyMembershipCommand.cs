using Cli;
using CommandLine;
using KeeperSecurity.Commands;
using KeeperSecurity.Utils;
using KeeperSecurity.Vault;
using System;
using System.IO;
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
        public static async Task ApplyMembershipCommand(this VaultContext context, ApplyMembershipCommandOptions options)
        {
            var fileName = options.FileName ?? "shared_folder_membership.json";

            if (!File.Exists(fileName))
            {
                Console.WriteLine($"Error: Shared folder membership file \"{fileName}\" not found");
                return;
            }

            ImportFile importFile;
            try
            {
                var json = File.ReadAllText(fileName);
                using var jsonDoc = JsonDocument.Parse(json);
                
                importFile = ParseMembershipJson(jsonDoc.RootElement);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error reading membership file: {ex.Message}");
                return;
            }

            var applyOptions = new ApplyMembershipOptions
            {
                FullSync = options.FullSync
            };

            Console.WriteLine($"Processing {importFile.SharedFolders?.Length ?? 0} shared folder(s)...");

            try
            {
                var summary = await context.Vault.ApplyMembership(importFile, applyOptions);

                if (summary.TeamsAdded > 0)
                {
                    Console.WriteLine($"{summary.TeamsAdded} team(s) added to shared folders");
                }
                if (summary.UsersAdded > 0)
                {
                    Console.WriteLine($"{summary.UsersAdded} user(s) added to shared folders");
                }
                if (summary.TeamsUpdated > 0)
                {
                    Console.WriteLine($"{summary.TeamsUpdated} team(s) updated in shared folders");
                }
                if (summary.UsersUpdated > 0)
                {
                    Console.WriteLine($"{summary.UsersUpdated} user(s) updated in shared folders");
                }
                if (summary.TeamsRemoved > 0)
                {
                    Console.WriteLine($"{summary.TeamsRemoved} team(s) removed from shared folders");
                }
                if (summary.UsersRemoved > 0)
                {
                    Console.WriteLine($"{summary.UsersRemoved} user(s) removed from shared folders");
                }

                if (summary.TeamsAdded == 0 && summary.UsersAdded == 0 &&
                    summary.TeamsUpdated == 0 && summary.UsersUpdated == 0 &&
                    summary.TeamsRemoved == 0 && summary.UsersRemoved == 0)
                {
                    Console.WriteLine("No changes applied. All memberships are up to date.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error applying membership: {ex.Message}");
            }
        }

        private static ImportFile ParseMembershipJson(JsonElement root)
        {
            var importFile = new ImportFile();

            if (root.TryGetProperty("shared_folders", out var sfArray))
            {
                var sharedFolders = new System.Collections.Generic.List<ImportSharedFolder>();
                
                foreach (var sfElement in sfArray.EnumerateArray())
                {
                    var sf = new ImportSharedFolder();
                    
                    if (sfElement.TryGetProperty("uid", out var uid))
                        sf.Uid = uid.GetString();
                    
                    if (sfElement.TryGetProperty("path", out var path))
                        sf.Path = path.GetString();
                    
                    if (sfElement.TryGetProperty("can_edit", out var canEdit))
                        sf.CanEdit = canEdit.GetBoolean();
                    
                    if (sfElement.TryGetProperty("can_share", out var canShare))
                        sf.CanShare = canShare.GetBoolean();
                    
                    if (sfElement.TryGetProperty("manage_records", out var manageRecords))
                        sf.ManageRecords = manageRecords.GetBoolean();
                    
                    if (sfElement.TryGetProperty("manage_users", out var manageUsers))
                        sf.ManageUsers = manageUsers.GetBoolean();
                    
                    if (sfElement.TryGetProperty("permissions", out var permsArray))
                    {
                        var permissions = new System.Collections.Generic.List<ImportSharedFolderPermissions>();
                        
                        foreach (var permElement in permsArray.EnumerateArray())
                        {
                            var perm = new ImportSharedFolderPermissions();
                            
                            if (permElement.TryGetProperty("uid", out var permUid))
                                perm.Uid = permUid.GetString();
                            
                            if (permElement.TryGetProperty("name", out var permName))
                                perm.Name = permName.GetString();
                            
                            if (permElement.TryGetProperty("manage_records", out var permManageRecords))
                                perm.ManageRecords = permManageRecords.GetBoolean();
                            
                            if (permElement.TryGetProperty("manage_users", out var permManageUsers))
                                perm.ManageUsers = permManageUsers.GetBoolean();
                            
                            permissions.Add(perm);
                        }
                        
                        sf.Permissions = permissions.ToArray();
                    }
                    
                    sharedFolders.Add(sf);
                }
                
                importFile.SharedFolders = sharedFolders.ToArray();
            }

            return importFile;
        }
    }
}
