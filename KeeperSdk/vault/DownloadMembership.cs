using KeeperSecurity.Commands;
using KeeperSecurity.Utils;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.Serialization.Json;
using System.Threading.Tasks;

namespace KeeperSecurity.Vault
{
    /// <summary>
    /// Options for downloading membership
    /// </summary>
    public class DownloadMembershipOptions
    {
        /// <summary>
        /// Include only shared folders, skip teams
        /// </summary>
        public bool FoldersOnly { get; set; }

        /// <summary>
        /// Force manage users permission for all users
        /// </summary>
        public bool? ForceManageUsers { get; set; }

        /// <summary>
        /// Force manage records permission for all users
        /// </summary>
        public bool? ForceManageRecords { get; set; }

        /// <summary>
        /// Subfolder handling: "ignore" or "flatten"
        /// </summary>
        public string SubFolderHandling { get; set; }
    }

    /// <summary>
    /// Keeper Membership Download methods
    /// </summary>
    public static class KeeperMembershipDownload
    {
        private static string GetFolderPath(IVaultData vault, string folderUid)
        {
            if (string.IsNullOrEmpty(folderUid))
            {
                return "";
            }

            var path = new List<string>();
            var folder = folderUid;
            var visited = new HashSet<string>();

            while (!string.IsNullOrEmpty(folder) && visited.Add(folder))
            {
                if (vault.TryGetFolder(folder, out var folderNode))
                {
                    path.Add(folderNode.Name);
                    folder = folderNode.ParentUid;
                }
                else
                {
                    break;
                }
            }

            path.Reverse();
            return string.Join(BatchVaultOperations.PathDelimiter.ToString(), path);
        }

        /// <summary>
        /// Downloads shared folder membership from Keeper vault
        /// </summary>
        public static async Task<ExportFile> DownloadMembership(
            this VaultOnline vault,
            DownloadMembershipOptions options = null)
        {
            options = options ?? new DownloadMembershipOptions();
            
            var exportFile = new ExportFile();
            var sharedFoldersList = new List<ExportSharedFolder>();
            var referencedTeams = new Dictionary<string, ExportTeam>();

            // Build folder path lookup
            var folderPaths = new Dictionary<string, string>();
            foreach (var folder in vault.Folders)
            {
                try
                {
                    var path = GetFolderPath(vault, folder.FolderUid);
                    if (!string.IsNullOrEmpty(path))
                    {
                        folderPaths[folder.FolderUid] = path;
                    }
                }
                catch
                {
                    // Ignore folders we can't access
                }
            }

            var teamLookup = new Dictionary<string, string>();
            try
            {
                var teams = await vault.GetTeamsForShare();
                foreach (var team in teams)
                {
                    teamLookup[team.TeamUid] = team.Name;
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Failed to load teams: {ex.Message}");
            }

            foreach (var sf in vault.SharedFolders)
            {
                var path = folderPaths.ContainsKey(sf.Uid) ? folderPaths[sf.Uid] : sf.Name;
                
                if (!string.IsNullOrEmpty(options.SubFolderHandling))
                {
                    var pathDelimiter = BatchVaultOperations.PathDelimiter;
                    var handling = options.SubFolderHandling.ToLower();
                    if (handling == "ignore" && path.Contains(pathDelimiter))
                    {
                        continue;
                    }
                    else if (handling == "flatten" && path.Contains(pathDelimiter))
                    {
                        var parts = path.Split(pathDelimiter);
                        if (parts.Length > 1)
                        {
                            path = parts[0] + " - " + string.Join(" - ", parts.Skip(1));
                        }
                    }
                }
                
                var exportSf = new ExportSharedFolder
                {
                    Uid = sf.Uid,
                    Path = path,
                    CanEdit = sf.DefaultCanEdit,
                    CanShare = sf.DefaultCanShare,
                    ManageUsers = sf.DefaultManageUsers,
                    ManageRecords = sf.DefaultManageRecords
                };

                if (sf.UsersPermissions != null && sf.UsersPermissions.Count > 0)
                {
                    var permissions = new List<ExportSharedFolderPermissions>();
                    foreach (var perm in sf.UsersPermissions)
                    {
                        var manageUsers = perm.ManageUsers;
                        var manageRecords = perm.ManageRecords;
                        
                        if (options.ForceManageUsers.HasValue)
                        {
                            manageUsers = options.ForceManageUsers.Value;
                        }
                        if (options.ForceManageRecords.HasValue)
                        {
                            manageRecords = options.ForceManageRecords.Value;
                        }

                        var permName = perm.Name;
                        var isTeam = perm.UserType == UserType.Team;
                        
                        if (isTeam && !string.IsNullOrEmpty(perm.Uid))
                        {
                            if (teamLookup.TryGetValue(perm.Uid, out var teamName))
                            {
                                permName = teamName;
                            }
                            
                            if (!referencedTeams.ContainsKey(perm.Uid))
                            {
                                referencedTeams[perm.Uid] = new ExportTeam
                                {
                                    Uid = perm.Uid,
                                    Name = permName ?? perm.Uid,
                                    Members = null
                                };
                            }
                        }
                        
                        permissions.Add(new ExportSharedFolderPermissions
                        {
                            Uid = isTeam ? perm.Uid : null,
                            Name = permName,
                            ManageUsers = manageUsers,
                            ManageRecords = manageRecords
                        });
                    }
                    exportSf.Permissions = permissions.ToArray();
                }

                sharedFoldersList.Add(exportSf);
            }

            if (sharedFoldersList.Count > 0)
            {
                exportFile.SharedFolders = sharedFoldersList.ToArray();
            }
            
            if (!options.FoldersOnly && referencedTeams.Count > 0)
            {
                exportFile.Teams = referencedTeams.Values.ToArray();
            }

            return exportFile;
        }

        /// <summary>
        /// Downloads membership and exports to JSON string
        /// </summary>
        public static async Task<string> DownloadMembershipToJson(
            this VaultOnline vault,
            DownloadMembershipOptions options = null)
        {
            var exportFile = await vault.DownloadMembership(options);
            var jsonBytes = JsonUtils.DumpJson(exportFile, indent: true);
            return System.Text.Encoding.UTF8.GetString(jsonBytes);
        }

        /// <summary>
        /// Downloads membership and exports to JSON file
        /// </summary>
        public static async Task DownloadMembershipToFile(
            this VaultOnline vault,
            string filename,
            DownloadMembershipOptions options = null)
        {
            var json = await vault.DownloadMembershipToJson(options);
            System.IO.File.WriteAllText(filename, json);
            Debug.WriteLine($"Downloaded membership to {filename}");
        }

        /// <summary>
        /// Merges downloaded membership with existing JSON file
        /// </summary>
        public static async Task MergeMembershipToFile(
            this VaultOnline vault,
            string filename,
            DownloadMembershipOptions options = null)
        {
            var newExportFile = await vault.DownloadMembership(options);

            ExportFile mergedExportFile;
            
            if (System.IO.File.Exists(filename))
            {
                try
                {
                    var existingJson = System.IO.File.ReadAllText(filename);
                    var jOptions = new System.Runtime.Serialization.Json.DataContractJsonSerializerSettings
                    {
                        UseSimpleDictionaryFormat = true,
                        EmitTypeInformation = System.Runtime.Serialization.EmitTypeInformation.Never
                    };
                    var serializer = new System.Runtime.Serialization.Json.DataContractJsonSerializer(
                        typeof(ExportFile), jOptions);
                    
                    using (var ms = new System.IO.MemoryStream(System.Text.Encoding.UTF8.GetBytes(existingJson)))
                    {
                        var existingExportFile = (ExportFile)serializer.ReadObject(ms);
                        
                        var mergedSharedFolders = new List<ExportSharedFolder>();
                        var updatedUids = new HashSet<string>(
                            newExportFile.SharedFolders?.Select(sf => sf.Uid) ?? Enumerable.Empty<string>());
                        
                        if (existingExportFile.SharedFolders != null)
                        {
                            foreach (var existingSf in existingExportFile.SharedFolders)
                            {
                                if (!string.IsNullOrEmpty(existingSf.Uid) && !updatedUids.Contains(existingSf.Uid))
                                {
                                    mergedSharedFolders.Add(existingSf);
                                }
                            }
                        }
                        
                        if (newExportFile.SharedFolders != null)
                        {
                            mergedSharedFolders.AddRange(newExportFile.SharedFolders);
                        }

                        var mergedTeams = new List<ExportTeam>();
                        var updatedTeamUids = new HashSet<string>(
                            newExportFile.Teams?.Select(t => t.Uid) ?? Enumerable.Empty<string>());
                        
                        if (existingExportFile.Teams != null)
                        {
                            foreach (var existingTeam in existingExportFile.Teams)
                            {
                                if (!string.IsNullOrEmpty(existingTeam.Uid) && !updatedTeamUids.Contains(existingTeam.Uid))
                                {
                                    mergedTeams.Add(existingTeam);
                                }
                            }
                        }
                        
                        if (newExportFile.Teams != null)
                        {
                            mergedTeams.AddRange(newExportFile.Teams);
                        }

                        mergedExportFile = new ExportFile
                        {
                            SharedFolders = mergedSharedFolders.Count > 0 ? mergedSharedFolders.ToArray() : null,
                            Teams = mergedTeams.Count > 0 ? mergedTeams.ToArray() : null,
                            Records = existingExportFile.Records
                        };
                        
                        Debug.WriteLine($"Merged with existing file \"{filename}\"");
                    }
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"Failed to merge with existing file: {ex.Message}. Overwriting.");
                    mergedExportFile = newExportFile;
                }
            }
            else
            {
                mergedExportFile = newExportFile;
            }

            var jsonBytes = JsonUtils.DumpJson(mergedExportFile, indent: true);
            var jsonString = System.Text.Encoding.UTF8.GetString(jsonBytes);
            System.IO.File.WriteAllText(filename, jsonString);
            
            Debug.WriteLine($"Downloaded membership to {filename}");
        }
    }
}

