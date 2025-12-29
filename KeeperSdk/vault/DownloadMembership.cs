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
                return "";

            var path = new List<string>();
            var visited = new HashSet<string>();

            for (var folder = folderUid; 
                 !string.IsNullOrEmpty(folder) && visited.Add(folder) && vault.TryGetFolder(folder, out var node); 
                 folder = node.ParentUid)
            {
                path.Add(node.Name);
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
            options ??= new DownloadMembershipOptions();
            var referencedTeams = new Dictionary<string, ExportTeam>();
            var folderPaths = vault.Folders.ToDictionary(f => f.FolderUid, f => GetFolderPath(vault, f.FolderUid));
            var teamLookup = await GetTeamLookup(vault);
            var pathDelimiter = BatchVaultOperations.PathDelimiter;
            var handling = options.SubFolderHandling?.ToLower();

            string GetPath(SharedFolder sf)
            {
                var path = folderPaths.TryGetValue(sf.Uid, out var p) && !string.IsNullOrEmpty(p) ? p : sf.Name;
                return handling == "flatten" && path.Contains(pathDelimiter) 
                    ? string.Join(" - ", path.Split(pathDelimiter)) : path;
            }

            var sharedFolders = vault.SharedFolders
                .Where(sf => !(handling == "ignore" && (folderPaths.TryGetValue(sf.Uid, out var p) ? p : sf.Name).Contains(pathDelimiter)))
                .Select(sf => new ExportSharedFolder
                {
                    Uid = sf.Uid,
                    Path = GetPath(sf),
                    CanEdit = sf.DefaultCanEdit,
                    CanShare = sf.DefaultCanShare,
                    ManageUsers = sf.DefaultManageUsers,
                    ManageRecords = sf.DefaultManageRecords,
                    Permissions = sf.UsersPermissions?.Count > 0 
                        ? sf.UsersPermissions.Select(perm => CreatePermission(perm, teamLookup, referencedTeams, options)).ToArray() 
                        : null
                }).ToArray();

            return new ExportFile
            {
                SharedFolders = sharedFolders.Length > 0 ? sharedFolders : null,
                Teams = !options.FoldersOnly && referencedTeams.Count > 0 ? referencedTeams.Values.ToArray() : null
            };
        }

        private static async Task<Dictionary<string, string>> GetTeamLookup(VaultOnline vault)
        {
            try { return (await vault.GetTeamsForShare()).ToDictionary(t => t.TeamUid, t => t.Name); }
            catch (Exception ex) { Debug.WriteLine($"Failed to load teams: {ex.Message}"); return new Dictionary<string, string>(); }
        }

        private static ExportSharedFolderPermissions CreatePermission(
            SharedFolderPermission perm, 
            Dictionary<string, string> teamLookup, 
            Dictionary<string, ExportTeam> referencedTeams,
            DownloadMembershipOptions options)
        {
            var isTeam = perm.UserType == UserType.Team;
            var permName = isTeam && !string.IsNullOrEmpty(perm.Uid) && teamLookup.TryGetValue(perm.Uid, out var teamName) ? teamName : perm.Name;

            if (isTeam && !string.IsNullOrEmpty(perm.Uid) && !referencedTeams.ContainsKey(perm.Uid))
                referencedTeams[perm.Uid] = new ExportTeam { Uid = perm.Uid, Name = permName ?? perm.Uid };

            return new ExportSharedFolderPermissions
            {
                Uid = isTeam ? perm.Uid : null,
                Name = permName,
                ManageUsers = options.ForceManageUsers ?? perm.ManageUsers,
                ManageRecords = options.ForceManageRecords ?? perm.ManageRecords
            };
        }

        /// <summary>
        /// Downloads membership and exports to JSON string
        /// </summary>
        public static async Task<string> DownloadMembershipToJson(this VaultOnline vault, DownloadMembershipOptions options = null)
            => System.Text.Encoding.UTF8.GetString(JsonUtils.DumpJson(await vault.DownloadMembership(options), indent: true));

        /// <summary>
        /// Downloads membership and exports to JSON file
        /// </summary>
        public static async Task DownloadMembershipToFile(this VaultOnline vault, string filename, DownloadMembershipOptions options = null)
        {
            System.IO.File.WriteAllText(filename, await vault.DownloadMembershipToJson(options));
            Debug.WriteLine($"Downloaded membership to {filename}");
        }

        private static readonly DataContractJsonSerializer _serializer = new DataContractJsonSerializer(
            typeof(ExportFile), 
            new DataContractJsonSerializerSettings { UseSimpleDictionaryFormat = true, EmitTypeInformation = System.Runtime.Serialization.EmitTypeInformation.Never });

        /// <summary>
        /// Merges downloaded membership with existing JSON file
        /// </summary>
        public static async Task MergeMembershipToFile(this VaultOnline vault, string filename, DownloadMembershipOptions options = null)
        {
            var newExport = await vault.DownloadMembership(options);
            var result = newExport;
            
            if (System.IO.File.Exists(filename))
            {
                try
                {
                    using var ms = new System.IO.MemoryStream(System.Text.Encoding.UTF8.GetBytes(System.IO.File.ReadAllText(filename)));
                    var existing = (ExportFile)_serializer.ReadObject(ms);
                    var newSfUids = new HashSet<string>(newExport.SharedFolders?.Select(sf => sf.Uid) ?? Enumerable.Empty<string>());
                    var newTeamUids = new HashSet<string>(newExport.Teams?.Select(t => t.Uid) ?? Enumerable.Empty<string>());

                    T[] Merge<T>(T[] existingArr, T[] newArr, Func<T, string> getUid, HashSet<string> newUids) =>
                        (existingArr ?? Array.Empty<T>()).Where(x => !string.IsNullOrEmpty(getUid(x)) && !newUids.Contains(getUid(x)))
                        .Concat(newArr ?? Array.Empty<T>()).ToArray();

                    var folders = Merge(existing.SharedFolders, newExport.SharedFolders, sf => sf.Uid, newSfUids);
                    var teams = Merge(existing.Teams, newExport.Teams, t => t.Uid, newTeamUids);

                    result = new ExportFile
                    {
                        SharedFolders = folders.Length > 0 ? folders : null,
                        Teams = teams.Length > 0 ? teams : null,
                        Records = existing.Records
                    };
                    Debug.WriteLine($"Merged with existing file \"{filename}\"");
                }
                catch (Exception ex) { Debug.WriteLine($"Failed to merge: {ex.Message}. Overwriting."); }
            }

            System.IO.File.WriteAllText(filename, System.Text.Encoding.UTF8.GetString(JsonUtils.DumpJson(result, indent: true)));
            Debug.WriteLine($"Downloaded membership to {filename}");
        }
    }
}

