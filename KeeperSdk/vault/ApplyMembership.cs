using KeeperSecurity.Commands;
using KeeperSecurity.Utils;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading.Tasks;

namespace KeeperSecurity.Vault
{
    /// <summary>
    /// Summary of shared folder membership changes
    /// </summary>
    public class MembershipSummary
    {
        public int TeamsAdded { get; set; }
        public int UsersAdded { get; set; }
        public int TeamsUpdated { get; set; }
        public int UsersUpdated { get; set; }
        public int TeamsRemoved { get; set; }
        public int UsersRemoved { get; set; }
    }

    /// <summary>
    /// Options for applying membership
    /// </summary>
    public class ApplyMembershipOptions
    {
        /// <summary>
        /// Full sync: update and remove existing membership
        /// </summary>
        public bool FullSync { get; set; }
    }

    /// <summary>
    /// Keeper Apply Membership methods for shared folders
    /// </summary>
    public static class KeeperApplyMembership
    {
        /// <summary>
        /// Applies shared folder membership from ImportFile to the vault
        /// </summary>
        public static async Task<MembershipSummary> ApplyMembership(
            this VaultOnline vault,
            ImportFile importFile,
            ApplyMembershipOptions options = null)
        {
            options = options ?? new ApplyMembershipOptions();

            var summary = new MembershipSummary();

            if (importFile.SharedFolders != null && importFile.SharedFolders.Length > 0)
            {
                summary = await ImportUserPermissions(vault, importFile.SharedFolders, options.FullSync);
            }

            return summary;
        }

        /// <summary>
        /// Imports user permissions for shared folders
        /// </summary>
        private static async Task<MembershipSummary> ImportUserPermissions(
            VaultOnline vault,
            ImportSharedFolder[] sharedFolders,
            bool fullSync)
        {
            var summary = new MembershipSummary();
            
            var teamLookup = new Dictionary<string, string>();
            foreach (var team in await vault.GetTeamsForShare())
            {
                teamLookup[team.TeamUid] = team.TeamUid;
                teamLookup[team.Name.ToLower()] = team.TeamUid;
            }

            foreach (var sharedFolder in sharedFolders)
            {
                if (sharedFolder.Permissions == null || sharedFolder.Permissions.Length == 0)
                {
                    Debug.WriteLine($"No permissions to apply for folder: {sharedFolder.Path}");
                    continue;
                }

                string sharedFolderUid = null;

                if (!string.IsNullOrEmpty(sharedFolder.Uid))
                {
                    Debug.WriteLine($"Using folder UID from import: {sharedFolder.Uid}");
                    
                    if (vault.TryGetSharedFolder(sharedFolder.Uid, out var _))
                    {
                        sharedFolderUid = sharedFolder.Uid;
                        Debug.WriteLine($"Folder UID {sharedFolder.Uid} is a valid shared folder");
                    }
                    else
                    {
                        Debug.WriteLine($"Folder UID {sharedFolder.Uid} is not accessible or not a shared folder");
                    }
                }
                else if (!string.IsNullOrEmpty(sharedFolder.Path))
                {
                    Debug.WriteLine($"Looking up folder by path: {sharedFolder.Path}");
                    var bo = new BatchVaultOperations(vault);
                    var folderNode = bo.GetFolderByPath(sharedFolder.Path);
                    
                    if (folderNode != null)
                    {
                        Debug.WriteLine($"Found folder by path: {sharedFolder.Path}, UID: {folderNode.FolderUid}, Type: {folderNode.FolderType}");
                        
                        if (vault.TryGetSharedFolder(folderNode.FolderUid, out var _))
                        {
                            sharedFolderUid = folderNode.FolderUid;
                            Debug.WriteLine($"Folder is a shared folder");
                        }
                        else
                        {
                            Debug.WriteLine($"Folder '{sharedFolder.Path}' exists but is not a shared folder");
                        }
                    }
                    else
                    {
                        Debug.WriteLine($"Folder not found by path: {sharedFolder.Path}");
                    }
                }

                if (string.IsNullOrEmpty(sharedFolderUid))
                {
                    Debug.WriteLine($"Skipping folder - not found or not accessible: {sharedFolder.Path}");
                    continue;
                }

                SharedFolder currentSf = null;
                if (vault.TryGetSharedFolder(sharedFolderUid, out var sf))
                {
                    currentSf = sf;
                }

                if (currentSf == null)
                {
                    Debug.WriteLine($"Folder '{sharedFolder.Path}' (UID: {sharedFolderUid}) is not a shared folder or you don't have permission to manage it. Skipping permissions.");
                    continue;
                }

                Debug.WriteLine($"Processing {sharedFolder.Permissions.Length} permission(s) for folder: {sharedFolder.Path ?? sharedFolderUid}");

                var currentPermissions = new Dictionary<string, SharedFolderPermission>();

                if (currentSf.UsersPermissions != null)
                {
                    Debug.WriteLine($"Current folder has {currentSf.UsersPermissions.Count} existing permission(s)");
                    foreach (var perm in currentSf.UsersPermissions)
                    {
                        if (!string.IsNullOrEmpty(perm.Uid))
                        {
                            currentPermissions[perm.Uid] = perm;
                        }
                        if (!string.IsNullOrEmpty(perm.Name))
                        {
                            currentPermissions[perm.Name.ToLower()] = perm;
                        }
                    }
                }

                var processedIds = new HashSet<string>();

                foreach (var permission in sharedFolder.Permissions)
                {
                    string userId = null;
                    UserType userType = UserType.Team;

                    if (!string.IsNullOrEmpty(permission.Uid) && teamLookup.TryGetValue(permission.Uid, out var value1))
                    {
                        userId = value1;
                    }
                    else if (!string.IsNullOrEmpty(permission.Name))
                    {
                        var name = permission.Name.ToLower();
                        if (teamLookup.TryGetValue(name, out var value))
                        {
                            userId = value;
                        }
                        else
                        {
                            try
                            {
                                _ = new System.Net.Mail.MailAddress(name);
                                userId = name;
                                userType = UserType.User;
                            }
                            catch
                            {
                                Debug.WriteLine($"Skipped invalid email: {permission.Name}");
                            }
                        }
                    }

                    if (string.IsNullOrEmpty(userId))
                    {
                        Debug.WriteLine($"Could not resolve user/team: {permission.Name ?? permission.Uid}");
                        continue;
                    }

                    Debug.WriteLine($"Processing {userType}: {userId} (ManageUsers={permission.ManageUsers}, ManageRecords={permission.ManageRecords})");

                    processedIds.Add(userId);
                    if (!string.IsNullOrEmpty(permission.Name))
                    {
                        processedIds.Add(permission.Name.ToLower());
                    }

                    var options = new SharedFolderUserOptions
                    {
                        ManageUsers = permission.ManageUsers,
                        ManageRecords = permission.ManageRecords
                    };

                    SharedFolderPermission existing = null;
                    if (currentPermissions.TryGetValue(userId, out var byUid))
                    {
                        existing = byUid;
                    }
                    else if (!string.IsNullOrEmpty(permission.Name) && currentPermissions.TryGetValue(permission.Name.ToLower(), out var byName))
                    {
                        existing = byName;
                    }

                    if (existing != null && !string.IsNullOrEmpty(existing.Uid))
                    {
                        processedIds.Add(existing.Uid);
                    }

                    if (existing != null)
                    {
                        if (existing.ManageUsers != (permission.ManageUsers ?? false) || 
                            existing.ManageRecords != (permission.ManageRecords ?? false))
                        {
                            Debug.WriteLine($"Updating {userType} {userId}: ManageUsers {existing.ManageUsers}->{permission.ManageUsers}, ManageRecords {existing.ManageRecords}->{permission.ManageRecords}");
                            await vault.PutUserToSharedFolder(sharedFolderUid, userId, userType, options);
                            if (userType == UserType.Team)
                                summary.TeamsUpdated++;
                            else
                                summary.UsersUpdated++;
                        }
                        else
                        {
                            Debug.WriteLine($"{userType} {userId} already has correct permissions, skipping");
                        }
                    }
                    else
                    {
                        Debug.WriteLine($"Adding new {userType}: {userId}");
                        await vault.PutUserToSharedFolder(sharedFolderUid, userId, userType, options);
                        if (userType == UserType.Team)
                            summary.TeamsAdded++;
                        else
                            summary.UsersAdded++;
                    }
                }

                if (fullSync)
                {
                    var processedForRemoval = new HashSet<string>();
                    foreach (var kvp in currentPermissions)
                    {
                        var perm = kvp.Value;
                        var permKey = perm.Uid ?? perm.Name; // Unique key per permission
                        
                        if (processedForRemoval.Contains(permKey))
                            continue;
                        processedForRemoval.Add(permKey);
                        
                        var wasProcessed = (!string.IsNullOrEmpty(perm.Uid) && processedIds.Contains(perm.Uid)) ||
                                          (!string.IsNullOrEmpty(perm.Name) && processedIds.Contains(perm.Name.ToLower()));
                        
                        if (!wasProcessed)
                        {
                            var removeId = perm.UserType == UserType.Team ? perm.Uid : perm.Name;
                            await vault.RemoveUserFromSharedFolder(sharedFolderUid, removeId, perm.UserType);
                            if (perm.UserType == UserType.Team)
                                summary.TeamsRemoved++;
                            else
                                summary.UsersRemoved++;
                        }
                    }
                }
            }

            return summary;
        }
    }
}
