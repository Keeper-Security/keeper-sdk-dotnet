using KeeperSecurity.Commands;
using KeeperSecurity.Utils;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;

namespace KeeperSecurity.Vault
{
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

            return importFile.SharedFolders?.Length > 0
                ? await ImportUserPermissions(vault, importFile.SharedFolders, options.FullSync)
                : new MembershipSummary();
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
            var teamLookup = BuildTeamLookup(await vault.GetTeamsForShare());
            var bo = new BatchVaultOperations(vault);

            foreach (var sharedFolder in sharedFolders.Where(sf => sf.Permissions?.Length > 0))
            {
                var sharedFolderUid = ResolveSharedFolderUid(vault, sharedFolder);
                if (string.IsNullOrEmpty(sharedFolderUid) || !vault.TryGetSharedFolder(sharedFolderUid, out var currentSf))
                {
                    Debug.WriteLine($"Skipping folder '{sharedFolder.Path}': not found or not accessible");
                    continue;
                }

                Debug.WriteLine($"Processing {sharedFolder.Permissions.Length} permission(s) for folder: {sharedFolder.Path ?? sharedFolderUid}");

                var currentPermissions = BuildCurrentPermissions(currentSf);
                var processedIds = new HashSet<string>();

                foreach (var permission in sharedFolder.Permissions)
                {
                    if (permission == null)
                    {
                        continue;
                    }

                    var (userId, userType) = ResolveUserOrTeam(permission, teamLookup);
                    if (string.IsNullOrEmpty(userId))
                    {
                        Debug.WriteLine($"Could not resolve user/team: {permission.Name ?? permission.Uid}");
                        continue;
                    }

                    Debug.WriteLine($"Processing {userType}: {userId} (ManageUsers={permission.ManageUsers}, ManageRecords={permission.ManageRecords})");

                    TrackProcessedIds(processedIds, userId, permission.Name);
                    var existing = FindExistingPermission(currentPermissions, userId, permission.Name);
                    if (existing?.Uid != null) processedIds.Add(existing.Uid);

                    ApplyPermission(bo, sharedFolderUid, userId, userType, 
                        new SharedFolderUserOptions { ManageUsers = permission.ManageUsers, ManageRecords = permission.ManageRecords },
                        existing, permission, summary);
                }

                if (fullSync)
                    RemoveUnprocessedPermissions(bo, sharedFolderUid, currentPermissions, processedIds, summary);
            }
            await bo.ApplyChanges();
            return summary;
        }

        private static Dictionary<string, string> BuildTeamLookup(IEnumerable<TeamInfo> teams)
        {
            return teams
                .SelectMany(t => new[]
                {
                    (t.TeamUid, t.TeamUid),
                    (!string.IsNullOrEmpty(t.Name) ? t.Name.ToLower() : null, t.TeamUid)
                })
                .Where(x => !string.IsNullOrEmpty(x.Item1))
                .GroupBy(x => x.Item1)
                .ToDictionary(g => g.Key, g => g.First().Item2);
        }

        private static string ResolveSharedFolderUid(VaultOnline vault, ImportSharedFolder sharedFolder)
        {
            if (!string.IsNullOrEmpty(sharedFolder.Uid))
                return vault.TryGetSharedFolder(sharedFolder.Uid, out _) ? sharedFolder.Uid : null;

            if (string.IsNullOrEmpty(sharedFolder.Path))
                return null;

            var folderNode = new BatchVaultOperations(vault).GetFolderByPath(sharedFolder.Path);
            return folderNode != null && vault.TryGetSharedFolder(folderNode.FolderUid, out _) 
                ? folderNode.FolderUid 
                : null;
        }

        private static Dictionary<string, SharedFolderPermission> BuildCurrentPermissions(SharedFolder sf)
        {
            if (sf.UsersPermissions == null)
                return new Dictionary<string, SharedFolderPermission>();

            return sf.UsersPermissions
                .SelectMany(p => new[] 
                { 
                    (key: p.Uid, perm: p), 
                    (key: p.Name?.ToLower(), perm: p) 
                })
                .Where(x => !string.IsNullOrEmpty(x.key))
                .GroupBy(x => x.key)
                .ToDictionary(g => g.Key, g => g.First().perm);
        }

        private static (string userId, UserType userType) ResolveUserOrTeam(
            ImportSharedFolderPermissions permission,
            Dictionary<string, string> teamLookup)
        {
            if (!string.IsNullOrEmpty(permission.Uid) && teamLookup.TryGetValue(permission.Uid, out var teamUid))
                return (teamUid, UserType.Team);

            if (string.IsNullOrEmpty(permission.Name))
                return (null, UserType.User);

            var name = permission.Name.ToLower();
            
            if (teamLookup.TryGetValue(name, out var teamByName))
                return (teamByName, UserType.Team);

            return IsValidEmail(name) ? (name, UserType.User) : (null, UserType.User);
        }

        private static bool IsValidEmail(string email)
        {
            try { _ = new System.Net.Mail.MailAddress(email); return true; }
            catch { return false; }
        }

        private static void TrackProcessedIds(HashSet<string> processedIds, string userId, string name)
        {
            processedIds.Add(userId);
            if (!string.IsNullOrEmpty(name)) processedIds.Add(name.ToLower());
        }

        private static SharedFolderPermission FindExistingPermission(
            Dictionary<string, SharedFolderPermission> currentPermissions,
            string userId,
            string name)
            => currentPermissions.TryGetValue(userId, out var byUid) ? byUid
             : !string.IsNullOrEmpty(name) && currentPermissions.TryGetValue(name.ToLower(), out var byName) ? byName
             : null;

        private static void ApplyPermission(
            BatchVaultOperations bo,
            string sharedFolderUid,
            string userId,
            UserType userType,
            SharedFolderUserOptions options,
            SharedFolderPermission existing,
            ImportSharedFolderPermissions permission,
            MembershipSummary summary)
        {
            var isUpdate = existing != null;
            var needsChange = !isUpdate || 
                              existing.ManageUsers != (permission.ManageUsers ?? false) ||
                              existing.ManageRecords != (permission.ManageRecords ?? false);

            if (!needsChange)
                return;

            bo.PutUserToSharedFolder(sharedFolderUid, userId, userType, options);
            IncrementSummary(summary, userType, isUpdate);
        }

        private static void IncrementSummary(MembershipSummary summary, UserType userType, bool isUpdate)
        {
            if (isUpdate)
            {
                if (userType == UserType.Team) summary.TeamsUpdated++; else summary.UsersUpdated++;
            }
            else
            {
                if (userType == UserType.Team) summary.TeamsAdded++; else summary.UsersAdded++;
            }
        }

        private static void RemoveUnprocessedPermissions(
            BatchVaultOperations bo,
            string sharedFolderUid,
            Dictionary<string, SharedFolderPermission> currentPermissions,
            HashSet<string> processedIds,
            MembershipSummary summary)
        {
            var uniquePerms = currentPermissions.Values
                .GroupBy(p => p.Uid ?? p.Name)
                .Select(g => g.First())
                .Where(p => !WasProcessed(p, processedIds));

            foreach (var perm in uniquePerms)
            {
                var removeId = perm.UserType == UserType.Team ? perm.Uid : perm.Name;
                bo.RemoveUserFromSharedFolder(sharedFolderUid, removeId, perm.UserType);
                if (perm.UserType == UserType.Team) summary.TeamsRemoved++; else summary.UsersRemoved++;
            }
        }

        private static bool WasProcessed(SharedFolderPermission perm, HashSet<string> processedIds)
            => (!string.IsNullOrEmpty(perm.Uid) && processedIds.Contains(perm.Uid)) ||
               (!string.IsNullOrEmpty(perm.Name) && processedIds.Contains(perm.Name.ToLower()));
    }

    #region Data Contracts

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

    #endregion
}
