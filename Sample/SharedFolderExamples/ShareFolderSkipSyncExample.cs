using System;
using System.Threading.Tasks;
using KeeperSecurity.Authentication;
using KeeperSecurity.Vault;

namespace Sample.SharedFolderExamples
{
    /// <summary>
    /// Shared folder user/team helpers using <see cref="SharedFolderSkipSyncDown"/> (no full vault sync).
    /// Authenticate with <see cref="AuthenticateAndGetVault.GetAuthAsync"/>. For a synced vault, see <see cref="ShareFolderToUser"/>.
    /// </summary>
    public static class ShareFolderSkipSyncExample
    {
        public static async Task PutUserToSharedFolder(IAuthentication auth, string sharedFolderUid, string userId,
            IUserShareOptions options = null)
        {
            try
            {
                await SharedFolderSkipSyncDown.PutUserToSharedFolderAsync(auth, sharedFolderUid, userId, options);
                Console.WriteLine($"User {userId} added to shared folder {sharedFolderUid}.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }

        public static async Task RemoveUserFromSharedFolder(IAuthentication auth, string sharedFolderUid, string userId)
        {
            try
            {
                await SharedFolderSkipSyncDown.RemoveUserFromSharedFolderAsync(auth, sharedFolderUid, userId);
                Console.WriteLine($"User {userId} removed from shared folder {sharedFolderUid}.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }

        public static async Task PutTeamToSharedFolder(IAuthentication auth, string sharedFolderUid, string teamNameOrUid,
            IUserShareOptions options = null)
        {
            try
            {
                await SharedFolderSkipSyncDown.PutTeamToSharedFolderAsync(auth, sharedFolderUid, teamNameOrUid, options);
                Console.WriteLine($"Team {teamNameOrUid} added to shared folder {sharedFolderUid}.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }

        public static async Task RemoveTeamFromSharedFolder(IAuthentication auth, string sharedFolderUid,
            string teamNameOrUid)
        {
            try
            {
                await SharedFolderSkipSyncDown.RemoveTeamFromSharedFolderAsync(auth, sharedFolderUid, teamNameOrUid);
                Console.WriteLine($"Team {teamNameOrUid} removed from shared folder {sharedFolderUid}.");
                }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}
