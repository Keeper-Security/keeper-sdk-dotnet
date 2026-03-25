using System;
using System.Threading.Tasks;
using KeeperSecurity.Authentication;
using KeeperSecurity.Vault;

namespace Sample.SharedFolderExamples
{
    public static class ShareFolderSkipSyncExample
    {
        public static async Task PutUserToSharedFolder(IAuthentication auth, string sharedFolderUid, string userId,
            IUserShareOptions options = null)
        {
            try
            {
                await SharedFolderSkipSyncDown.PutUserToSharedFolderAsync(auth, sharedFolderUid, userId, options);
                Console.WriteLine($"User {userId} added to shared folder {sharedFolderUid}.");
                await WriteDecryptedFolderRecordsAsync(auth, sharedFolderUid,
                    $"No records listed on this shared folder (user {userId} has folder access).").ConfigureAwait(false);
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
                await WriteDecryptedFolderRecordsAsync(auth, sharedFolderUid,
                    "No records listed on this shared folder after remove.").ConfigureAwait(false);
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

        private static async Task WriteDecryptedFolderRecordsAsync(IAuthentication auth, string sharedFolderUid,
            string emptyFolderMessage)
        {
            var recordUids = await SharedFolderSkipSyncDown.GetRecordUidsFromSharedFolderAsync(auth, sharedFolderUid)
                .ConfigureAwait(false);
            if (recordUids.Count == 0)
            {
                Console.WriteLine(emptyFolderMessage);
                return;
            }

            var loaded = await RecordSkipSyncDown.GetRecordsAsync(auth, recordUids).ConfigureAwait(false);
            foreach (var r in loaded.Records)
                Console.WriteLine($"  {r.Uid}: {r.Title ?? "(no title)"}");
            if (loaded.NoPermissionRecordUids.Count > 0)
                Console.WriteLine($"  No permission: {string.Join(", ", loaded.NoPermissionRecordUids)}");
            if (loaded.FailedRecordUids.Count > 0)
                Console.WriteLine($"  Failed to decrypt: {string.Join(", ", loaded.FailedRecordUids)}");
        }
    }
}
