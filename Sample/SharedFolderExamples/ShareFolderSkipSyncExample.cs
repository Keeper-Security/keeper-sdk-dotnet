using System;
using System.Threading.Tasks;
using KeeperSecurity.Authentication;
using KeeperSecurity.Vault;

namespace Sample.SharedFolderExamples
{
    /// <summary>
    /// Samples for <see cref="SharedFolderSkipSyncDown"/> and <see cref="RecordSkipSyncDown"/> without loading the full vault.
    /// </summary>
    public static class ShareFolderSkipSyncExample
    {
        /// <summary>
        /// Lists decrypted records using <see cref="RecordSkipSyncDown.GetSharedFolderRecordsAsync"/> (keys from <c>get_shared_folders</c> <c>records</c>).
        /// </summary>
        public static Task ListSharedFolderRecordsAsync(IAuthentication auth, string sharedFolderUid,
            string emptyFolderMessage = "No records in this shared folder (or folder unavailable).")
            => ListAndPrintFolderRecordsAsync(auth, sharedFolderUid, emptyFolderMessage,
                () => RecordSkipSyncDown.GetSharedFolderRecordsAsync(auth, sharedFolderUid.Trim()));

        /// <summary>
        /// Lists decrypted records using <see cref="RecordSkipSyncDown.GetOwnedRecordsAsync"/> (keys from each <c>get_records_details</c> <c>recordData</c> row).
        /// </summary>
        public static Task ListSharedFolderRecordsOwnedAsync(IAuthentication auth, string sharedFolderUid,
            string emptyFolderMessage = "No records in this shared folder (or folder unavailable).")
            => ListAndPrintFolderRecordsAsync(auth, sharedFolderUid, emptyFolderMessage, async () =>
            {
                var uids = await SharedFolderSkipSyncDown
                    .GetRecordUidsFromSharedFolderAsync(auth, sharedFolderUid.Trim()).ConfigureAwait(false);
                return await RecordSkipSyncDown.GetOwnedRecordsAsync(auth, uids).ConfigureAwait(false);
            });

        /// <summary>Adds or updates a user on the shared folder, then prints folder records (shared-folder key path).</summary>
        public static async Task PutUserToSharedFolder(IAuthentication auth, string sharedFolderUid, string userId,
            IUserShareOptions options = null)
        {
            if (!TryEnsureAuthenticated(auth))
                return;

            try
            {
                await SharedFolderSkipSyncDown.PutUserToSharedFolderAsync(auth, sharedFolderUid, userId, options);
                Console.WriteLine($"User {userId} added to shared folder {sharedFolderUid}.");
                await WriteDecryptedFolderRecordsSharedFolderAsync(auth, sharedFolderUid,
                    $"No records listed on this shared folder (user {userId} has folder access).").ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }

        /// <summary>Removes a user from the shared folder, then prints folder records (shared-folder key path).</summary>
        public static async Task RemoveUserFromSharedFolder(IAuthentication auth, string sharedFolderUid, string userId)
        {
            if (!TryEnsureAuthenticated(auth))
                return;

            try
            {
                await SharedFolderSkipSyncDown.RemoveUserFromSharedFolderAsync(auth, sharedFolderUid, userId);
                Console.WriteLine($"User {userId} removed from shared folder {sharedFolderUid}.");
                await WriteDecryptedFolderRecordsSharedFolderAsync(auth, sharedFolderUid,
                    "No records listed on this shared folder after remove.").ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }

        /// <summary>Adds or updates a team on the shared folder, then prints folder records (shared-folder key path).</summary>
        public static async Task PutTeamToSharedFolder(IAuthentication auth, string sharedFolderUid, string teamNameOrUid,
            IUserShareOptions options = null)
        {
            if (!TryEnsureAuthenticated(auth))
                return;

            try
            {
                await SharedFolderSkipSyncDown.PutTeamToSharedFolderAsync(auth, sharedFolderUid, teamNameOrUid, options);
                Console.WriteLine($"Team {teamNameOrUid} added to shared folder {sharedFolderUid}.");
                await WriteDecryptedFolderRecordsSharedFolderAsync(auth, sharedFolderUid,
                    $"No records listed on this shared folder (team {teamNameOrUid} has folder access).").ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }

        /// <summary>Removes a team from the shared folder, then prints folder records (shared-folder key path).</summary>
        public static async Task RemoveTeamFromSharedFolder(IAuthentication auth, string sharedFolderUid,
            string teamNameOrUid)
        {
            if (!TryEnsureAuthenticated(auth))
                return;

            try
            {
                await SharedFolderSkipSyncDown.RemoveTeamFromSharedFolderAsync(auth, sharedFolderUid, teamNameOrUid);
                Console.WriteLine($"Team {teamNameOrUid} removed from shared folder {sharedFolderUid}.");
                await WriteDecryptedFolderRecordsSharedFolderAsync(auth, sharedFolderUid,
                    "No records listed on this shared folder after remove.").ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }

        private static async Task ListAndPrintFolderRecordsAsync(IAuthentication auth, string sharedFolderUid,
            string emptyFolderMessage, Func<Task<RecordDetailsSkipSyncResult>> loadAsync)
        {
            if (!TryEnsureAuthenticated(auth))
                return;
            if (string.IsNullOrWhiteSpace(sharedFolderUid))
            {
                Console.WriteLine("Shared folder UID is required.");
                return;
            }

            var loaded = await loadAsync().ConfigureAwait(false);
            PrintOrEmptyMessage(loaded, emptyFolderMessage);
        }

        private static async Task WriteDecryptedFolderRecordsSharedFolderAsync(IAuthentication auth, string sharedFolderUid,
            string emptyFolderMessage)
        {
            if (auth == null)
                return;

            var loaded = await RecordSkipSyncDown.GetSharedFolderRecordsAsync(auth, sharedFolderUid)
                .ConfigureAwait(false);
            PrintOrEmptyMessage(loaded, emptyFolderMessage);
        }

        private static void PrintOrEmptyMessage(RecordDetailsSkipSyncResult loaded, string emptyFolderMessage)
        {
            if (loaded.Records.Count == 0 && loaded.FailedRecordUids.Count == 0 &&
                loaded.NoPermissionRecordUids.Count == 0)
                Console.WriteLine(emptyFolderMessage);
            else
                PrintRecordDetailsResult(loaded);
        }

        private static void PrintRecordDetailsResult(RecordDetailsSkipSyncResult loaded)
        {
            foreach (var r in loaded.Records)
                Console.WriteLine($"  {r.Uid}: {r.Title ?? "(no title)"}");
            if (loaded.NoPermissionRecordUids.Count > 0)
                Console.WriteLine($"  No permission: {string.Join(", ", loaded.NoPermissionRecordUids)}");
            if (loaded.FailedRecordUids.Count > 0)
                Console.WriteLine($"  Failed to decrypt: {string.Join(", ", loaded.FailedRecordUids)}");
            if (loaded.InvalidRecordUids.Count > 0)
                Console.WriteLine($"  Invalid UID format: {string.Join(", ", loaded.InvalidRecordUids)}");
        }

        private static bool TryEnsureAuthenticated(IAuthentication auth)
        {
            if (auth != null)
                return true;
            Console.WriteLine("Not authenticated.");
            return false;
        }
    }
}
