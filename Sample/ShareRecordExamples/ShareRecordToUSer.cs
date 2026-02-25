using System;
using System.Threading.Tasks;
using KeeperSecurity.Vault;

namespace Sample.ShareRecordExamples
{
    public static class ShareRecordToUser
    {
        public static async Task ShareRecordToUserWithPermissions(string recordUid, string username, IRecordShareOptions options)
        {
            var vault = await AuthenticateAndGetVault.GetVault();
            var result = await ShareRecordToUserWithPermissionsSimple(vault, recordUid, username, options);
            if (result)
            {
                Console.WriteLine($"Record shared successfully to {username} for Record UID: {options.Expiration}");
            }
            else
            {
                Console.WriteLine("Record shared failed");
            }
        }

        public static async Task<bool> ShareRecordToUserWithPermissionsSimple(VaultOnline vault, string recordUid, string username, IRecordShareOptions options)
        {
            try
            {
                await vault.ShareRecordWithUser(
                    recordUid,
                    username,
                    options
                    );
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
                return false;
            }

        }
    }
}