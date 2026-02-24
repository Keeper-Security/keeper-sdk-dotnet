using System;
using System.Threading.Tasks;
using KeeperSecurity.Vault;

namespace Sample.ShareRecordExamples
{
    public static class RevokeShareRecordToUser
    {
        public static async Task RemoveShareRecordToUser(string recordUid, string username)
        {
            var vault = await AuthenticateAndGetVault.GetVault();
            var result = await RemoveShareRecordToUserSimple(vault, recordUid, username);
            if (result)
            {
                Console.WriteLine($"Successfully removed {username} from Record Uid: {recordUid}");
            }
            else
            {
                Console.WriteLine($"Failed to remove {username} from Record Uid: {recordUid}");
            }
        }

        public static async Task<bool> RemoveShareRecordToUserSimple(VaultOnline vault, string recordUid, string username)
        {
            try
            {
                await vault.RevokeShareFromUser(
                    recordUid,
                    username
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