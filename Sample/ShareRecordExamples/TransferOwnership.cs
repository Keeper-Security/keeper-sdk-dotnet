using System;
using System.Threading.Tasks;
using KeeperSecurity.Vault;

namespace Sample.TransferOwnershipExamples
{
    public static class TransferOwnership
    {
        public static async Task TransferRecordToUser(string recordUid, string username)
        {
            var vault = await AuthenticateAndGetVault.GetVault();
            var result = await TransferRecordToUserSimple(vault, recordUid, username);
            if (result)
            {
                Console.WriteLine($"Successfully transferred ownership for user '{username}' to record UID '{recordUid}'.");

            }
            else
            {
                Console.WriteLine($"Failed to transfer");
            }
        }

        public static async Task<bool> TransferRecordToUserSimple(VaultOnline vault, string recordUid, string username)
        {
            try
            {
                await vault.TransferRecordToUser(
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