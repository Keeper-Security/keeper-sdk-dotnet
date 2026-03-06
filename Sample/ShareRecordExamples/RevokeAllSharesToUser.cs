using System;
using System.Threading.Tasks;
using KeeperSecurity.Vault;

namespace Sample.ShareRecordExamples
{
    public static class RevokeAllSharesToUser
    {
        public static async Task RemoveAllSharesToUser(VaultOnline vault, string username)
        {
            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;
            var result = await RemoveAllSharesToUserSimple(vault, username);
            if (result)
            {
                Console.WriteLine($"Successfully removed {username} from all shares");
            }
            else
            {
                Console.WriteLine($"Failed to remove {username} from all shares");
            }
        }

        public static async Task<bool> RemoveAllSharesToUserSimple(VaultOnline vault, string username)
        {
            try
            {
                await vault.CancelSharesWithUser(
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