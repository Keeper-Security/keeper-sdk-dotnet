using System;
using System.Threading.Tasks;
using KeeperSecurity.Vault;

namespace Sample.KeeperNSFExamples
{
    public static class RevokeKeeperNSFFolderAccessExample
    {
        public static async Task Revoke(VaultOnline vault, string folderUid, string userEmail)
        {
            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;

            try
            {
                await vault.RevokeKeeperNSFFolderAccess(folderUid, userEmail);
                Console.WriteLine($"Revoked folder access for {userEmail} on {folderUid}.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error revoking folder access: {ex.Message}");
            }
        }
    }
}
