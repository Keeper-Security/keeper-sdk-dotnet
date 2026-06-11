using System;
using System.Threading.Tasks;
using KeeperSecurity.Vault;

namespace Sample.KeeperNSFExamples
{
    public static class GrantKeeperNSFFolderAccessExample
    {
        /// <param name="role">viewer, shared-manager, content-manager, content-share-manager, or full-manager</param>
        public static async Task Grant(
            VaultOnline vault,
            string folderUid,
            string userEmail,
            string role = "viewer")
        {
            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;

            try
            {
                await vault.GrantKeeperNSFFolderAccess(folderUid, userEmail, role);
                Console.WriteLine($"Granted '{role}' on folder {folderUid} to {userEmail}.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error granting folder access: {ex.Message}");
            }
        }
    }
}
