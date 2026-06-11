using System;
using System.Threading.Tasks;
using KeeperSecurity.Vault;

namespace Sample.KeeperNSFExamples
{
    public static class UpdateKeeperNSFRecordPermissionsExample
    {
        /// <param name="action">grant or revoke</param>
        /// <param name="role">Required when action is grant (e.g. viewer, content-manager)</param>
        public static async Task UpdatePermissions(
            VaultOnline vault,
            string folderUid,
            string action,
            string role = null,
            bool recursive = false,
            bool dryRun = true)
        {
            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;

            try
            {
                var result = await vault.UpdateKeeperNSFRecordPermissions(folderUid, action, role, recursive, dryRun);
                Console.WriteLine($"Permission update ({action}, dryRun={dryRun}):");
                Console.WriteLine($"  Grants:  {result.Grants?.Count ?? 0}");
                Console.WriteLine($"  Revokes: {result.Revokes?.Count ?? 0}");
                Console.WriteLine($"  Skipped: {result.Skipped?.Count ?? 0}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error updating record permissions: {ex.Message}");
            }
        }
    }
}
