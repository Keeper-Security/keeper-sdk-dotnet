using System;
using System.Threading.Tasks;
using KeeperSecurity.Vault;

namespace Sample.SharedFolderExamples
{
    public static class SharedFolderPermissions
    {
        public static async Task ManageSharedFolderPermissions1(VaultOnline vault, string sharedFolderUid,
            string recordUid,
            IRecordShareOptions permissionsOptions)
        {
            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;
            var result = await ManageSharedFolderPermissionsSimple(
                vault,
                sharedFolderUid,
                recordUid,
                permissionsOptions);
            if (result)
            {
                Console.WriteLine("Permissions updated successfully.");
            }
            else
            {
                Console.WriteLine("Failed to update permissions.");
            }
        }
        public static async Task<bool> ManageSharedFolderPermissionsSimple(
            VaultOnline vault,
            string sharedFolderUid,
            string recordUid,
            IRecordShareOptions permissionsOptions)
        {
            try
            {
                await vault.ChangeRecordInSharedFolder(sharedFolderUid, recordUid, permissionsOptions);
                return true;   // success
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
                return false;  // failure
            }
        }

    }
}
