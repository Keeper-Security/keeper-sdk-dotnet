using System;
using System.Threading.Tasks;
using KeeperSecurity.Vault;

namespace Sample.SharedFolderToUserExamples
{
    public static class ShareFolderToUser
    {
        public static async Task ShareFolderWithUser(VaultOnline vault, string sharedFolderUid,
            string userId,
            UserType userType,
            IUserShareOptions options)
        {
            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;
            var result = await ShareFolderToUserSimple(
                vault,
                sharedFolderUid,
                userId,
                userType,
                options);
            if (result)
            {
                Console.WriteLine($"Folder shared successfully to {userId}.");
            }
            else
            {
                Console.WriteLine("Failed to share folder.");
            }
        }
        public static async Task<bool> ShareFolderToUserSimple(
            VaultOnline vault,
            string sharedFolderUid,
            string userId,
            UserType userType,
            IUserShareOptions options)
        {
            try
            {
                await vault.PutUserToSharedFolder(sharedFolderUid, userId, userType, options);
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