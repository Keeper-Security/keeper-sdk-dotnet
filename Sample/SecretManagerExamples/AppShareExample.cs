using System.Threading.Tasks;
using KeeperSecurity.Vault;
using System;

namespace Sample.SecretManagerExamples
{
    public static class AppShareExample
    {
        public static async Task AddUserToSharedFolder(VaultOnline vault, 
            string sharedFolderUid,
            string userId,
            UserType userType,
            IUserShareOptions options
        )
        {
            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;
            try
            {
                await vault.PutUserToSharedFolder(sharedFolderUid, userId, userType, options);

                Console.WriteLine("User successfully added to the shared folder.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }

        public static async Task ShareRecordToUser(VaultOnline vault,
            string recordUid,
            string username,
            IRecordShareOptions options
        )
        {
            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;
            try
            {
                await vault.ShareRecordWithUser(recordUid, username, options);

                Console.WriteLine("Record successfully shared with the user.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}
