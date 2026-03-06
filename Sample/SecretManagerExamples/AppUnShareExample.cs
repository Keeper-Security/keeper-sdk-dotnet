using System.Threading.Tasks;
using KeeperSecurity.Vault;
using System;

namespace Sample.SecretManagerExamples
{
    public static class AppUnShareExample
    {
        public static async Task RemoveUserToSharedFolder(VaultOnline vault, 
            string sharedFolderUid,
            string userId,
            UserType userType
        )
        {
            try
            {
                if (vault == null)
                {
                    vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
                if (vault == null) return;
                }

                await vault.RemoveUserFromSharedFolder(sharedFolderUid, userId, userType);

                Console.WriteLine("User successfully Removed from the shared folder.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }

        public static async Task RevokeShareToUser(VaultOnline vault,
            string recordUid,
            string username
        )
        {
            try
            {
                vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
                if (vault == null) return;

                await vault.RevokeShareFromUser(recordUid, username);

                Console.WriteLine("Record successfully removed from the user.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}
