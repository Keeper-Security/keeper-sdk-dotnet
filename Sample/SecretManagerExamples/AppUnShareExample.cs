using System.Threading.Tasks;
using KeeperSecurity.Vault;
using System;

namespace Sample.SecretManagerExamples
{
    public static class AppUnShareExample
    {
        private static VaultOnline vault;

        public static async Task RemoveUserToSharedFolder(
            string sharedFolderUid,
            string userId,
            UserType userType
        )
        {
            try
            {
                if (vault == null)
                {
                    vault = await AuthenticateAndGetVault.GetVault();
                }

                await vault.RemoveUserFromSharedFolder(sharedFolderUid, userId, userType);

                Console.WriteLine("User successfully Removed from the shared folder.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }

        public static async Task RevokeShareToUser(
            string recordUid,
            string username
        )
        {
            try
            {
                if (vault == null)
                {
                    vault = await AuthenticateAndGetVault.GetVault();
                }

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
