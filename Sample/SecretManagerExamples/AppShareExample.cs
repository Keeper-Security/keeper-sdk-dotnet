using System.Threading.Tasks;
using KeeperSecurity.Vault;
using System;

namespace Sample.SecretManagerExamples
{
    public static class AppShareExample
    {
        private static VaultOnline vault;

        public static async Task AddUserToSharedFolder(
            string sharedFolderUid,
            string userId,
            UserType userType,
            IUserShareOptions options
        )
        {
            try
            {
                if (vault == null)
                {
                    vault = await AuthenticateAndGetVault.GetVault();
                }

                await vault.PutUserToSharedFolder(sharedFolderUid, userId, userType, options);

                Console.WriteLine("User successfully added to the shared folder.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }

        public static async Task ShareRecordToUser(
            string recordUid,
            string username,
            IRecordShareOptions options
        )
        {
            try
            {
                if (vault == null)
                {
                    vault = await AuthenticateAndGetVault.GetVault();
                }

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
