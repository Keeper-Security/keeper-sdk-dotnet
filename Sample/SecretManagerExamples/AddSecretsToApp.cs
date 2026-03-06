using System.Threading.Tasks;
using KeeperSecurity.Vault;
using System;

namespace Sample.SecretManagerExamples
{
    public static class SecretManagerShareExample
    {
        public static async Task SecretManagerShare(VaultOnline vault, 
            string applicationId,
            string sharedFolderOrRecordUid,
            bool canEdit)
        {
            try
            {
                vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;

                await vault.ShareToSecretManagerApplication(
                        applicationId,
                        sharedFolderOrRecordUid,
                        canEdit
                    );
                Console.WriteLine($"sharedFolderOrRecordUid: {sharedFolderOrRecordUid} Shared successfully to the ApplicationUid: {applicationId}.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}
