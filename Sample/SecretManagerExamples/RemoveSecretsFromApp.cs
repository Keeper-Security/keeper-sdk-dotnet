using System.Threading.Tasks;
using KeeperSecurity.Vault;
using System;

namespace Sample.SecretManagerExamples
{
    public static class SecretManagerUnShareExample
    {
        public static async Task SecretManagerUnShare(VaultOnline vault, 
            string applicationId,
            string sharedFolderOrRecordUid
        )
        {
            try
            {
                vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;

                await vault.UnshareFromSecretManagerApplication(
                        applicationId,
                        sharedFolderOrRecordUid
                    );
                Console.WriteLine($"Successfully removed sharing sharedFolderOrRecordUid: {sharedFolderOrRecordUid} from ApplicationUid: {applicationId}.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}
