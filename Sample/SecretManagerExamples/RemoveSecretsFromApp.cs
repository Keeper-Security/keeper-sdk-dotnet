using System.Threading.Tasks;
using System;

namespace Sample.SecretManagerExamples
{
    public static class SecretManagerUnShareExample
    {
        public static async Task SecretManagerUnShare(
            string applicationId,
            string sharedFolderOrRecordUid
        )
        {
            try
            {
                var vault = await AuthenticateAndGetVault.GetVault();
                if (vault == null)
                {
                    Console.WriteLine("Authentication failed. Vault is null.");
                    return;
                }

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
