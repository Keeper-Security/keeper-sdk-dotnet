using System.Threading.Tasks;
using System;

namespace Sample.SecretManagerExamples
{
    public static class SecretManagerShareExample
    {
        public static async Task SecretManagerShare(
            string applicationId,
            string sharedFolderOrRecordUid,
            bool canEdit)
        {
            try
            {
                var vault = await AuthenticateAndGetVault.GetVault();

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
