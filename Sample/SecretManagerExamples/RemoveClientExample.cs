using System.Threading.Tasks;
using System;

namespace Sample.SecretManagerExamples
{
    public static class RemoveClientExample
    {
        public static async Task RemoveClient(
            string applicationId,
            string deviceId)
        {
            try
            {
                var vault = await AuthenticateAndGetVault.GetVault();

                await vault.DeleteSecretManagerClient(
                        applicationId,
                        deviceId
                    );

                Console.WriteLine($"Client removed successfully.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}
