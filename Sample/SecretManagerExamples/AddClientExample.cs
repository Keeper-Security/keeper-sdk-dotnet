using System.Threading.Tasks;
using System;

namespace Sample.SecretManagerExamples
{
    public static class AddClientExample
    {
        public static async Task AddClient(
            string applicationId,
            bool unlockIp,
            int firstAccessExpireInMinutes,
            int accessExpiresInMinutes,
            string name)
        {
            try
            {
                var vault = await AuthenticateAndGetVault.GetVault();

                var response = await vault.AddSecretManagerClient(
                    applicationId,
                    unlockIp,
                    firstAccessExpireInMinutes,
                    accessExpiresInMinutes,
                    name
                );

                Console.WriteLine($"Client added successfully. {response}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}
