using System.Threading.Tasks;
using KeeperSecurity.Vault;
using System;

namespace Sample.SecretManagerExamples
{
    public static class AddClientExample
    {
        public static async Task AddClient(VaultOnline vault, 
            string applicationId,
            bool unlockIp,
            int firstAccessExpireInMinutes,
            int accessExpiresInMinutes,
            string name)
        {
            try
            {
                vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;

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
