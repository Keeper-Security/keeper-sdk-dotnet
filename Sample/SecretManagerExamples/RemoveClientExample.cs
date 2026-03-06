using System.Threading.Tasks;
using KeeperSecurity.Vault;
using System;

namespace Sample.SecretManagerExamples
{
    public static class RemoveClientExample
    {
        public static async Task RemoveClient(VaultOnline vault, 
            string applicationId,
            string deviceId)
        {
            try
            {
                vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;

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
