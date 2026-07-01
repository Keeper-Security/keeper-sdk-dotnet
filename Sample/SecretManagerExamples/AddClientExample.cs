using System;
using System.Threading.Tasks;
using Enterprise;
using KeeperSecurity.Vault;

namespace Sample.SecretManagerExamples
{
    public static class AddClientExample
    {
        public static async Task AddClient(
            VaultOnline vault,
            string applicationId,
            bool unlockIp = true,
            int? firstAccessExpireInMinutes = null,
            int? accessExpiresInMinutes = null,
            string name = null,
            AppClientType? appClientType = null)
        {
            try
            {
                vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
                if (vault == null)
                {
                    return;
                }

                var response = await vault.AddSecretManagerClient(
                    applicationId,
                    unlockIp,
                    firstAccessExpireInMinutes,
                    accessExpiresInMinutes,
                    name,
                    appClientType);

                var device = response.Item1;
                var clientKey = response.Item2;

                Console.WriteLine("Successfully generated client device.");
                Console.WriteLine($"One-Time Access Token: {clientKey}");
                Console.WriteLine($"IP Lock: {(device.LockIp ? "Enabled" : "Disabled")}");
                Console.WriteLine(
                    $"Token Expires On: {(device.FirstAccessExpireOn.HasValue ? device.FirstAccessExpireOn.Value.ToString("G") : "Taken")}");
                Console.WriteLine(
                    $"App Access Expires On: {(device.AccessExpireOn.HasValue ? device.AccessExpireOn.Value.ToString("G") : "Never")}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}
