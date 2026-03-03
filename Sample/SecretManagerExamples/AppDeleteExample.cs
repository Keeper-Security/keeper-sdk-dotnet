using System.Threading.Tasks;
using KeeperSecurity.Vault;
using System;

namespace Sample.SecretManagerExamples
{
    public static class AppDeleteExample
    {
        public static async Task AppDelete(VaultOnline vault, string applicationUid)
        {
            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;

            if (string.IsNullOrEmpty(applicationUid))
            {
                Console.WriteLine("Application UID is required.");
                return;
            }
            
            await vault.DeleteSecretManagerApplication(applicationUid);
        }

    }
}
