using System.Threading.Tasks;
using KeeperSecurity.Vault;
using System;

namespace Sample.SecretManagerExamples
{
    public static class AppDeleteExample
    {
        public static async Task AppDelete(string applicationUid)
        {
            var vault = await AuthenticateAndGetVault.GetVault();
            if (vault == null)
            {
                Console.WriteLine("Authentication failed. Vault is null.");
                return;
            }

            if (string.IsNullOrEmpty(applicationUid))
            {
                Console.WriteLine("Application UID is required.");
                return;
            }
            
            await vault.DeleteSecretManagerApplication(applicationUid);
        }

    }
}
