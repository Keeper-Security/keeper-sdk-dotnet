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
            await vault.DeleteSecretManagerApplication(applicationUid);
        }

    }
}
