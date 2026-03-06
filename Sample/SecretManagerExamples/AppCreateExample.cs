using System.Threading.Tasks;
using KeeperSecurity.Vault;
using System;


namespace Sample.SecretManagerExamples
{
    public static class AppCreateExample
    {
        public static async Task AppCreate(VaultOnline vault, string applicationName)
        {
            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;
            
            var appRecord = await vault.CreateSecretManagerApplication(applicationName);
            Console.WriteLine($"App created with UID: {appRecord.Uid} and Name: {appRecord.Title}");

        }

    }
}
