using System.Threading.Tasks;
using System;


namespace Sample.SecretManagerExamples
{
    public static class AppCreateExample
    {
        public static async Task AppCreate(string applicationName)
        {
            var vault = await AuthenticateAndGetVault.GetVault();
            if (vault == null)
            {
                Console.WriteLine("Authentication failed. Vault is null.");
                return;
            }
            
            var appRecord = await vault.CreateSecretManagerApplication(applicationName);
            Console.WriteLine($"App created with UID: {appRecord.Uid} and Name: {appRecord.Title}");

        }

    }
}
