using System.Threading.Tasks;
using System;


namespace Sample.SecretManagerExamples
{
    public static class AppCreateExample
    {
        public static async Task AppCreate(string applicationName)
        {
            var vault = await AuthenticateAndGetVault.GetVault();
            var appRecord = await vault.CreateSecretManagerApplication(applicationName);
            Console.WriteLine($"App created with UID: {appRecord.Uid} and Name: {appRecord.Title}");

        }

    }
}
