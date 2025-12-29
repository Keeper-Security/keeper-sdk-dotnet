using System.Threading.Tasks;
using KeeperSecurity.Vault;
using System;

namespace Sample.SecretManagerExamples
{
    public static class AppViewExample
    {
        public static async Task AppView(string applicationUid)
        {
            var vault = await AuthenticateAndGetVault.GetVault();
            var appRecord = vault.TryGetKeeperRecord(applicationUid, out KeeperRecord application);

            if (!appRecord)
            {
                Console.WriteLine("Record not found.");
                return;
            }

            Console.WriteLine("{0,-20}: {1}", "UID", application.Uid);
            Console.WriteLine("{0,-20}: {1}", "Version", application.Version);
            Console.WriteLine("{0,-20}: {1}", "Revision", application.Revision);
            Console.WriteLine("{0,-20}: {1}", "Title", application.Title);
            Console.WriteLine("{0,-20}: {1}", "Last Modified", application.ClientModified);
            Console.WriteLine("{0,-20}: {1}", "Owner", application.Owner);
            Console.WriteLine("{0,-20}: {1}", "Shared", application.Shared);
            Console.WriteLine("{0,-20}: {1}", "Record Key (Base64)", Convert.ToBase64String(application.RecordKey));
        }

    }
}
