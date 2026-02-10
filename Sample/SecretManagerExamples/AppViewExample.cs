using System;
using System.Threading.Tasks;
using KeeperSecurity.Vault;

namespace Sample.SecretManagerExamples
{
    public static class AppViewExample
    {
        public static async Task AppView(string applicationUid)
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

            var found = vault.TryGetKeeperRecord(applicationUid, out KeeperRecord record);
            if (!found || record == null)
            {
                Console.WriteLine($"Record '{applicationUid}' not found.");
                return;
            }

            var application = record as ApplicationRecord;
            if (application == null)
            {
                Console.WriteLine($"Record '{applicationUid}' is not an Application record. Type: {record.GetType().Name}");
                return;
            }

            Console.WriteLine("======== Application Details ========");
            Console.WriteLine("{0,-20}: {1}", "UID", application.Uid);
            Console.WriteLine("{0,-20}: {1}", "Title", application.Title);
            Console.WriteLine("{0,-20}: {1}", "Version", application.Version);
            Console.WriteLine("{0,-20}: {1}", "Revision", application.Revision);
            Console.WriteLine("{0,-20}: {1}", "Last Modified", application.ClientModified);
            Console.WriteLine("{0,-20}: {1}", "Owner", application.Owner);
            Console.WriteLine("{0,-20}: {1}", "Shared", application.Shared);
            Console.WriteLine("=====================================");
        }
    }
}
