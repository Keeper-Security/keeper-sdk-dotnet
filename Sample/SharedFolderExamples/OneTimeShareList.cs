using System;
using System.Threading.Tasks;
using KeeperSecurity.Vault;


namespace Sample.OneTimeShareListExamples
{
    public static class OneTimeShareList
    {
        public static async Task GetOneTimeShareList(VaultOnline vault, string recordUid)
        {
            vault = await AuthenticateAndGetVault.ResolveVaultAsync(vault);
            if (vault == null) return;
            var shares = await vault.GetExernalRecordShares(recordUid);
            Console.WriteLine($"One-Time Shares for Record UID: {recordUid}");
            Console.WriteLine(new string('=', 120));

            // Print header
            Console.WriteLine("{0,-25} {1,-40}", "Field", "Value");
            Console.WriteLine(new string('=', 120));

            // Print rows
            foreach (var share in shares)
            {
                Console.WriteLine("{0,-25} {1,-40}", "Record UID", share.RecordUid);
                Console.WriteLine("{0,-25} {1,-40}", "Client Id", share.ClientId);
                Console.WriteLine("{0,-25} {1,-40}", "Name", share.Name);
                Console.WriteLine("{0,-25} {1,-40}", "Created On", share.CreatedOn);
                Console.WriteLine("{0,-25} {1,-40}", "First Access Expires", share.FirstAccessExpiresOn);
                Console.WriteLine("{0,-25} {1,-40}", "Access Expires On", share.AccessExpiresOn);
                Console.WriteLine("{0,-25} {1,-40}", "First Accessed", share.FirstAccessed);
                Console.WriteLine("{0,-25} {1,-40}", "Last Accessed", share.LastAccessed);

                Console.WriteLine(new string('-', 120));   // separator after each share
            }

        }
    }
}